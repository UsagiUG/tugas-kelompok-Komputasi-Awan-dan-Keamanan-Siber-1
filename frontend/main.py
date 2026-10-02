"""Edge gateway client.

  python main.py              -> menu
  python main.py --manual     -> ketik data telemetry sendiri lalu kirim terenkripsi
  python main.py --benchmark  -> benchmark RSA vs ECC (30 pesan x 3 ukuran x 2 mode)
  python main.py --fetch-key  -> ambil public key server, tampilkan fingerprint, simpan
  python main.py --show-readings [--sensor-id 1] [--limit 20]
                              -> lihat data yang sudah diterima server
                                 (butuh token: env READINGS_TOKEN atau --token)

Public key server diambil dari GET /public-key saat program mulai, lalu
dicocokkan dengan salinan di frontend/certs (lihat src/server_public_key.py).
  --key-source file   hanya pakai file di frontend/certs (tanpa request ke server)
  --trust-new-key     terima key server yang berbeda dari salinan tersimpan

Server URL: --url, atau environment variable TELEMETRY_URL
(default http://localhost:3000/telemetry).
"""
import argparse
import json
import os
from urllib.parse import urlsplit, urlunsplit
import random
import time
from datetime import datetime, timezone, timedelta

import numpy as np
import pandas as pd
import requests

from src.rsa_encryption import prepare_rsa_key
from src.ecc_encryption import prepare_ecc_key
from src.build_payload import EdgeGateway
from src.server_public_key import (get_server_keys, format_fingerprint,
                                   KeyFetchError, KeyMismatchError)

DEFAULT_URL = os.environ.get("TELEMETRY_URL", "http://localhost:3000/telemetry")
CSV_PATH = os.path.join("..", "statistics")
SUMMARY_PATH = os.path.join("..", "statistics_summary.txt")
TZ_WIB = timezone(timedelta(hours=7))

# (key, label, unit, allowed min, allowed max, random min, random max)
# Random ranges match sensor_simulation.py.
FIELDS = [
    ("temperature",   "Suhu udara",       "°C", -40.0, 85.0,  20.0,  40.0),
    ("air_humidity",  "Kelembapan udara", "%",    0.0, 100.0, 40.0, 100.0),
    ("soil_moisture", "Kelembapan tanah", "%",    0.0, 100.0,  0.0, 100.0),
    ("soil_ph",       "pH tanah",         "",     0.0, 14.0,   4.0,   7.0),
]


# ---------------------------------------------------------------------------
# Shared: encrypt the oldest queued reading and send it
# ---------------------------------------------------------------------------
def encrypt_and_send(gateway, mode, url, keys):
    """Returns (payload, response, encrypt_seconds, round_trip_seconds)."""
    start_encrypt = time.perf_counter()
    if mode == "rsa":
        session_key, key, _ = prepare_rsa_key(keys.rsa_pem)
    else:
        session_key, key, _ = prepare_ecc_key(keys.ecc_pem)
    payload = gateway.build_payload(mode, session_key, key)
    end_encrypt = time.perf_counter()

    response = gateway.post(url, json=payload)
    end_rt = time.perf_counter()
    return payload, response, end_encrypt - start_encrypt, end_rt - end_encrypt


def error_text(response):
    try:
        return response.json().get("error", response.text)
    except ValueError:
        return response.text[:200]


# ---------------------------------------------------------------------------
# Manual mode
# ---------------------------------------------------------------------------
def ask_float(label, unit, lo, hi, rand_lo, rand_hi):
    unit_txt = f" {unit}" if unit else ""
    while True:
        raw = input(f"  {label} ({lo:g} s/d {hi:g}{unit_txt}) [Enter = acak]: ").strip().replace(",", ".")
        if raw == "":
            value = round(random.uniform(rand_lo, rand_hi), 2)
            print(f"      -> {value}{unit_txt} (acak)")
            return value
        try:
            value = float(raw)
        except ValueError:
            print("      Masukkan angka, contoh: 27.5")
            continue
        if not lo <= value <= hi:
            print(f"      Nilai harus di antara {lo:g} dan {hi:g}")
            continue
        return value


def ask_int(prompt, default):
    while True:
        raw = input(f"{prompt} [Enter = {default}]: ").strip()
        if raw == "":
            return default
        if raw.isdigit():
            return int(raw)
        print("  Masukkan bilangan bulat >= 0")


def ask_mode(default="ecc"):
    while True:
        raw = input(f"Mode enkripsi kunci sesi [rsa/ecc] (Enter = {default}): ").strip().lower()
        if raw == "":
            return default
        if raw in ("rsa", "ecc"):
            return raw
        print("  Pilih rsa atau ecc")


def ask_yes(prompt, default=True):
    hint = "Y/n" if default else "y/N"
    raw = input(f"{prompt} [{hint}]: ").strip().lower()
    if raw == "":
        return default
    return raw in ("y", "ya", "yes")


def send_queue(gateway, mode, url, keys):
    """Send every queued reading, oldest first. Stops at the first failure;
    unsent readings stay in the sensor database and are retried next time."""
    while gateway.pending_count() > 0:
        reading = gateway.next_pending_reading()
        stamp = reading.get("reading_timestamp", "?")
        try:
            payload, response, enc_s, rt_s = encrypt_and_send(gateway, mode, url, keys)
        except requests.exceptions.RequestException as err:
            print(f"  [GAGAL] Tidak bisa menghubungi server: {err.__class__.__name__}")
            print(f"          Data tetap di antrean ({gateway.pending_count()} pesan) dan dikirim ulang nanti.")
            return False

        if response.status_code == 200:
            dec_ms = response.json().get("decryption_duration", float("nan"))
            size = len(json.dumps(payload).encode())
            print(f"  [200] Terkirim: pembacaan {stamp}")
            print(f"        mode {mode.upper()}, paket {size} B, enkripsi {enc_s*1000:.2f} ms, "
                  f"dekripsi server {dec_ms:.2f} ms, round trip {rt_s*1000:.1f} ms")
        else:
            print(f"  [{response.status_code}] Ditolak server: {error_text(response)}")
            print(f"        Data tetap di antrean ({gateway.pending_count()} pesan). "
                  "Cek log server untuk alasannya.")
            return False
    return True


def run_manual(url, keys):
    print("\n=== Input data telemetry manual ===")
    print(f"Server: {url}")
    sensor_id = ask_int("ID sensor", 1)
    gateway = EdgeGateway(sensor_id)
    mode = ask_mode()

    pending = gateway.pending_count()
    if pending:
        print(f"\nAda {pending} data lama yang belum terkirim untuk sensor {sensor_id}.")
        if ask_yes("Kirim sekarang?"):
            send_queue(gateway, mode, url, keys)

    while True:
        print(f"\nMasukkan pembacaan sensor {sensor_id}:")
        reading = {key: ask_float(label, unit, lo, hi, rlo, rhi)
                   for key, label, unit, lo, hi, rlo, rhi in FIELDS}
        reading = {"reading_timestamp": datetime.now(TZ_WIB).isoformat(), **reading}

        print("\nData yang akan dienkripsi dan dikirim:")
        print(json.dumps(reading, indent=2, ensure_ascii=False))
        if ask_yes("Kirim data ini?"):
            gateway.add_sensor_data(reading)
            send_queue(gateway, mode, url, keys)
        else:
            print("  Dibatalkan, data tidak disimpan.")

        if not ask_yes("\nInput data lagi?"):
            left = gateway.pending_count()
            if left:
                print(f"{left} data masih di antrean dan akan dikirim saat mode manual dijalankan lagi.")
            break


# ---------------------------------------------------------------------------
# Benchmark mode (unchanged measurements)
# ---------------------------------------------------------------------------
def run_benchmark(url, keys):
    print(f"\n=== Benchmark RSA vs ECC -> {url} ===")
    sensor1 = EdgeGateway(1)

    # Leftover readings (e.g. from manual mode) would be sent first and distort
    # the payload sizes, so send them before measuring.
    if sensor1.pending_count():
        print(f"Mengirim {sensor1.pending_count()} data lama di antrean sensor 1 dulu (tidak diukur)...")
        if not send_queue(sensor1, "ecc", url, keys):
            raise SystemExit("Antrean tidak bisa dikosongkan; benchmark dibatalkan.")

    modes = ["rsa", "ecc"]
    sizes = [1, 10, 100]

    with open(SUMMARY_PATH, "w") as output_file:
        for mode in modes:
            for size in sizes:
                print(f"  {mode} {size}kb ...")
                durations_encryption = []
                packet_size = []
                generate_durations = []
                decryption_durations = []
                round_trip_durations = []

                for _ in range(30):
                    sensor1.generate_sensor_data(size)

                start_tp = time.perf_counter()
                for _ in range(30):
                    start_encrypt = time.perf_counter()
                    session_key, key, generate_dur = prepare_rsa_key(keys.rsa_pem) if mode == "rsa" else prepare_ecc_key(keys.ecc_pem)
                    payload = sensor1.build_payload(mode, session_key, key)
                    end_encrypt = time.perf_counter()

                    start_rt = time.perf_counter()
                    response = sensor1.post(url, json=payload)
                    end_rt = time.perf_counter()
                    if response.status_code != 200:
                        raise RuntimeError(f"{mode} {size}kb: server returned {response.status_code} {response.text}")
                    # server reports milliseconds (performance.now()); store seconds like the other columns
                    decryption_duration = response.json()["decryption_duration"] / 1000

                    durations_encryption.append(end_encrypt - start_encrypt)
                    decryption_durations.append(decryption_duration)
                    round_trip_durations.append(end_rt - start_rt)
                    packet_size.append(len(json.dumps(payload).encode()))
                    generate_durations.append(generate_dur)
                end_tp = time.perf_counter()

                df = pd.DataFrame({"Encryption (second)": durations_encryption,
                                "decryption (second)": decryption_durations,
                                "round trip (second)": round_trip_durations,
                                "size (byte)": packet_size,
                                "session key generation (second)": generate_durations})
                df.to_csv(os.path.join(CSV_PATH, f"{mode} {size}kb.csv"), index=False)

                df_tp = pd.DataFrame({"time (second)": [start_tp], "time after 30 messages sent (second)": [end_tp]})
                df_tp.to_csv(os.path.join(CSV_PATH, f"{mode} {size}kb throughput.csv"), index=False)

                output_file.write(f"{mode} {size}kb\n")

                d1 = np.array(durations_encryption) * 1000
                output_file.write(f"Encrypt- mean: {np.mean(d1):.3f} ms, median: {np.median(d1):.3f} ms, std: {np.std(d1):.3f} ms\n")

                d2 = np.array(decryption_durations) * 1000
                output_file.write(f"Decrypt- mean: {np.mean(d2):.3f} ms, median: {np.median(d2):.3f} ms, std: {np.std(d2):.3f} ms\n")

                d5 = np.array(round_trip_durations) * 1000
                output_file.write(f"Round trip- mean: {np.mean(d5):.3f} ms, median: {np.median(d5):.3f} ms, std: {np.std(d5):.3f} ms\n")

                output_file.write(f"Throughput: {30/(end_tp-start_tp)} message/second\n")

                d3 = np.array(packet_size)
                output_file.write(f"JSON size - mean: {np.mean(d3):.3f} bytes, median: {np.median(d3):.3f} bytes, std: {np.std(d3):.3f} bytes\n")

                d4 = np.array(generate_durations) * 1000
                output_file.write(f"Generate key- mean: {np.mean(d4):.3f} ms, median: {np.median(d4):.3f} ms, std: {np.std(d4):.3f} ms\n")

                output_file.write("="*80+"\n\n")
    print(f"Selesai. Ringkasan di {SUMMARY_PATH}, CSV di {CSV_PATH}")


# ---------------------------------------------------------------------------
# Server public keys
# ---------------------------------------------------------------------------
def obtain_keys(args):
    """Get the server's public keys once, before any message is encrypted
    (so fetching them is never part of the benchmark timing)."""
    try:
        keys = get_server_keys(args.url, source=args.key_source,
                               accept_new=args.trust_new_key)
    except KeyMismatchError as err:
        raise SystemExit(f"\nDIHENTIKAN. {err}")
    except (KeyFetchError, FileNotFoundError, ValueError) as err:
        raise SystemExit(f"\nTidak bisa mendapatkan public key server: {err}")

    print(f"Public key server: {keys.source}")
    print(f"  RSA sha256: {format_fingerprint(keys.rsa_fingerprint)}")
    print(f"  ECC sha256: {format_fingerprint(keys.ecc_fingerprint)}")
    return keys


# ---------------------------------------------------------------------------
# View the readings stored on the server
# ---------------------------------------------------------------------------
def readings_url(telemetry_url):
    parts = urlsplit(telemetry_url)
    path = parts.path.rstrip("/")
    if path.endswith("/telemetry"):
        path = path[:-len("/telemetry")]
    return urlunsplit((parts.scheme, parts.netloc, path + "/readings", "", ""))


def show_readings(url, token, sensor_id=None, limit=20):
    if not token:
        raise SystemExit("Butuh token: set environment variable READINGS_TOKEN atau pakai --token")
    params = {"limit": limit}
    if sensor_id is not None:
        params["sensor_id"] = sensor_id
    endpoint = readings_url(url)
    try:
        r = requests.get(endpoint, params=params, timeout=15,
                         headers={"Authorization": f"Bearer {token.strip()}"})
    except requests.exceptions.RequestException as err:
        raise SystemExit(f"Tidak bisa menghubungi {endpoint}: {err.__class__.__name__}")
    if r.status_code == 401:
        raise SystemExit("401: token salah")
    if r.status_code == 404:
        raise SystemExit("404: endpoint /readings mati (READINGS_TOKEN belum di-set di server) "
                         "atau server masih versi lama")
    if r.status_code != 200:
        raise SystemExit(f"Server menjawab HTTP {r.status_code}: {error_text(r)}")

    rows = r.json()["readings"]
    print(f"\n{len(rows)} data terbaru dari {endpoint}"
          + (f" (sensor {sensor_id})" if sensor_id is not None else "") + "\n")
    if not rows:
        print("Belum ada data. Kirim dulu dengan: python main.py --manual")
        return
    header = f"{'id':>5}  {'sensor':>6}  {'mode':4}  {'diterima server (WIB)':19}  {'suhu':>6}  {'udara%':>6}  {'tanah%':>6}  {'pH':>5}"
    print(header)
    print("-" * len(header))
    for row in rows:
        d = row["data"] if isinstance(row["data"], dict) else {}
        try:
            received = datetime.fromisoformat(row["received_at"].replace("Z", "+00:00")).astimezone(TZ_WIB).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            received = row["received_at"][:19]
        def num(key):
            v = d.get(key)
            return f"{v:.2f}" if isinstance(v, (int, float)) else "-"
        print(f"{row['id']:>5}  {row['sensor_id']:>6}  {row['mode']:4}  {received:19}  "
              f"{num('temperature'):>6}  {num('air_humidity'):>6}  {num('soil_moisture'):>6}  {num('soil_ph'):>5}")


def normalize_telemetry_url(url):
    """Accept the bare service URL too: https://x.run.app -> https://x.run.app/telemetry"""
    parts = urlsplit(url)
    if parts.path in ("", "/"):
        return urlunsplit((parts.scheme, parts.netloc, "/telemetry", "", ""))
    return url


# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Edge gateway: kirim telemetry terenkripsi (AES-GCM + RSA/ECC) ke server")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--manual", action="store_true", help="input data telemetry manual")
    group.add_argument("--benchmark", action="store_true", help="jalankan benchmark RSA vs ECC")
    group.add_argument("--show-readings", action="store_true",
                       help="lihat data yang sudah diterima server (butuh token)")
    group.add_argument("--fetch-key", action="store_true",
                       help="ambil public key dari server, tampilkan fingerprint, simpan ke frontend/certs")
    parser.add_argument("--url", default=DEFAULT_URL, help="URL endpoint /telemetry")
    parser.add_argument("--key-source", choices=["server", "file"], default="server",
                        help="server = minta ke GET /public-key (default); file = hanya frontend/certs")
    parser.add_argument("--trust-new-key", action="store_true",
                        help="terima public key server yang berbeda dari salinan tersimpan")
    parser.add_argument("--token", default=os.environ.get("READINGS_TOKEN"),
                        help="token untuk --show-readings (default: env READINGS_TOKEN)")
    parser.add_argument("--sensor-id", type=int, default=None, help="filter --show-readings per sensor")
    parser.add_argument("--limit", type=int, default=20, help="jumlah data untuk --show-readings (maks 500)")
    args = parser.parse_args()
    args.url = normalize_telemetry_url(args.url)

    try:
        if args.show_readings:
            show_readings(args.url, args.token, args.sensor_id, args.limit)
            return
        if args.manual:
            action = "manual"
        elif args.benchmark:
            action = "benchmark"
        elif args.fetch_key:
            action = "fetch"
        else:
            print("Pilih mode:")
            print("  1) Input data telemetry manual")
            print("  2) Benchmark RSA vs ECC (30 pesan x 3 ukuran x 2 mode)")
            print("  3) Ambil public key dari server")
            print("  4) Lihat data yang sudah diterima server")
            choice = input("Pilihan [1/2/3/4]: ").strip()
            if choice == "4":
                show_readings(args.url, args.token, args.sensor_id, args.limit)
                return
            action = {"2": "benchmark", "3": "fetch"}.get(choice, "manual")

        if action == "fetch" and args.key_source == "file":
            raise SystemExit("--fetch-key butuh --key-source server")
        keys = obtain_keys(args)

        if action == "manual":
            run_manual(args.url, keys)
        elif action == "benchmark":
            run_benchmark(args.url, keys)
    except (KeyboardInterrupt, EOFError):
        print("\nDihentikan.")


if __name__ == "__main__":
    main()
