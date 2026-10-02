"""Server public keys for the edge gateway.

Where the keys come from:
  - "server": GET <server>/public-key. The answer is checked (key type, RSA size,
    SHA-256 fingerprint) and compared with the copy pinned in frontend/certs:
      * no pinned copy yet  -> trust on first use: save it, show the fingerprints
      * same as pinned      -> use it
      * different           -> refuse (possible man-in-the-middle or key rotation)
                               unless the caller explicitly accepts the new key
    If the server cannot be reached, the pinned copy is used so readings can
    still be encrypted and queued.
  - "file": only the pinned copy in frontend/certs (written by generate_key.py
    or by an earlier fetch).

Fingerprint = SHA-256 of the DER SubjectPublicKeyInfo, the same value the
server prints in its log at startup, so it can be compared out of band.
"""
import hashlib
import os
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_public_key)

CERTS_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'certs'))
RSA_PATH = os.path.join(CERTS_DIR, 'rsa_public_key.pem')
ECC_PATH = os.path.join(CERTS_DIR, 'ecc_public_key.pem')
MIN_RSA_BITS = 2048
LOCAL_HOSTS = ('localhost', '127.0.0.1', '::1')


class KeyFetchError(Exception):
    """The server did not give usable public keys."""


class KeyMismatchError(Exception):
    """The server's key differs from the pinned copy."""

    def __init__(self, changed, pinned, fetched):
        self.changed, self.pinned, self.fetched = changed, pinned, fetched
        lines = [f"Public key {'/'.join(changed)} dari server BERBEDA dengan yang tersimpan di {CERTS_DIR}."]
        for name in changed:
            attr = 'rsa_fingerprint' if name == 'RSA' else 'ecc_fingerprint'
            lines.append(f"  {name} tersimpan : {format_fingerprint(getattr(pinned, attr))}")
            lines.append(f"  {name} dari server: {format_fingerprint(getattr(fetched, attr))}")
        lines.append("Bisa karena key server memang diganti, atau ada pihak di tengah (MITM) yang menukar key.")
        lines.append("Cocokkan fingerprint baru dengan log server, lalu jalankan: python main.py --fetch-key --trust-new-key")
        super().__init__("\n".join(lines))


@dataclass
class ServerKeys:
    rsa_pem: str
    ecc_pem: str
    rsa_fingerprint: str
    ecc_fingerprint: str
    source: str


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def fingerprint(pem: str) -> str:
    key = load_pem_public_key(pem.encode('utf-8'))
    der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def format_fingerprint(fp: str) -> str:
    return ' '.join(fp[i:i + 4] for i in range(0, len(fp), 4))


def _check_rsa(pem: str):
    key = load_pem_public_key(pem.encode('utf-8'))
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError('rsa_public_key bukan key RSA')
    if key.key_size < MIN_RSA_BITS:
        raise ValueError(f'key RSA hanya {key.key_size} bit (minimal {MIN_RSA_BITS})')


def _check_ecc(pem: str):
    key = load_pem_public_key(pem.encode('utf-8'))
    if not isinstance(key, X25519PublicKey):
        raise ValueError('ecc_public_key bukan key X25519')


def _make_keys(rsa_pem: str, ecc_pem: str, source: str) -> ServerKeys:
    _check_rsa(rsa_pem)
    _check_ecc(ecc_pem)
    return ServerKeys(rsa_pem, ecc_pem, fingerprint(rsa_pem), fingerprint(ecc_pem), source)


def public_key_url(telemetry_url: str) -> str:
    """http://host:3000/telemetry -> http://host:3000/public-key"""
    parts = urlsplit(telemetry_url)
    path = parts.path.rstrip('/')
    if path.endswith('/telemetry'):
        path = path[:-len('/telemetry')]
    return urlunsplit((parts.scheme, parts.netloc, path + '/public-key', '', ''))


def is_insecure(url: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme == 'http' and parts.hostname not in LOCAL_HOSTS


# ---------------------------------------------------------------------------
# sources
# ---------------------------------------------------------------------------
def load_from_files() -> ServerKeys:
    with open(RSA_PATH, 'r', encoding='utf-8') as f:
        rsa_pem = f.read()
    with open(ECC_PATH, 'r', encoding='utf-8') as f:
        ecc_pem = f.read()
    return _make_keys(rsa_pem, ecc_pem, f'file ({CERTS_DIR})')


def save_to_files(keys: ServerKeys):
    os.makedirs(CERTS_DIR, exist_ok=True)
    for path, pem in ((RSA_PATH, keys.rsa_pem), (ECC_PATH, keys.ecc_pem)):
        with open(path, 'w', encoding='utf-8') as f:
            f.write(pem)


def fetch_from_server(telemetry_url: str, timeout: float = 10) -> ServerKeys:
    url = public_key_url(telemetry_url)
    try:
        response = requests.get(url, timeout=timeout)
    except requests.exceptions.RequestException as err:
        raise KeyFetchError(f'tidak bisa menghubungi {url} ({err.__class__.__name__})') from err
    if response.status_code != 200:
        raise KeyFetchError(f'{url} menjawab HTTP {response.status_code}')
    try:
        data = response.json()
        keys = _make_keys(data['rsa_public_key'], data['ecc_public_key'], f'server ({url})')
    except (ValueError, KeyError, TypeError) as err:
        raise KeyFetchError(f'jawaban {url} tidak berisi public key yang valid: {err}') from err

    # Consistency check with the fingerprints the server reports (if any).
    for name, claimed, actual in (('RSA', data.get('rsa_fingerprint_sha256'), keys.rsa_fingerprint),
                                  ('ECC', data.get('ecc_fingerprint_sha256'), keys.ecc_fingerprint)):
        if claimed and claimed != actual:
            raise KeyFetchError(f'fingerprint {name} yang dikirim server tidak cocok dengan key-nya')
    return keys


def get_server_keys(telemetry_url: str, source: str = 'server',
                    accept_new: bool = False, log=print) -> ServerKeys:
    """Main entry point; see the module docstring for the rules."""
    if source == 'file':
        return load_from_files()

    if is_insecure(telemetry_url):
        log('PERINGATAN: server diakses lewat http (bukan https). Public key bisa ditukar di jalan; '
            'pakai https untuk server di internet.')

    try:
        fetched = fetch_from_server(telemetry_url)
    except KeyFetchError as err:
        try:
            cached = load_from_files()
        except FileNotFoundError:
            raise KeyFetchError(f'{err}, dan belum ada salinan public key di {CERTS_DIR}') from err
        log(f'PERINGATAN: {err}. Memakai public key tersimpan.')
        cached.source += ', server tidak bisa dihubungi'
        return cached

    try:
        pinned = load_from_files()
    except FileNotFoundError:
        pinned = None

    if pinned is None:
        save_to_files(fetched)
        fetched.source += ', pertama kali: disimpan ke frontend/certs'
        log('Public key server baru pertama kali diterima dan disimpan (trust on first use).')
        log('Cocokkan fingerprint di bawah dengan log server untuk memastikan key-nya asli.')
        return fetched

    changed = [name for name, old, new in (('RSA', pinned.rsa_fingerprint, fetched.rsa_fingerprint),
                                           ('ECC', pinned.ecc_fingerprint, fetched.ecc_fingerprint))
               if old != new]
    if not changed:
        fetched.source += ', cocok dengan salinan tersimpan'
        return fetched
    if not accept_new:
        raise KeyMismatchError(changed, pinned, fetched)

    save_to_files(fetched)
    fetched.source += f", key {'/'.join(changed)} baru diterima dan disimpan"
    return fetched


# Backward compatibility for code (e.g. main.ipynb) that imports the old names:
#   from src.server_public_key import server_rsa_public_key, server_ecc_public_key
def __getattr__(name):
    if name == 'server_rsa_public_key':
        return load_from_files().rsa_pem
    if name == 'server_ecc_public_key':
        return load_from_files().ecc_pem
    raise AttributeError(name)


if __name__ == '__main__':
    k = load_from_files()
    print(CERTS_DIR)
    print('RSA sha256:', format_fingerprint(k.rsa_fingerprint))
    print('ECC sha256:', format_fingerprint(k.ecc_fingerprint))
