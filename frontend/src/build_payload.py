from datetime import datetime, timezone, timedelta
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import json
from src.sensor_simulation import sensor_simulation
import sqlite3
import requests
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

class EdgeGateway:
	def __init__(self, sensor_id, return_aad_bytes: bool = False):
		self.sensor_id = sensor_id
		self.return_aad_bytes = return_aad_bytes
		self.db_conn = sqlite3.connect(f"sensor{sensor_id}.db")
		cursor_init = self.db_conn.cursor()
		# cursor_init.execute("""
		# 	CREATE TABLE IF NOT EXISTS self_id (
		# 	id INTEGER PRIMARY KEY)
		# """)
		cursor_init.execute("""
			CREATE TABLE IF NOT EXISTS session_keys (
			id			INTEGER	PRIMARY KEY,
			key 		TEXT	NOT NULL,
			times_used	INTEGER	NOT NULL)
		""")
		cursor_init.execute("""
			CREATE TABLE IF NOT EXISTS sensor_readings (
			id			INTEGER	PRIMARY KEY,
			data		TEXT	NOT NULL,
			sent_status	INTEGER	NOT NULL)
		""")
		# cursor_init.execute("INSERT OR IGNORE INTO self_id (id) VALUES (?)", (sensor_id,))
		self.db_conn.commit()

	# def get_latest_session_key(self):
	# 	cursor = self.db_conn.cursor()
	# 	cursor.execute("""
	# 			SELECT id, key FROM session_keys ORDER BY id DESC LIMIT 1
	# 		""")
	# 	return cursor.fetchone()

	def get_latest_session_key(self):
		return self.db_conn.execute("""
				SELECT id, key FROM session_keys ORDER BY id DESC LIMIT 1
			""").fetchone()



	def build_payload(self, mode: str, session_key, key) -> dict:
		tz_wib = timezone(timedelta(hours=7))

		# this one gonna cascade depending on the result. None is not a valid session_key. You need to use the current session_key
		# session_key = get_session_key() # -> raw_bytes
		# session_key for testing because get_session_key isn't finished yet

		aad = {
			'sensor_id': self.sensor_id,
			'mode': mode,
			'transmission_timestamp': datetime.now(tz_wib).isoformat(),
			'key': base64.b64encode(key).decode('utf-8') 
		}
		aad_bytes = json.dumps(aad, separators=(',', ':'), sort_keys=True).encode('utf-8')

		aesgcm = AESGCM(session_key)
		iv = os.urandom(12)

		plaintext_string = self.db_conn.execute("""
			SELECT data FROM sensor_readings
			WHERE sent_status = 0
			ORDER BY id ASC
			LIMIT 1
		""").fetchone()[0]
		# print(plaintext_string)

		plaintext_bytes = plaintext_string.encode('utf-8') 
		# print(plaintext_bytes)
		encrypted_raw = aesgcm.encrypt(iv, plaintext_bytes, aad_bytes)
		ciphertext = encrypted_raw[:-16]
		tag = encrypted_raw[-16:]

		return {
			'aad': aad if not self.return_aad_bytes else aad_bytes.decode('utf-8'),
			'nonce': base64.b64encode(iv).decode('utf-8'),
			'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
			'tag': base64.b64encode(tag).decode('utf-8')
		}

	def post(self, url: str, *, json: dict):
		response=requests.post(url, json=json, timeout=30, allow_redirects=False)
		if response.status_code in (301, 302, 307, 308):
			print(f"  [PERINGATAN] Server redirect ke: {response.headers.get('Location')}")
			print("  Kemungkinan endpoint HTTP tidak diizinkan; gunakan HTTPS.")
			return response  # tidak ikuti redirect, biar terlihat jelas apa yang terjadi
		if response.status_code == 200:
			self.db_conn.execute("""
				UPDATE sensor_readings
				SET sent_status = 1
				WHERE id = (
					SELECT id
					FROM sensor_readings
					WHERE sent_status = 0
					ORDER BY id ASC
					LIMIT 1
				)
			""")
			self.db_conn.commit()
		return response

	def generate_sensor_data(self, dummy_size_kb: int = 1):
		plaintext_string = json.dumps(sensor_simulation(dummy_size_kb))# -> dict[str,float]

		self.db_conn.execute("""
			INSERT INTO sensor_readings (data, sent_status)
			VALUES (?, 0)
		""", (plaintext_string,))
		self.db_conn.commit()

	def add_sensor_data(self, reading: dict):
		"""Queue a reading given by the caller (e.g. typed in manually)."""
		self.db_conn.execute("""
			INSERT INTO sensor_readings (data, sent_status)
			VALUES (?, 0)
		""", (json.dumps(reading),))
		self.db_conn.commit()

	def pending_count(self) -> int:
		"""Number of readings still waiting to be sent."""
		return self.db_conn.execute(
			"SELECT COUNT(*) FROM sensor_readings WHERE sent_status = 0"
		).fetchone()[0]

	def next_pending_reading(self):
		"""The reading build_payload() will send next, as a dict (None if the queue is empty)."""
		row = self.db_conn.execute("""
			SELECT data FROM sensor_readings
			WHERE sent_status = 0
			ORDER BY id ASC
			LIMIT 1
		""").fetchone()
		return json.loads(row[0]) if row else None

if __name__ == "__main__":
	sensor1 = EdgeGateway(1)
	sensor1.generate_sensor_data()