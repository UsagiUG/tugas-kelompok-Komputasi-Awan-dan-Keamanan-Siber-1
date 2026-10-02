from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import time

def prepare_ecc_key(public_key_pem: str) -> tuple[bytes, bytes, float]:
    server_public = load_pem_public_key(public_key_pem.encode("utf-8"))

    start = time.perf_counter()
    ephemeral_private = X25519PrivateKey.generate()


    ephemeral_public  = ephemeral_private.public_key()
    ephemeral_public_bytes = ephemeral_public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    shared_secret = ephemeral_private.exchange(server_public)
    session_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"sensor-server-v1"
    ).derive(shared_secret)
    end = time.perf_counter()
    return session_key, ephemeral_public_bytes, (end-start)
