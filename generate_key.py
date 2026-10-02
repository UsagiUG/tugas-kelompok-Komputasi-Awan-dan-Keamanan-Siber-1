# =================================================================================
# =================================================================================
# ECC
# =================================================================================
# =================================================================================
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (Encoding, PublicFormat, PrivateFormat, NoEncryption)

backend_dir = os.path.join('.', 'backend', 'certs')
frontend_dir = os.path.join('.', 'frontend', 'certs')

# Pastikan folder backend & frontend sudah ada agar tidak error
os.makedirs(backend_dir, exist_ok=True)
os.makedirs(frontend_dir, exist_ok=True)

ecc_private_key = X25519PrivateKey.generate()
ecc_public_key  = ecc_private_key.public_key()

ecc_private_pem = ecc_private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode('utf-8')
ecc_public_pem  = ecc_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

# print(ecc_private_pem)
# print(ecc_public_pem)

with open(os.path.join(backend_dir, 'ecc_private_key.pem'), 'w', encoding='utf-8') as f:
    f.write(ecc_private_pem)

with open(os.path.join(frontend_dir, 'ecc_public_key.pem'), 'w', encoding='utf-8') as f:
    f.write(ecc_public_pem)

# =================================================================================
# =================================================================================
# RSA
# =================================================================================
# =================================================================================
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate kunci privat
rsa_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Ekstrak menjadi format PEM string
rsa_private_pem = rsa_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

rsa_public_key = rsa_private_key.public_key()

# Ekstrak menjadi format PEM string
rsa_public_pem = rsa_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

with open(os.path.join(backend_dir, 'rsa_private_key.pem'), 'w', encoding='utf-8') as f:
    f.write(rsa_private_pem)

with open(os.path.join(frontend_dir, 'rsa_public_key.pem'), 'w', encoding='utf-8') as f:
    f.write(rsa_public_pem)