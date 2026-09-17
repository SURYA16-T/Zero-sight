import os
import json
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from phe import paillier

# OWASP-recommended Argon2id parameters
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 65536   # 64 MiB
ARGON2_PARALLELISM = 4

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=passphrase.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID,
    )

def export_encrypted_private_key(private_key: paillier.PaillierPrivateKey, passphrase: str) -> dict:
    if len(passphrase) < 12:
        raise ValueError("Passphrase must be at least 12 characters long")
    
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)

    payload = json.dumps({
        "p": str(private_key.p),
        "q": str(private_key.q),
    }).encode()

    ciphertext = aesgcm.encrypt(nonce, payload, None)

    return {
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "kdf": "argon2id",
        "kdf_params": {
            "time_cost": ARGON2_TIME_COST,
            "memory_cost_kib": ARGON2_MEMORY_COST_KIB,
            "parallelism": ARGON2_PARALLELISM,
        },
    }

def load_encrypted_private_key(blob: dict, passphrase: str, public_key: paillier.PaillierPublicKey) -> paillier.PaillierPrivateKey:
    salt = bytes.fromhex(blob["salt"])
    nonce = bytes.fromhex(blob["nonce"])
    ciphertext = bytes.fromhex(blob["ciphertext"])
    
    if blob.get("kdf") == "argon2id":
        key = _derive_key(passphrase, salt)
    else:
        raise ValueError("Unsupported KDF")

    aesgcm = AESGCM(key)
    payload = json.loads(aesgcm.decrypt(nonce, ciphertext, None))

    return paillier.PaillierPrivateKey(public_key, int(payload["p"]), int(payload["q"]))
