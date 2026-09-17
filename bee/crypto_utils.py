"""
Cryptographic utilities for the ZeroSight Blind Eligibility Engine.
Wraps Paillier Homomorphic Encryption with security defaults and fingerprinting.
"""

import hashlib
from typing import Tuple, Dict, Any, Union
from phe import paillier

from bee.config import DEFAULT_KEY_SIZE, FALLBACK_KEY_SIZE


def generate_keypair(
    key_size: int = DEFAULT_KEY_SIZE,
) -> Tuple[paillier.PaillierPublicKey, paillier.PaillierPrivateKey]:
    """
    Generates a Paillier key pair using OS entropy.
    Defaults to 2048-bit modulus for NIST SP 800-57 security compliance.
    """
    if key_size not in (1024, 2048, 3072, 4096):
        raise ValueError(f"Unsupported key size: {key_size}. Use 1024 (fast demo) or 2048+.")

    public_key, private_key = paillier.generate_paillier_keypair(n_length=key_size)
    return public_key, private_key


def compute_public_key_fingerprint(public_key: paillier.PaillierPublicKey) -> str:
    """
    Computes a cryptographic SHA-256 fingerprint of the Paillier public key modulus.
    Used in verifiable audit receipts.
    """
    n_bytes = str(public_key.n).encode("utf-8")
    return hashlib.sha256(n_bytes).hexdigest()[:16]


def encrypt_field(
    public_key: paillier.PaillierPublicKey,
    value: Union[int, float],
) -> paillier.EncryptedNumber:
    """
    Encrypts an integer or float value using the provided Paillier public key.
    Applies fresh random blinding factor.
    """
    if not isinstance(value, (int, float)):
        raise TypeError(f"Value must be int or float, got {type(value)}")
    return public_key.encrypt(value)


def encrypt_fields(
    public_key: paillier.PaillierPublicKey,
    data: Dict[str, Union[int, float]],
) -> Dict[str, paillier.EncryptedNumber]:
    """
    Encrypts all fields in the provided dictionary under the public key.
    """
    encrypted_dict = {}
    for field_name, value in data.items():
        encrypted_dict[field_name] = encrypt_field(public_key, value)
    return encrypted_dict


def decrypt_score(
    private_key: paillier.PaillierPrivateKey,
    encrypted_score: paillier.EncryptedNumber,
) -> int:
    """
    Decrypts an encrypted score using the client's private key.
    Returns the integer score rounded to nearest whole number if applicable.
    """
    if not isinstance(private_key, paillier.PaillierPrivateKey):
        raise TypeError("Expected paillier.PaillierPrivateKey instance")
    decrypted_val = private_key.decrypt(encrypted_score)
    # Round to nearest integer if floating representation was used
    if isinstance(decrypted_val, float):
        return int(round(decrypted_val))
    return int(decrypted_val)
