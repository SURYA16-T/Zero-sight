"""
Safe JSON serialization and deserialization for Paillier Cryptosystem objects.
Ensures zero use of Python pickle, strictly eliminating deserialization attacks.
"""

from typing import Dict, Any
from phe import paillier


def serialize_public_key(public_key: paillier.PaillierPublicKey) -> Dict[str, str]:
    """
    Serializes a Paillier public key to a dictionary of string values.
    Using strings prevents precision loss across language boundaries.
    """
    if not isinstance(public_key, paillier.PaillierPublicKey):
        raise TypeError("Expected paillier.PaillierPublicKey instance")
    return {"n": str(public_key.n)}


def deserialize_public_key(data: Dict[str, Any]) -> paillier.PaillierPublicKey:
    """
    Reconstructs a Paillier public key from a serialized dictionary.
    """
    if not isinstance(data, dict) or "n" not in data:
        raise ValueError("Invalid public key payload: 'n' parameter missing")
    try:
        n = int(data["n"])
        if n <= 0:
            raise ValueError("Public key modulus must be a positive integer")
        return paillier.PaillierPublicKey(n=n)
    except (ValueError, TypeError) as e:
        raise ValueError(f"Failed to deserialize public key: {e}")


def serialize_encrypted_number(enc: paillier.EncryptedNumber) -> Dict[str, Any]:
    """
    Serializes an EncryptedNumber instance into ciphertext integer and exponent.
    """
    if not isinstance(enc, paillier.EncryptedNumber):
        raise TypeError("Expected paillier.EncryptedNumber instance")
    return {
        "ciphertext": str(enc.ciphertext()),
        "exponent": int(enc.exponent),
    }


def deserialize_encrypted_number(
    public_key: paillier.PaillierPublicKey,
    data: Dict[str, Any],
) -> paillier.EncryptedNumber:
    """
    Reconstructs an EncryptedNumber from serialized ciphertext and exponent.
    """
    if not isinstance(data, dict) or "ciphertext" not in data or "exponent" not in data:
        raise ValueError("Invalid ciphertext payload: 'ciphertext' and 'exponent' required")
    try:
        ciphertext = int(data["ciphertext"])
        exponent = int(data["exponent"])
        return paillier.EncryptedNumber(public_key, ciphertext, exponent)
    except (ValueError, TypeError) as e:
        raise ValueError(f"Failed to deserialize encrypted number: {e}")


def serialize_encrypted_dict(
    encrypted_dict: Dict[str, paillier.EncryptedNumber],
) -> Dict[str, Dict[str, Any]]:
    """
    Serializes a dictionary of encrypted fields.
    """
    return {k: serialize_encrypted_number(v) for k, v in encrypted_dict.items()}


def deserialize_encrypted_dict(
    public_key: paillier.PaillierPublicKey,
    serialized_dict: Dict[str, Dict[str, Any]],
) -> Dict[str, paillier.EncryptedNumber]:
    """
    Deserializes a dictionary of serialized encrypted fields.
    """
    return {
        k: deserialize_encrypted_number(public_key, v)
        for k, v in serialized_dict.items()
    }
