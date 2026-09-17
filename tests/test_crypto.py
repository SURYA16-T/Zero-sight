import pytest
from bee.crypto_utils import (
    generate_keypair,
    encrypt_field,
    encrypt_fields,
    decrypt_score,
    compute_public_key_fingerprint,
)
from bee.serializer import (
    serialize_public_key,
    deserialize_public_key,
    serialize_encrypted_number,
    deserialize_encrypted_number,
    serialize_encrypted_dict,
    deserialize_encrypted_dict,
)


def test_keygen_and_fingerprint():
    pub, priv = generate_keypair(key_size=1024)
    fingerprint = compute_public_key_fingerprint(pub)
    assert isinstance(fingerprint, str)
    assert len(fingerprint) == 16


def test_encrypt_and_decrypt_single():
    pub, priv = generate_keypair(key_size=1024)
    val = 42000
    enc = encrypt_field(pub, val)
    dec = decrypt_score(priv, enc)
    assert dec == val


def test_encrypt_dict():
    pub, priv = generate_keypair(key_size=1024)
    data = {"income": 18000, "children": 2}
    enc_dict = encrypt_fields(pub, data)
    assert "income" in enc_dict
    assert "children" in enc_dict
    assert decrypt_score(priv, enc_dict["income"]) == 18000
    assert decrypt_score(priv, enc_dict["children"]) == 2


def test_serialization_pipeline():
    pub, priv = generate_keypair(key_size=1024)
    serialized_pub = serialize_public_key(pub)
    assert "n" in serialized_pub

    reconstructed_pub = deserialize_public_key(serialized_pub)
    assert reconstructed_pub.n == pub.n

    enc = encrypt_field(pub, 98765)
    serialized_enc = serialize_encrypted_number(enc)
    assert "ciphertext" in serialized_enc
    assert "exponent" in serialized_enc

    reconstructed_enc = deserialize_encrypted_number(reconstructed_pub, serialized_enc)
    dec = decrypt_score(priv, reconstructed_enc)
    assert dec == 98765
