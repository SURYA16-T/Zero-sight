import pytest
from bee.config import MAX_FILE_SIZE_BYTES
from bee.parser import parse_json_content, ParsingSecurityError
from bee.serializer import (
    deserialize_public_key,
    deserialize_encrypted_number,
)
from bee.policy import load_policy, compute_policy_hash
from bee.crypto_utils import generate_keypair, encrypt_fields, decrypt_score
from bee.evaluator import evaluate_encrypted_payload, evaluate_encrypted, evaluate_plaintext
from bee.serializer import serialize_public_key, serialize_encrypted_dict


def test_tampered_policy_rejection():
    """Ensures evaluator rejects payload if policy hash does not match canonical digest."""
    policy = load_policy("community_welfare_v1")
    pub, priv = generate_keypair(key_size=1024)
    data = {"income": 18000, "children": 2, "disability": 0, "senior": 0}
    enc_data = encrypt_fields(pub, data)

    # Client payload claims a tampered hash
    payload = {
        "policy": policy,
        "policy_hash": "tampered_fake_hash_1234567890",
        "public_key": serialize_public_key(pub),
        "encrypted_fields": serialize_encrypted_dict(enc_data),
    }

    with pytest.raises(ValueError, match="Policy hash mismatch"):
        evaluate_encrypted_payload(payload)


def test_deserialize_malformed_public_key():
    """Ensures parser rejects invalid or hostile public key payloads."""
    with pytest.raises(ValueError, match="Invalid public key payload"):
        deserialize_public_key({})

    with pytest.raises(ValueError, match="modulus must be a positive integer"):
        deserialize_public_key({"n": "-12345"})

    with pytest.raises(ValueError, match="Failed to deserialize public key"):
        deserialize_public_key({"n": "not_a_number"})


def test_deserialize_malformed_ciphertext():
    """Ensures parser rejects invalid or corrupt ciphertext payloads."""
    pub, _ = generate_keypair(key_size=1024)

    with pytest.raises(ValueError, match="Invalid ciphertext payload"):
        deserialize_encrypted_number(pub, {})

    with pytest.raises(ValueError, match="Failed to deserialize encrypted number"):
        deserialize_encrypted_number(pub, {"ciphertext": "abc", "exponent": 0})


def test_extreme_negative_score_wrap_around_protection():
    """
    Tests that large incomes (e.g. $500,000) leading to negative scores
    do not wrap around modulo n into a false positive (Eligible).
    """
    policy = load_policy("community_welfare_v1")
    pub, priv = generate_keypair(key_size=1024)
    data = {"income": 500_000, "children": 0, "disability": 0, "senior": 0}

    # Plaintext score: 50000 - 500000 = -450000
    pt_score = evaluate_plaintext(data, policy)
    assert pt_score == -450000

    enc_data = encrypt_fields(pub, data)
    enc_score = evaluate_encrypted(pub, enc_data, policy)
    dec_score = decrypt_score(priv, enc_score)

    assert dec_score == -450000
    # Must definitely NOT be eligible
    assert dec_score < policy["threshold"]
