import pytest
from bee.crypto_utils import generate_keypair, encrypt_fields, decrypt_score
from bee.policy import load_policy, compute_policy_hash
from bee.evaluator import evaluate_encrypted, evaluate_plaintext, evaluate_encrypted_payload
from bee.serializer import serialize_public_key, serialize_encrypted_dict


@pytest.fixture
def policy():
    return load_policy("community_welfare_v1")


def test_eligible_evaluation(policy):
    pub, priv = generate_keypair(key_size=1024)
    data = {"income": 18000, "children": 2, "disability": 0, "senior": 0}

    # Plaintext
    pt_score = evaluate_plaintext(data, policy)
    assert pt_score == 38000

    # Encrypted
    enc_data = encrypt_fields(pub, data)
    enc_score = evaluate_encrypted(pub, enc_data, policy)
    dec_score = decrypt_score(priv, enc_score)
    assert dec_score == 38000


def test_not_eligible_evaluation(policy):
    pub, priv = generate_keypair(key_size=1024)
    data = {"income": 45000, "children": 1, "disability": 0, "senior": 0}

    pt_score = evaluate_plaintext(data, policy)
    assert pt_score == 8000

    enc_data = encrypt_fields(pub, data)
    enc_score = evaluate_encrypted(pub, enc_data, policy)
    dec_score = decrypt_score(priv, enc_score)
    assert dec_score == 8000


def test_evaluator_stateless_payload_endpoint(policy):
    pub, priv = generate_keypair(key_size=1024)
    data = {"income": 23000, "children": 1, "disability": 0, "senior": 0}
    enc_data = encrypt_fields(pub, data)

    payload = {
        "policy": policy,
        "policy_hash": compute_policy_hash(policy),
        "public_key": serialize_public_key(pub),
        "encrypted_fields": serialize_encrypted_dict(enc_data),
    }

    response = evaluate_encrypted_payload(payload)
    assert response["status"] == "success"
    assert "encrypted_score" in response
