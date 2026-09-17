"""
Evaluator module for ZeroSight.
Executes eligibility policies over encrypted ciphertexts.
Operates with ZERO access to applicant private keys or plaintext data.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Union
from phe import paillier

from bee.serializer import (
    deserialize_public_key,
    deserialize_encrypted_dict,
    serialize_encrypted_number,
)
from bee.policy import compute_policy_hash, load_policy


def evaluate_encrypted(
    public_key: paillier.PaillierPublicKey,
    encrypted_data: Dict[str, paillier.EncryptedNumber],
    policy: Dict[str, Any],
) -> paillier.EncryptedNumber:
    """
    Computes policy score using homomorphic addition and scalar multiplication.
    The evaluator only sees ciphertexts.
    """
    if not isinstance(public_key, paillier.PaillierPublicKey):
        raise TypeError("Expected paillier.PaillierPublicKey instance")

    base_score = policy.get("base_score", 0)
    weights = policy.get("weights", {})

    # Start with encrypted base score
    encrypted_score = public_key.encrypt(base_score)

    # Accumulate weighted inputs homomorphically
    for field_name, weight in weights.items():
        if field_name in encrypted_data:
            enc_val = encrypted_data[field_name]
            if not isinstance(enc_val, paillier.EncryptedNumber):
                raise TypeError(f"Field '{field_name}' must be an EncryptedNumber")
            # Homomorphic scalar multiplication and addition
            encrypted_score = encrypted_score + (enc_val * weight)

    return encrypted_score


def evaluate_encrypted_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Stateless evaluator endpoint interface.
    Receives JSON-serializable request payload and returns JSON response.
    Completely isolated from client execution context.
    """
    if "public_key" not in payload:
        raise ValueError("Missing 'public_key' in evaluator payload")
    if "encrypted_fields" not in payload:
        raise ValueError("Missing 'encrypted_fields' in evaluator payload")
    if "policy" not in payload:
        raise ValueError("Missing 'policy' in evaluator payload")

    policy = payload["policy"]
    public_key = deserialize_public_key(payload["public_key"])
    encrypted_data = deserialize_encrypted_dict(public_key, payload["encrypted_fields"])

    # Verify policy integrity if policy_hash is provided
    expected_hash = compute_policy_hash(policy)
    if "policy_hash" in payload and payload["policy_hash"] != expected_hash:
        raise ValueError("Policy hash mismatch: evaluator rejected altered policy definition")

    encrypted_score = evaluate_encrypted(public_key, encrypted_data, policy)

    return {
        "status": "success",
        "policy_id": policy.get("policy_id", "unknown"),
        "policy_hash": expected_hash,
        "encrypted_score": serialize_encrypted_number(encrypted_score),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "fields_evaluated": list(encrypted_data.keys()),
    }


def evaluate_plaintext(
    data: Dict[str, Any],
    policy: Dict[str, Any],
) -> int:
    """
    Computes plaintext score on unencrypted data.
    STRICT PRIVACY RULE: This function is executed client-side ONLY
    for local testing and demonstration comparisons.
    """
    base_score = policy.get("base_score", 0)
    weights = policy.get("weights", {})

    score = base_score
    for field_name, weight in weights.items():
        val = data.get(field_name, 0)
        score += weight * val

    return score
