"""
Policy management and cryptographic integrity hashing for ZeroSight.
Guarantees that evaluators cannot modify formula weights or eligibility thresholds.
"""

import os
import json
import hashlib
from typing import Dict, Any, List


def compute_policy_hash(policy: Dict[str, Any]) -> str:
    """
    Computes a canonical SHA-256 digest of the policy specification.
    Keys are sorted and delimiters are standardized to avoid formatting discrepancies.
    """
    canonical_json = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def validate_policy_structure(policy: Dict[str, Any]) -> None:
    """
    Validates that a policy dictionary complies with required schema rules.
    """
    required_keys = ["policy_id", "version", "base_score", "weights", "threshold", "required_fields"]
    for key in required_keys:
        if key not in policy:
            raise ValueError(f"Malformed policy: missing mandatory key '{key}'")

    if not isinstance(policy["base_score"], (int, float)):
        raise TypeError("policy 'base_score' must be a numeric value")

    if not isinstance(policy["threshold"], (int, float)):
        raise TypeError("policy 'threshold' must be a numeric value")

    if not isinstance(policy["weights"], dict):
        raise TypeError("policy 'weights' must be a dictionary")

    if not isinstance(policy["required_fields"], list):
        raise TypeError("policy 'required_fields' must be a list")


def load_policy(policy_path_or_name: str) -> Dict[str, Any]:
    """
    Loads a policy JSON file from a path or by its filename inside the policies directory.
    Attaches computed SHA-256 integrity hash.
    """
    # Check if direct file exists
    if os.path.isfile(policy_path_or_name):
        target_file = policy_path_or_name
    else:
        # Check relative to project root policies folder
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        policies_dir = os.path.join(base_dir, "policies")
        candidate = os.path.join(policies_dir, policy_path_or_name)
        if not candidate.endswith(".json"):
            candidate += ".json"
        if os.path.isfile(candidate):
            target_file = candidate
        else:
            raise FileNotFoundError(f"Policy file not found: {policy_path_or_name}")

    with open(target_file, "r", encoding="utf-8") as f:
        policy = json.load(f)

    validate_policy_structure(policy)
    policy["_hash"] = compute_policy_hash(policy)
    return policy
