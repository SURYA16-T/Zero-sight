"""
Client-side Comparison Module for ZeroSight.
Used exclusively for local verification and demonstration to mathematically prove
that encrypted evaluation produces results identical to unencrypted evaluation.
"""

from typing import Dict, Any


def compare_results(
    plaintext_score: int,
    decrypted_score: int,
    policy: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compares plaintext computation against homomorphically evaluated and decrypted score.
    Runs strictly in client memory.
    """
    threshold = policy.get("threshold", 0)

    plaintext_eligible = plaintext_score >= threshold
    encrypted_eligible = decrypted_score >= threshold

    plaintext_result = "Eligible" if plaintext_eligible else "Not Eligible"
    encrypted_result = "Eligible" if encrypted_eligible else "Not Eligible"

    score_match = plaintext_score == decrypted_score
    result_match = plaintext_result == encrypted_result

    is_overall_match = score_match and result_match
    match_status = "Match" if is_overall_match else "Mismatch"

    return {
        "plaintext_score": plaintext_score,
        "plaintext_result": plaintext_result,
        "encrypted_decrypted_score": decrypted_score,
        "encrypted_result": encrypted_result,
        "threshold": threshold,
        "score_match": score_match,
        "result_match": result_match,
        "match_status": match_status,
        "is_match": is_overall_match,
        "delta": abs(plaintext_score - decrypted_score),
    }
