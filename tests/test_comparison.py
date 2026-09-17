import pytest
from bee.comparison import compare_results


@pytest.fixture
def dummy_policy():
    return {"threshold": 30000}


def test_comparison_match_eligible(dummy_policy):
    res = compare_results(38000, 38000, dummy_policy)
    assert res["is_match"] is True
    assert res["match_status"] == "Match"
    assert res["plaintext_result"] == "Eligible"
    assert res["encrypted_result"] == "Eligible"


def test_comparison_match_not_eligible(dummy_policy):
    res = compare_results(8000, 8000, dummy_policy)
    assert res["is_match"] is True
    assert res["plaintext_result"] == "Not Eligible"
    assert res["encrypted_result"] == "Not Eligible"


def test_comparison_mismatch(dummy_policy):
    res = compare_results(35000, 25000, dummy_policy)
    assert res["is_match"] is False
    assert res["match_status"] == "Mismatch"
    assert res["plaintext_result"] == "Eligible"
    assert res["encrypted_result"] == "Not Eligible"
