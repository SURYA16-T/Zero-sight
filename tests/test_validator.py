import pytest
from bee.validator import validate_extracted_data


@pytest.fixture
def sample_policy():
    return {
        "required_fields": ["income", "children", "disability", "senior"],
        "threshold": 30000,
    }


def test_validation_success(sample_policy):
    data = {
        "income": 18000,
        "children": 2,
        "disability": 0,
        "senior": 0,
    }
    errors = validate_extracted_data(data, sample_policy)
    assert len(errors) == 0


def test_validation_missing_required(sample_policy):
    data = {
        "children": 2,
        "disability": 0,
        "senior": 0,
    }
    errors = validate_extracted_data(data, sample_policy)
    assert any("income" in err for err in errors)


def test_validation_negative_income(sample_policy):
    data = {
        "income": -5000,
        "children": 2,
        "disability": 0,
        "senior": 0,
    }
    errors = validate_extracted_data(data, sample_policy)
    assert any("Income cannot be negative" in err for err in errors)


def test_validation_excessive_children(sample_policy):
    data = {
        "income": 15000,
        "children": 50,
        "disability": 0,
        "senior": 0,
    }
    errors = validate_extracted_data(data, sample_policy)
    assert any("Children must be between" in err for err in errors)


def test_validation_invalid_binary_flag(sample_policy):
    data = {
        "income": 15000,
        "children": 2,
        "disability": 5,
        "senior": 0,
    }
    errors = validate_extracted_data(data, sample_policy)
    assert any("Disability status must be binary" in err for err in errors)
