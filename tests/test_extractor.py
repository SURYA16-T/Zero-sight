import pytest
from bee.extractor import (
    extract_and_normalize_fields,
    normalize_binary_value,
    normalize_numeric_value,
)


def test_normalize_binary_value():
    assert normalize_binary_value("yes") == 1
    assert normalize_binary_value("TRUE") == 1
    assert normalize_binary_value(1) == 1
    assert normalize_binary_value("no") == 0
    assert normalize_binary_value("FALSE") == 0
    assert normalize_binary_value(0) == 0
    assert normalize_binary_value("unknown") == 0


def test_normalize_numeric_value():
    assert normalize_numeric_value("$18,000") == 18000
    assert normalize_numeric_value("25000 USD") == 25000
    assert normalize_numeric_value(2.0) == 2
    assert normalize_numeric_value("invalid", default=99) == 99


def test_extract_and_normalize_aliases():
    raw = {
        "Annual Income": "$24,500",
        "Number_of_Children": "3",
        "is_disabled": "Yes",
        "Senior_Citizen": "False",
        "Monthly Rent": "1200",
    }
    extracted = extract_and_normalize_fields(raw)
    assert extracted["income"] == 24500
    assert extracted["children"] == 3
    assert extracted["disability"] == 1
    assert extracted["senior"] == 0
    assert extracted["rent"] == 1200
