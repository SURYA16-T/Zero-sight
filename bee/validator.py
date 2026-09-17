"""
Validation module for ZeroSight.
Enforces strict range invariants, required field presence, and data integrity checks.
"""

from typing import Dict, List, Any
from bee.config import (
    MIN_INCOME,
    MAX_INCOME,
    MIN_CHILDREN,
    MAX_CHILDREN,
    MIN_RENT,
    MAX_RENT,
)


def validate_extracted_data(
    data: Dict[str, Any],
    policy: Dict[str, Any],
) -> List[str]:
    """
    Validates applicant data against policy rules and cryptographic domain invariants.
    Returns a list of human-readable error messages. If valid, the list is empty.
    """
    errors: List[str] = []

    required_fields = policy.get("required_fields", [])
    for field in required_fields:
        if field not in data:
            errors.append(f"Required field missing: '{field}'")

    # Specific field checks if present
    if "income" in data:
        income = data["income"]
        if not isinstance(income, int):
            errors.append("Income must be an integer")
        elif income < MIN_INCOME:
            errors.append(f"Income cannot be negative (got {income})")
        elif income > MAX_INCOME:
            errors.append(f"Income exceeds maximum supported threshold ({MAX_INCOME})")

    if "children" in data:
        children = data["children"]
        if not isinstance(children, int):
            errors.append("Children must be an integer")
        elif not (MIN_CHILDREN <= children <= MAX_CHILDREN):
            errors.append(f"Children must be between {MIN_CHILDREN} and {MAX_CHILDREN} (got {children})")

    if "disability" in data:
        disability = data["disability"]
        if disability not in (0, 1):
            errors.append(f"Disability status must be binary 0 or 1 (got {disability})")

    if "senior" in data:
        senior = data["senior"]
        if senior not in (0, 1):
            errors.append(f"Senior citizen status must be binary 0 or 1 (got {senior})")

    if "rent" in data:
        rent = data["rent"]
        if not isinstance(rent, int) or rent < MIN_RENT or rent > MAX_RENT:
            errors.append(f"Rent must be an integer between {MIN_RENT} and {MAX_RENT}")

    if "unemployment_status" in data:
        unemp = data["unemployment_status"]
        if unemp not in (0, 1):
            errors.append(f"Unemployment status must be binary 0 or 1 (got {unemp})")

    return errors
