"""
ZeroSight Security Configuration and System Parameters.
Defines strict limits to prevent DoS attacks, memory overflows, and parser exploits.
"""

from typing import Dict, List, Any

# Cryptographic parameters
DEFAULT_KEY_SIZE: int = 2048  # NIST SP 800-57 recommended minimum for Paillier
FALLBACK_KEY_SIZE: int = 1024  # For fast demo mode only

# File Upload & Parsing Limits (Anti-DoS)
MAX_FILE_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB maximum file upload
MAX_TEXT_CHARACTERS: int = 100_000         # 100k characters max for regex parsing
MAX_PDF_PAGES: int = 5                     # Max 5 pages for PDF extraction

# Numerical & Field Domain Invariants (Prevent modulo wrap-around)
MAX_INCOME: int = 1_000_000_000            # Max 1 Billion
MIN_INCOME: int = 0
MAX_CHILDREN: int = 20
MIN_CHILDREN: int = 0
MAX_RENT: int = 1_000_000
MIN_RENT: int = 0

# Field alias mapping for extraction
FIELD_ALIASES: Dict[str, List[str]] = {
    "income": [
        "income",
        "annual_income",
        "annual income",
        "yearly_income",
        "salary",
        "gross_income",
        "total_income",
    ],
    "children": [
        "children",
        "number_of_children",
        "num_children",
        "dependents",
        "dependent_children",
        "kids",
    ],
    "disability": [
        "disability",
        "disability_status",
        "disabled",
        "is_disabled",
        "has_disability",
    ],
    "senior": [
        "senior",
        "senior_citizen",
        "elderly",
        "is_senior",
        "is_senior_citizen",
    ],
    "rent": [
        "rent",
        "monthly_rent",
        "annual_rent",
        "housing_cost",
    ],
    "unemployment_status": [
        "unemployment_status",
        "unemployed",
        "is_unemployed",
        "jobless",
    ],
}

# Truthy / Falsy string representations for binary fields
TRUTHY_VALUES = {"1", "yes", "true", "y", "t"}
FALSY_VALUES = {"0", "no", "false", "n", "f"}
