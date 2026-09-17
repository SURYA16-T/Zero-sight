"""
Field extraction and normalization module for ZeroSight.
Maps arbitrary document aliases and formats into standard numerical fields.
"""

import re
from typing import Dict, Any, Union
from bee.config import FIELD_ALIASES, TRUTHY_VALUES, FALSY_VALUES


def normalize_binary_value(val: Any) -> int:
    """
    Normalizes boolean, affirmative strings, or numbers into binary integer (0 or 1).
    """
    if isinstance(val, bool):
        return 1 if val else 0

    if isinstance(val, (int, float)):
        return 1 if val != 0 else 0

    str_val = str(val).strip().lower()
    if str_val in TRUTHY_VALUES:
        return 1
    elif str_val in FALSY_VALUES:
        return 0
    else:
        # If unable to parse, return 0 by default
        return 0


def normalize_numeric_value(val: Any, default: int = 0) -> int:
    """
    Cleans strings with currency symbols, suffixes, or commas and converts to standard integer.
    E.g. "$18,000" -> 18000, "25000 USD" -> 25000, "2.0" -> 2.
    """
    if isinstance(val, (int, float)):
        return int(val)

    str_val = str(val).strip()
    cleaned = str_val.replace(",", "")
    match = re.search(r"[-+]?\d+(?:\.\d+)?", cleaned)
    if match:
        num_str = match.group(0)
        try:
            if "." in num_str:
                return int(float(num_str))
            return int(num_str)
        except (ValueError, TypeError):
            return default
    return default



def extract_and_normalize_fields(raw_data: Dict[str, Any]) -> Dict[str, int]:
    """
    Scans raw dictionary keys against alias catalog and normalizes values.
    Returns normalized dictionary of standardized field keys.
    """
    normalized = {}

    # Lowercase all input keys and replace spaces/hyphens with underscores
    cleaned_input = {}
    for k, v in raw_data.items():
        cleaned_key = str(k).strip().lower().replace(" ", "_").replace("-", "_")
        cleaned_input[cleaned_key] = v

    # Match each canonical field against its defined aliases
    for canonical_field, aliases in FIELD_ALIASES.items():
        found_value = None
        for alias in aliases:
            cleaned_alias = alias.lower().replace(" ", "_").replace("-", "_")
            if cleaned_alias in cleaned_input:
                found_value = cleaned_input[cleaned_alias]
                break

        if found_value is not None:
            if canonical_field in ("disability", "senior", "unemployment_status"):
                normalized[canonical_field] = normalize_binary_value(found_value)
            elif canonical_field in ("income", "children", "rent"):
                normalized[canonical_field] = normalize_numeric_value(found_value)

    return normalized
