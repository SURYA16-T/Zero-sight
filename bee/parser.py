"""
Defensive file parser for ZeroSight.
Supports JSON, TXT, and PDF with anti-DoS and memory leak prevention.
All operations execute in-memory; files are never persisted to disk.
"""

import io
import re
import json
from typing import Dict, Any, Union
import pdfplumber

from bee.config import (
    MAX_FILE_SIZE_BYTES,
    MAX_TEXT_CHARACTERS,
    MAX_PDF_PAGES,
    FIELD_ALIASES,
)


class ParsingSecurityError(Exception):
    """Raised when file parsing exceeds security thresholds or triggers defenses."""
    pass


def parse_json_content(content: Union[str, bytes]) -> Dict[str, Any]:
    """
    Safely parses JSON payload from string or bytes.
    Enforces size limits and dictionary output.
    """
    if isinstance(content, bytes):
        if len(content) > MAX_FILE_SIZE_BYTES:
            raise ParsingSecurityError(f"JSON payload exceeds max allowed size ({MAX_FILE_SIZE_BYTES} bytes)")
        text = content.decode("utf-8", errors="replace")
    else:
        if len(content.encode("utf-8")) > MAX_FILE_SIZE_BYTES:
            raise ParsingSecurityError(f"JSON payload exceeds max allowed size ({MAX_FILE_SIZE_BYTES} bytes)")
        text = content

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Malformed JSON syntax: {e}")

    if not isinstance(data, dict):
        raise ValueError("JSON payload root must be an object/dictionary")

    return data


def parse_text_content(content: Union[str, bytes]) -> Dict[str, Any]:
    """
    Safely parses plain text documents using linear-time bounded regexes.
    Supports both key-value pairs (key: value or key=value).
    """
    if isinstance(content, bytes):
        if len(content) > MAX_FILE_SIZE_BYTES:
            raise ParsingSecurityError(f"Text content exceeds max size ({MAX_FILE_SIZE_BYTES} bytes)")
        text = content.decode("utf-8", errors="replace")
    else:
        text = content

    if len(text) > MAX_TEXT_CHARACTERS:
        text = text[:MAX_TEXT_CHARACTERS]

    extracted = {}

    # Extract line-by-line key-value pairs
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        match = re.match(r"^([^:=]+)\s*[:=]\s*(.+)$", line)
        if match:
            raw_key = match.group(1).strip().lower().replace(" ", "_")
            raw_val = match.group(2).strip()

            # Remove trailing comments or units (e.g. "18000 USD" -> "18000")
            val_match = re.match(r"^([^\s#]+)", raw_val)
            if val_match:
                extracted[raw_key] = val_match.group(1)

    return extracted


def parse_pdf_content(content: bytes) -> Dict[str, Any]:
    """
    Safely parses PDF byte stream in-memory.
    Imposes strict page limits and PDF-bomb mitigations.
    """
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise ParsingSecurityError(f"PDF document exceeds max size ({MAX_FILE_SIZE_BYTES} bytes)")

    accumulated_text = []
    stream = io.BytesIO(content)

    try:
        with pdfplumber.open(stream) as pdf:
            pages_to_read = min(len(pdf.pages), MAX_PDF_PAGES)
            for page_idx in range(pages_to_read):
                page = pdf.pages[page_idx]
                page_text = page.extract_text()
                if page_text:
                    accumulated_text.append(page_text)
    except Exception as e:
        raise ValueError(f"Could not read PDF document: {e}")

    full_text = "\n".join(accumulated_text)
    return parse_text_content(full_text)


def parse_file(file_content: Union[str, bytes], file_type: str) -> Dict[str, Any]:
    """
    Unified entrypoint for file parsing based on extension or MIME type.
    """
    file_type = file_type.lower().strip().lstrip(".")

    if isinstance(file_content, bytes):
        from bee.secure_upload import validate_upload
        validate_upload(file_content)

    if file_type in ("json",):
        return parse_json_content(file_content)
    elif file_type in ("txt", "text"):
        return parse_text_content(file_content)
    elif file_type in ("pdf",):
        if not isinstance(file_content, bytes):
            raise TypeError("PDF parsing requires raw bytes")
        return parse_pdf_content(file_content)
    else:
        raise ValueError(f"Unsupported file format: '.{file_type}'. Supported: json, txt, pdf")
