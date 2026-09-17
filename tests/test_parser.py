import pytest
from bee.parser import (
    parse_json_content,
    parse_text_content,
    parse_pdf_content,
    parse_file,
    ParsingSecurityError,
)
from bee.config import MAX_FILE_SIZE_BYTES


def test_parse_valid_json():
    content = '{"income": 25000, "children": 3, "disability": 0, "senior": 1}'
    result = parse_json_content(content)
    assert result["income"] == 25000
    assert result["children"] == 3


def test_parse_json_malformed():
    content = '{"income": 25000, "children": }'
    with pytest.raises(ValueError, match="Malformed JSON syntax"):
        parse_json_content(content)


def test_parse_json_not_dict():
    content = '[1, 2, 3]'
    with pytest.raises(ValueError, match="root must be an object"):
        parse_json_content(content)


def test_parse_text_key_value():
    content = """
    Income: 18000
    Children = 2
    Disability: Yes
    Senior: No
    # This is a comment
    """
    result = parse_text_content(content)
    assert result["income"] == "18000"
    assert result["children"] == "2"
    assert result["disability"] == "Yes"
    assert result["senior"] == "No"


def test_parse_file_unsupported_format():
    with pytest.raises(ValueError, match="Unsupported file format"):
        parse_file("content", "exe")


def test_parse_size_limit_exceeded():
    huge_payload = b"x" * (MAX_FILE_SIZE_BYTES + 1024)
    with pytest.raises(ParsingSecurityError):
        parse_json_content(huge_payload)
