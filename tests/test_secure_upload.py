import pytest
from bee.secure_upload import validate_upload, MAX_UPLOAD_BYTES, ALLOWED_MIME

def test_validate_upload_size():
    large_payload = b"0" * (MAX_UPLOAD_BYTES + 1)
    with pytest.raises(ValueError, match="File exceeds maximum allowed size"):
        validate_upload(large_payload)

def test_validate_upload_mime():
    from bee.secure_upload import magic
    if magic is None:
        pytest.skip("libmagic not installed")

    # Valid JSON
    valid_json = b'{"income": 1000}'
    mime = validate_upload(valid_json)
    assert mime == "application/json" or mime == "text/plain" # magic sometimes detects json as plain text depending on libmagic version

    # Invalid MIME (e.g. an image)
    # Magic bytes for GIF
    invalid_payload = b'GIF89a...'
    with pytest.raises(ValueError, match="Unsupported or spoofed file type"):
        validate_upload(invalid_payload)
