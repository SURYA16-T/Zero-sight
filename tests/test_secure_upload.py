import pytest
from bee.secure_upload import validate_upload, MAX_UPLOAD_BYTES, ALLOWED_MIME

def test_validate_upload_size():
    large_payload = b"0" * (MAX_UPLOAD_BYTES + 1)
    with pytest.raises(ValueError, match="File exceeds maximum allowed size"):
        validate_upload(large_payload)

def test_validate_upload_mime(monkeypatch):
    from unittest.mock import MagicMock
    import bee.secure_upload
    
    mock_magic = MagicMock()
    
    # We create a side effect to simulate magic.from_buffer
    def mock_from_buffer(buffer, mime=True):
        if buffer.startswith(b'{"income":'):
            return "application/json"
        if buffer.startswith(b'GIF89a'):
            return "image/gif"
        return "application/octet-stream"
        
    mock_magic.from_buffer = mock_from_buffer
    
    # Override magic in the module
    monkeypatch.setattr(bee.secure_upload, "magic", mock_magic)

    # Valid JSON
    valid_json = b'{"income": 1000}'
    mime = validate_upload(valid_json)
    assert mime == "application/json"

    # Invalid MIME (e.g. an image)
    invalid_payload = b'GIF89a...'
    with pytest.raises(ValueError, match="Unsupported or spoofed file type"):
        validate_upload(invalid_payload)
