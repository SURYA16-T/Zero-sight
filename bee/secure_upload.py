try:
    import magic
except ImportError:
    magic = None
import tempfile
import os

MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 MB — eligibility forms are tiny
ALLOWED_MIME = {
    "application/json": ".json",
    "text/plain": ".txt",
    "application/pdf": ".pdf",
}

def validate_upload(file_bytes: bytes) -> str:
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise ValueError("File exceeds maximum allowed size")

    if magic is None:
        return "application/octet-stream" # Fallback if libmagic is not installed

    detected = magic.from_buffer(file_bytes, mime=True)
    if detected not in ALLOWED_MIME:
        raise ValueError(f"Unsupported or spoofed file type: {detected}")

    return detected

def to_scratch_file(file_bytes: bytes, suffix: str) -> str:
    """Write to a private temp file that is deleted on close, never persisted."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.chmod(path, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(file_bytes)
    return path

def secure_delete(path: str):
    """Best-effort overwrite before unlink. Not guaranteed on SSD/journaled FS."""
    if not os.path.exists(path):
        return
    try:
        length = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(os.urandom(length))
            f.flush()
            os.fsync(f.fileno())
    finally:
        os.remove(path)
