# Zero Sight — Blind Eligibility Engine

This document extends `bee_implementation_.md`. It does not replace the original
functional plan — it hardens it so the project can be defended as a genuine
security engineering deliverable, not just a crypto demo.

---

## 1. Executive Summary

The base plan gets the *privacy* model right: sensitive fields never leave the
user's machine in plaintext, and the evaluator only ever touches Paillier
ciphertexts. What it's missing is everything *around* the crypto — key custody,
input trust boundaries, transport security, and operational hygiene. Those are
exactly the things a CSE/security reviewer will probe first, because a correct
cryptographic primitive wrapped in a sloppy system is still an insecure system.

This addendum adds:

```text
1. A formal threat model (STRIDE)
2. A hardened, layered architecture diagram
3. Key management (encrypted-at-rest private key)
4. Secure file ingestion (size caps, MIME verification, PDF sanitization)
5. Evaluator API hardening (auth, rate limiting, schema validation)
6. Secrets and configuration management
7. Privacy-safe audit logging
8. Dependency / supply-chain security
9. CI security gates
10. Deployment hardening
11. Viva / presentation talking points
```

---

## 2. Threat Model (STRIDE)

| Threat | Where it applies | Mitigation |
| --- | --- | --- |
| **Spoofing** | Evaluator API caller impersonates a legitimate client | API key / mTLS on `/evaluate`, Section 6 |
| **Tampering** | Encrypted payload or policy file modified in transit | TLS everywhere, policy hash verification (already in plan, Section 24) |
| **Repudiation** | No record of which policy version produced which result | Signed audit log entries, Section 8 |
| **Information Disclosure** | Uploaded file, private key, or logs leak plaintext PII | Encrypted key at rest, no-plaintext logging, in-memory-only temp files, Section 4/5/8 |
| **Denial of Service** | Large/malformed files or API floods exhaust the server | File size caps, rate limiting, Section 5/6 |
| **Elevation of Privilege** | Malicious PDF exploits parser to execute code or read disk | Sandboxed/size-limited parsing, no execution of embedded content, Section 5 |

State explicitly in your report that **the evaluator is assumed honest-but-curious**:
it correctly runs the policy but must never be able to recover plaintext values.
Paillier alone does not prevent a *malicious* evaluator from returning a bogus
encrypted score — if you want to defend against that too, say so and note it as
future work (verifiable computation / zero-knowledge proofs), rather than silently
ignoring it. This kind of scoped honesty is what separates a real security
project from a checkbox one.

---

## 3. Hardened Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│  CLIENT (User's machine / browser)                               │
│                                                                   │
│  Upload → Parse → Preview → Select fields → Validate             │
│                        │                                          │
│                        ▼                                          │
│   Paillier keypair generated locally                              │
│   Private key encrypted with user passphrase (PBKDF2 + AES-GCM)   │
│   Encrypted at rest, never transmitted                            │
│                        │                                          │
│                        ▼                                          │
│   Selected fields encrypted (public key) ──────────┐              │
│   Plaintext fields discarded from memory ASAP        │            │
└──────────────────────────────────────────────────────┼────────────┘
                                                         │  TLS 1.2+
                                                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  EVALUATOR (Server / FastAPI)                                    │
│                                                                   │
│   Reverse proxy (nginx/Caddy) — TLS termination, security headers │
│                        │                                          │
│                        ▼                                          │
│   Auth middleware — API key or mTLS                               │
│                        │                                          │
│                        ▼                                          │
│   Rate limiter (per-IP / per-key)                                 │
│                        │                                          │
│                        ▼                                          │
│   Pydantic schema validation (reject malformed ciphertexts)       │
│                        │                                          │
│                        ▼                                          │
│   Homomorphic evaluation (Paillier ops only, no decryption)       │
│                        │                                          │
│                        ▼                                          │
│   Audit log: policy_hash, request_id, timestamp, byte-size        │
│   — NEVER logs field values, ciphertext contents, or IP+PII       │
└──────────────────────────────────────────────────────┼────────────┘
                                                         │  TLS 1.2+
                                                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  CLIENT — decrypt encrypted_score with private key                │
│         — compare vs local plaintext calc (demo only)             │
│         — private key decrypted transiently, wiped after use      │
└─────────────────────────────────────────────────────────────────┘
```

Key principle to state explicitly in your report: **trust boundaries are drawn
at the network edge, not at the module boundary.** Everything left of the TLS
line is trusted (it's the user's own machine); everything right of it is
untrusted input and must be validated as such.

---

## 4. Key Management

Don't store the Paillier private key as a bare pickled object. Encrypt it with
a user-supplied passphrase before writing it anywhere (including Streamlit's
session state serialized to disk, if that ever happens).

```python
# bee/key_management.py
import os
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from phe import paillier

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,  # OWASP 2023+ recommendation for PBKDF2-SHA256
    )
    return kdf.derive(passphrase.encode())

def export_encrypted_private_key(private_key: paillier.PaillierPrivateKey,
                                  passphrase: str) -> dict:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)

    payload = json.dumps({
        "p": str(private_key.p),
        "q": str(private_key.q),
    }).encode()

    ciphertext = aesgcm.encrypt(nonce, payload, None)

    return {
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "kdf": "pbkdf2-sha256-600000",
    }

def load_encrypted_private_key(blob: dict, passphrase: str,
                                public_key: paillier.PaillierPublicKey
                                ) -> paillier.PaillierPrivateKey:
    salt = bytes.fromhex(blob["salt"])
    nonce = bytes.fromhex(blob["nonce"])
    ciphertext = bytes.fromhex(blob["ciphertext"])
    key = _derive_key(passphrase, salt)

    aesgcm = AESGCM(key)
    payload = json.loads(aesgcm.decrypt(nonce, ciphertext, None))

    return paillier.PaillierPrivateKey(public_key, int(payload["p"]), int(payload["q"]))
```

Also add:

```text
- Minimum key size policy: 1024-bit only for local timing benchmarks;
  ANY key that leaves the demo context uses 2048-bit minimum.
- Overflow guard: Paillier arithmetic is mod n. Before trusting a decrypted
  score, assert it falls in an expected sane range (e.g. -1,000,000 to
  1,000,000) to catch silent modular wraparound from a corrupted ciphertext.
- Wipe the plaintext private key object from memory after use where the
  runtime allows it (del + gc.collect()); note in your report that Python
  cannot guarantee secure memory erasure — this is a documented limitation,
  not a gap you hide.
```

---

## 5. Secure File Ingestion

Never trust the file extension. Cap size before parsing. Sanitize PDFs.

```python
# bee/secure_upload.py
import magic  # python-magic
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
    """Best-effort overwrite before unlink. Not guaranteed on SSD/journaled FS —
    document this limitation rather than claiming true secure erasure."""
    try:
        length = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(os.urandom(length))
            f.flush()
            os.fsync(f.fileno())
    finally:
        os.remove(path)
```

For PDFs specifically, disable anything beyond plain text extraction:

```text
- Use pdfplumber ONLY for text extraction — never render/execute embedded
  JavaScript, forms, or launch actions.
- Reject PDFs with more than N pages (e.g. 20) — cheap decompression-bomb guard.
- Run extraction inside a timeout (signal.alarm or a subprocess with a hard
  wall-clock limit) so a pathological PDF can't hang the worker.
- If the deployed version handles PDFs from untrusted public users, consider
  an isolated sandbox (subprocess with restricted syscalls, or a disposable
  container) — call this out as a "production hardening" item even if the
  MVP skips it.
```

---

## 6. Evaluator API Hardening (Section 24, Feature 5)

The plan's `/evaluate` endpoint as written has no auth, no rate limit, and no
schema validation. Harden it:

```python
# api/main.py
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address
import os

app = FastAPI()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

API_KEY = os.environ["BEE_EVALUATOR_API_KEY"]  # never hardcode, Section 7
api_key_header = APIKeyHeader(name="X-API-Key")

def verify_api_key(key: str = Depends(api_key_header)):
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

class EvaluateRequest(BaseModel):
    policy_id: str = Field(..., max_length=64)
    public_key_n: str = Field(..., max_length=2048)  # hex/decimal string, bounded
    encrypted_fields: dict[str, str] = Field(..., max_length=32)

    @field_validator("encrypted_fields")
    @classmethod
    def bound_field_sizes(cls, v):
        for name, ciphertext in v.items():
            if len(ciphertext) > 4096:
                raise ValueError(f"Ciphertext for {name} exceeds expected size")
        return v

@app.post("/evaluate")
@limiter.limit("10/minute")
def evaluate(request: Request, payload: EvaluateRequest,
             _: None = Depends(verify_api_key)):
    # ... reconstruct public key, run evaluate_encrypted(), return result
    # never log payload.encrypted_fields contents
    ...
```

```text
Also required in front of this service (usually via reverse proxy, not app code):

- TLS 1.2+ only, strong cipher suite, HSTS header
- Security headers: X-Content-Type-Options: nosniff,
  X-Frame-Options: DENY, Content-Security-Policy
- Request body size limit at the proxy layer (defense in depth with Pydantic)
- CORS locked to known origins only, not "*"
```

---

## 7. Secrets & Configuration Management

```text
- No secrets, API keys, or key material in source control — ever.
- Use environment variables loaded via python-dotenv locally; a proper
  secrets manager (AWS Secrets Manager / HashiCorp Vault / even a
  git-ignored .env for a college demo) in any hosted version.
- Add .env to .gitignore and ship .env.example with placeholder values.
- Different config per environment (dev/demo vs "hosted" mode described
  in Section 5's Important Privacy Note).
```

---

## 8. Privacy-Safe Audit Logging (fills in the unspecified `bee/audit.py`)

```python
# bee/audit.py
import hashlib
import json
import time
import uuid

def log_evaluation_event(policy_hash: str, ciphertext_byte_size: int,
                          result_present: bool, log_path: str = "audit.log"):
    """
    Logs ONLY metadata needed for accountability. Never logs:
    - field values (plaintext or decrypted)
    - ciphertext contents
    - raw uploaded file contents
    - IP address tied to a specific eligibility outcome
    """
    entry = {
        "event_id": str(uuid.uuid4()),
        "timestamp": time.time(),
        "policy_hash": policy_hash,
        "payload_size_bytes": ciphertext_byte_size,
        "produced_result": result_present,
    }
    entry["entry_hash"] = hashlib.sha256(
        json.dumps(entry, sort_keys=True).encode()
    ).hexdigest()

    with open(log_path, "a") as f:
        f.write(json.dumps(entry) + "\n")
```

Chain each `entry_hash` with the previous one (like a mini hash-chain / simple
Merkle-style log) if you want tamper-evidence to be a demo talking point —
it's a cheap addition that reads very well in a CSE viva.

---

## 9. Dependency & Supply Chain Security

```text
requirements.txt should be PINNED, not loose:

  streamlit==1.38.0
  phe==1.5.0
  pdfplumber==0.11.4
  pytest==8.3.3
  python-magic==0.4.27
  cryptography==43.0.1
  fastapi==0.115.0
  slowapi==0.1.9
  python-dotenv==1.0.1

Run in CI:
  pip-audit                 # known-CVE scan of installed packages
  bandit -r bee/            # static security analysis of your own code
```

---

## 10. CI Security Gate (example GitHub Actions)

```yaml
# .github/workflows/security.yml
name: Security Checks
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt
      - run: pip install pip-audit bandit
      - run: pip-audit
      - run: bandit -r bee/ -ll
      - run: pytest tests/
```

Having a green security-gate badge on the repo is a strong, low-effort
credibility signal for a CSE-stream CSP submission.

---

## 11. Deployment Hardening (if you host beyond `streamlit run` locally)

```text
- Run as a non-root user inside the container.
- Read-only root filesystem; only the temp-upload directory is writable,
  and it's tmpfs (in-memory, never touches disk).
- No inbound ports except 443 (TLS) exposed publicly; app port stays
  internal behind the reverse proxy.
- Set resource limits (CPU/memory) on the container to blunt DoS via
  oversized encryption/evaluation requests.
- Revisit Section 5's "Important Privacy Note": if hosted remotely, parsing
  and encryption MUST move to the browser (WASM or JS Paillier lib) — the
  current plan explicitly acknowledges this but defers it. State clearly in
  your report whether your submitted build is "local-only, privacy holds"
  or "hosted, privacy contingent on future browser-side crypto work."
```

---

## 12. Updated Folder Structure

```text
BlindEligibilityEngine/
│
├── app.py
├── main_cli.py
├── .env.example
├── .gitignore
│
├── bee/
│   ├── parser.py
│   ├── extractor.py
│   ├── validator.py
│   ├── crypto_utils.py
│   ├── key_management.py      # NEW — Section 4
│   ├── secure_upload.py        # NEW — Section 5
│   ├── policy.py
│   ├── evaluator.py
│   ├── comparison.py
│   ├── serializer.py
│   └── audit.py                # NOW implemented — Section 8
│
├── api/
│   └── main.py                 # NEW — hardened evaluator, Section 6
│
├── .github/workflows/
│   └── security.yml            # NEW — Section 10
│
├── policies/
├── sample_files/
├── tests/
│   ├── ...existing...
│   ├── test_key_management.py  # NEW
│   ├── test_secure_upload.py   # NEW
│   └── test_api_auth.py        # NEW
│
├── requirements.txt            # now pinned
├── SECURITY_ARCHITECTURE.md    # this file
└── README.md
```

---

## 13. Viva / Presentation Talking Points (CSE stream)

When you present this as a CSP, lead with the design decisions, not just the
crypto:

```text
1. Why Paillier (partial homomorphism, additive) fits an additive scoring
   policy — and its explicit limitation (no multiplication of two
   ciphertexts, so any future "income × rate" style policy needs a
   different scheme, e.g. CKKS/BFV or a hybrid approach).
2. Why "honest-but-curious evaluator" is the stated trust assumption,
   and what attack it does NOT defend against (a malicious evaluator
   returning a fabricated score) — and how that could be closed later.
3. Defense-in-depth: even though HE is the headline feature, the system
   is not secure without TLS, auth, rate limiting, and safe file handling
   around it — that's the point of this whole addendum.
4. The explicit gap between "local demo" privacy guarantees and "hosted"
   privacy guarantees, and what would need to change (browser-side crypto)
   to close it.
```

That framing — strong primitive, honest trust model, named residual risks —
is what typically separates a good CSP grade from an average one.
