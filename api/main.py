import hmac
import os
import time
from typing import Dict

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address

from bee.evaluator import evaluate_encrypted
from bee.policy import load_policy
from phe import paillier

app = FastAPI(title="ZeroSight Evaluator API")
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# The API key must be set in the environment
API_KEY = os.environ.get("ZEROSIGHT_EVALUATOR_API_KEY", "your_secure_api_key_here")
api_key_header = APIKeyHeader(name="X-API-Key")

MAX_CLOCK_SKEW_SECONDS = 60
_seen_nonces: Dict[str, float] = {}

def verify_api_key(key: str = Depends(api_key_header)):
    if not hmac.compare_digest(key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")

class EvaluateRequest(BaseModel):
    policy_id: str = Field(..., max_length=64)
    public_key_n: str = Field(..., max_length=2048)
    encrypted_fields: Dict[str, str] = Field(...)
    nonce: str = Field(..., min_length=16, max_length=64)
    timestamp: int = Field(...)

    @field_validator("encrypted_fields")
    @classmethod
    def bound_field_sizes(cls, v):
        for name, ciphertext in v.items():
            if len(ciphertext) > 4096:
                raise ValueError(f"Ciphertext for {name} exceeds expected size")
        return v

def verify_freshness(payload: EvaluateRequest):
    now = int(time.time())
    if abs(now - payload.timestamp) > MAX_CLOCK_SKEW_SECONDS:
        raise HTTPException(status_code=401, detail="Request expired")
    if payload.nonce in _seen_nonces:
        raise HTTPException(status_code=401, detail="Replayed request")
    _seen_nonces[payload.nonce] = now
    
    # Prune stale nonces
    for n, ts in list(_seen_nonces.items()):
        if now - ts > MAX_CLOCK_SKEW_SECONDS:
            del _seen_nonces[n]

@app.post("/evaluate")
@limiter.limit("10/minute")
def evaluate(request: Request, payload: EvaluateRequest, _: None = Depends(verify_api_key)):
    verify_freshness(payload)
    
    try:
        policy = load_policy(payload.policy_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Policy not found")

    public_key = paillier.PaillierPublicKey(n=int(payload.public_key_n))
    
    # Deserialize encrypted fields
    deserialized_fields = {}
    for name, ciphertext in payload.encrypted_fields.items():
        deserialized_fields[name] = paillier.EncryptedNumber(public_key, int(ciphertext))

    # Evaluate
    try:
        encrypted_score = evaluate_encrypted(deserialized_fields, public_key, policy)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "encrypted_score": str(encrypted_score.ciphertext()),
        "policy_hash": policy.get("_hash"),
        "status": "success"
    }
