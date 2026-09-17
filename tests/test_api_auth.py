import time
import pytest
from fastapi.testclient import TestClient
from api.main import app, API_KEY
from phe import paillier

client = TestClient(app)

def test_evaluate_missing_api_key():
    response = client.post("/evaluate", json={})
    assert response.status_code in (401, 403) # Missing header (401 in modern FastAPI, 403 in legacy)

def test_evaluate_invalid_api_key():
    response = client.post(
        "/evaluate",
        headers={"X-API-Key": "wrong_key"},
        json={}
    )
    assert response.status_code == 401

def test_evaluate_validation_error():
    response = client.post(
        "/evaluate",
        headers={"X-API-Key": API_KEY},
        json={} # Missing required fields
    )
    assert response.status_code == 422

def test_evaluate_invalid_timestamp():
    response = client.post(
        "/evaluate",
        headers={"X-API-Key": API_KEY},
        json={
            "policy_id": "community_welfare_v1",
            "public_key_n": "12345",
            "encrypted_fields": {},
            "nonce": "1234567890abcdef1234567890abcdef",
            "timestamp": int(time.time()) - 100 # Expired
        }
    )
    assert response.status_code == 401
    assert "Request expired" in response.json()["detail"]

def test_evaluate_replay_attack():
    payload = {
        "policy_id": "community_welfare_v1",
        "public_key_n": "12345",
        "encrypted_fields": {},
        "nonce": "1234567890abcdef1234567890abcdef",
        "timestamp": int(time.time())
    }
    
    # First request should fail because policy not found or keys are dummy, but it should pass freshness
    response1 = client.post(
        "/evaluate",
        headers={"X-API-Key": API_KEY},
        json=payload
    )
    # The actual failure will be 404 because community_welfare_v1 policy might not exist in test env,
    # or some other error, but it won't be 401 Replayed request
    
    # Second request with same nonce
    response2 = client.post(
        "/evaluate",
        headers={"X-API-Key": API_KEY},
        json=payload
    )
    assert response2.status_code == 401
    assert "Replayed request" in response2.json()["detail"]
