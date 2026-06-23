import pytest
from fastapi.testclient import TestClient
import oqs
from main import app

client = TestClient(app)

# --- SUCCESS TESTS ---

def test_pqc_handshake_flow_success():
    # Get server public key
    resp1 = client.post("/api/v1/auth/pqc-handshake")
    data = resp1.json()
    server_pub_key = bytes.fromhex(data["server_public_key_hex"])
    
    # Perform real encapsulation client-side
    with oqs.KeyEncapsulation("Kyber768") as client_kem:
        ciphertext, shared_secret = client_kem.encap_secret(server_pub_key)
    
    # Send real ciphertext to API
    payload = {
        "session_id": data["session_id"],
        "ciphertext_hex": ciphertext.hex()
    }
    resp2 = client.post("/api/v1/auth/pqc-complete", json=payload)
    
    # Expected 200 OK!
    assert resp2.status_code == 200

def test_verify_signature_success():
    alg_name = "ML-DSA-65"
    message = "Sensitive data"
    
    # 1. Signer generates keys and signs the message
    with oqs.Signature(alg_name) as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(message.encode('utf-8'))
        
    # 2. Send to API for verification
    payload = {
        "message": message,
        "public_key_hex": public_key.hex(),
        "signature_hex": signature.hex()
    }
    
    response = client.post("/api/v1/verify/document", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "success"


# --- FAILING TESTS | EDGE CASES ---

def test_handshake_invalid_ciphertext_length():
    """
    Ciphertext_hex length != 1088
    """
    # Setup session
    resp1 = client.post("/api/v1/auth/pqc-handshake")
    data = resp1.json()             # Data: ["server_public_key_hex"] & ["session_id"] 

    payload = {"session_id": data["session_id"], "ciphertext_hex": "deadbeef"}
    resp2 = client.post("/api/v1/auth/pqc-complete", json=payload)

    assert resp2.status_code == 400

def test_handshake_invalid_session_id():
    """
    Invalid session_id is injected
    """
    # Use a non-existent session ID (skips handshake/session route)
    payload = {"session_id": "fake-session-123", "ciphertext_hex": "0" * 200}
    resp2 = client.post("/api/v1/auth/pqc-complete", json=payload)

    assert resp2.status_code == 404

def test_handshake_non_hex_ciphertext():
    """
    When non-hexadecimal found in fromhex() pos 0.
    """
    # Send non-hex string
    resp1 = client.post("/api/v1/auth/pqc-handshake")
    data = resp1.json()
    payload = {"session_id": data["session_id"], "ciphertext_hex": "not-a-hex-string!!!"}
    resp2 = client.post("/api/v1/auth/pqc-complete", json=payload)

    assert resp2.status_code == 400

# def test_verify_signature_tampered():
#     """
#     When sending incorrect data
#     """
#     alg_name = "ML-DSA-65"
#     original_message = "Sensitive data"
#     tampered_message = "Tampered data"
    
#     with oqs.Signature(alg_name) as signer:
#         public_key = signer.generate_keypair()
#         signature = signer.sign(original_message.encode('utf-8'))
        
#     # We send the TAMPERED message, but the ORIGINAL signature
#     payload = {
#         "message": tampered_message, 
#         "public_key_hex": public_key.hex(),
#         "signature_hex": signature.hex()
#     }
    
#     response = client.post("/api/v1/verify/document", json=payload)

#     if response.status_code != 401:
#         print(f"DEBUG: Unexpected Status Code: {response.status_code}")
#         print(f"DEBUG: Response Body: {response.json()}")
    
#     # If this fails, it means response.status_code is 200, not 401
#     assert response.status_code == 401
