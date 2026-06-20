from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import oqs
import secrets
import re

app = FastAPI(title="Post-Quantum Secure Vault API", version="1.0.0")

# Could be stored in a seperate variables file
Kyber768_Length = 1088

# In-memory session storage (In production, use a secure Redis instance)
# Redis: Remote Dictionary Server
SESSIONS = {}

# --- Pydantic Schemas: Think of TypeScripts 'Types' or an Interface ---
class HandshakeInitResponse(BaseModel):
    server_public_key_hex: str
    session_id: str

class HandshakeCompleteRequest(BaseModel):
    session_id: str
    ciphertext_hex: str

class HandshakeCompleteResponse(BaseModel):
    status: str

class VerifySignatureRequest(BaseModel):
    message: str
    public_key_hex: str
    signature_hex: str



# --- Endpoints ---

@app.post("/api/v1/auth/pqc-handshake", response_model=HandshakeInitResponse)
def init_pqc_handshake():
    """Server generates a Kyber768 key pair for quick key exchange."""
    kem_alg = "Kyber768"
    try:
        with oqs.KeyEncapsulation(kem_alg) as server_kem:
            public_key = server_kem.generate_keypair()
            session_id = secrets.token_urlsafe(32)
            
            # Persist the private key context securely for the second half of the handshake
            # Storing the instantiated object or serialization depending on system design
            SESSIONS[session_id] = {
                "kem_object": server_kem,
                "public_key": public_key
            }
            
            # Response data object from server. JSON: ["server_public_key_hex"] & ["session_id"] 
            return HandshakeInitResponse(
                server_public_key_hex=public_key.hex(),
                session_id=session_id
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"KEM Initialization Failed: {str(e)}")


@app.post("/api/v1/auth/pqc-complete", response_model=HandshakeCompleteResponse)
def complete_pqc_handshake(payload: HandshakeCompleteRequest):
    # Validate Session Existence, get kem_object's session_id from SESSIONS
    session_data = SESSIONS.get(payload.session_id)
    if not session_data:
        raise HTTPException(status_code=404, detail="Session expired or invalid.")
    
    try:
        # Validate Hex format and Length BEFORE passing to liboqs
        # Kyber768 Ciphertext limit is 1088 bytes -> 2176 hex characters
        ciphertext = bytes.fromhex(payload.ciphertext_hex)
        if len(ciphertext) != Kyber768_Length:
            raise ValueError(f"Invalid ciphertext length: expected 1088 bytes, got {len(ciphertext)}")

        # Perform Decapsulation
        server_kem = session_data["kem_object"]
        shared_secret = server_kem.decap_secret(ciphertext)
        
        # Clean up session immediately on success
        del SESSIONS[payload.session_id]
        
        return HandshakeCompleteResponse(status="Secure Channel Established")

    except ValueError as ve:
        # Handle specific validation errors (e.g., bad hex, wrong length)
        if payload.session_id in SESSIONS: del SESSIONS[payload.session_id]
        raise HTTPException(status_code=400, detail=str(ve))
        
    except Exception as e:
        # Handle library/runtime errors
        if payload.session_id in SESSIONS: del SESSIONS[payload.session_id]
        # Log the actual error internally, but keep the client response generic for security
        print(f"Decapsulation internal error: {str(e)}") 
        raise HTTPException(status_code=400, detail="Decapsulation failed: Cryptographic error.")
    

@app.post("/api/v1/verify/document")
def verify_document_signature(payload: VerifySignatureRequest):
    # Format Validation: Regex check for valid Hexadecimal strings
    # This prevents invalid characters from ever hitting the bytes conversion
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    if not (hex_pattern.match(payload.signature_hex) and hex_pattern.match(payload.public_key_hex)):
        raise HTTPException(status_code=400, detail="Malformed input: Expected hexadecimal strings.")

    try:
        # Parsing: Safe to convert now that format is confirmed
        msg_bytes = payload.message.encode('utf-8')
        sig_bytes = bytes.fromhex(payload.signature_hex)
        pub_key_bytes = bytes.fromhex(payload.public_key_hex)

        # Cryptographic Verification: Trust the library's internal math
        with oqs.Signature("ML-DSA-65") as verifier:
            # The library will raise an exception if bytes are fundamentally wrong 
            # (e.g. key object is truncated), otherwise it returns False on mismatch.
            is_valid = verifier.verify(msg_bytes, sig_bytes, pub_key_bytes)
            
            if is_valid:
                return {"status": "success"}
            else:
                # This raises the 401, which we must ensure isn't caught by the generic Exception block
                raise HTTPException(status_code=401, detail="Signature mismatch.")

    # Catch our specific logic errors first
    except HTTPException:
        raise
        
    # Catch unexpected library/runtime errors last
    except Exception as e:
        print(f"DEBUG: Critical library error: {e}")
        raise HTTPException(status_code=400, detail="Verification processing failed.")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)