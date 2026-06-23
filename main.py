from fastapi import FastAPI, HTTPException, status, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import oqs
import secrets
import re
import logging

app = FastAPI(title="Post-Quantum Secure Vault API", version="1.0.0")

# --- Configuration & Constants ---
KYBER768_CIPHERTEXT_LENGTH = 1088

# In-memory session storage (In production, use a secure Redis instance)
SESSIONS = {}

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vault-api")


# ==================================================
# --- Pydantic Schemas ---
# ==================================================
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


# ==================================================
# --- Dependency Functions ---
# ==================================================
def verify_signature_dependency(payload: VerifySignatureRequest) -> dict:
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    if not (hex_pattern.match(payload.signature_hex) and hex_pattern.match(payload.public_key_hex)):
        raise HTTPException(status_code=400, detail="Malformed input.")
    
    try:
        return {
            "msg": payload.message.encode('utf-8'),
            "sig": bytes.fromhex(payload.signature_hex),
            "key": bytes.fromhex(payload.public_key_hex)
        }
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex encoding.")

def get_session_data(payload: HandshakeCompleteRequest) -> dict:
    session_data = SESSIONS.get(payload.session_id)
    if not session_data:
        raise HTTPException(status_code=404, detail="Session expired or invalid.")
    return session_data
    

# ==================================================
# --- Exception Handling ---
# ==================================================
class CryptographicError(Exception):
    """Raised when a cryptographic library operation fails."""
    def __init__(self, message: str, internal_error: str = None):
        self.message = message
        self.internal_error = internal_error
        super().__init__(self.message)

@app.exception_handler(CryptographicError)
async def crypto_exception_handler(request: Request, exc: CryptographicError):
    logger.error(
        f"CRITICAL_CRYPTO_FAILURE | Endpoint: {request.url.path} | "
        f"IP: {request.client.host} | Internal Error: {exc.internal_error}"
    )
    return JSONResponse(status_code=400, content={"detail": exc.message})


# ==================================================
# --- Endpoints ---
# ==================================================
@app.post("/api/v1/auth/pqc-handshake", response_model=HandshakeInitResponse)
def init_pqc_handshake():
    """Server generates a Kyber768 key pair and stores the secret key."""
    kem_alg = "Kyber768"
    try:
        with oqs.KeyEncapsulation(kem_alg) as server_kem:
            public_key = server_kem.generate_keypair()
            # Extract the raw bytes of the secret key to store safely
            secret_key_bytes = server_kem.export_secret_key() 
            
            session_id = secrets.token_urlsafe(32)
            
            # Store the BYTES, not the C-backed object
            SESSIONS[session_id] = {
                "secret_key": secret_key_bytes
            }
            
            return HandshakeInitResponse(
                server_public_key_hex=public_key.hex(),
                session_id=session_id
            )
    except Exception as e:
        logger.error(f"KEM Init Error: {str(e)}")
        raise HTTPException(status_code=500, detail="KEM Initialization Failed")


@app.post("/api/v1/auth/pqc-complete", response_model=HandshakeCompleteResponse)
def complete_pqc_handshake(
    payload: HandshakeCompleteRequest,
    session: dict = Depends(get_session_data)
):
    try:
        ciphertext = bytes.fromhex(payload.ciphertext_hex)
        if len(ciphertext) != KYBER768_CIPHERTEXT_LENGTH:
            raise ValueError(f"Invalid ciphertext length: expected {KYBER768_CIPHERTEXT_LENGTH} bytes.")

        # Re-instantiate the KEM object using the stored secret key bytes
        with oqs.KeyEncapsulation("Kyber768", secret_key=session["secret_key"]) as server_kem:
            shared_secret = server_kem.decap_secret(ciphertext)
        
        # Clean up session immediately on success
        del SESSIONS[payload.session_id]
        
        # In a real app, you would now use `shared_secret` to generate a JWT or symmetric session key
        return HandshakeCompleteResponse(status="Secure Channel Established")

    except ValueError as ve:
        if payload.session_id in SESSIONS: 
            del SESSIONS[payload.session_id]
        raise HTTPException(status_code=400, detail=str(ve))
        
    except Exception as e:
        if payload.session_id in SESSIONS: 
            del SESSIONS[payload.session_id]
            
        # Replaced print() with proper logger
        logger.error(f"Decapsulation internal error: {str(e)}") 
        raise HTTPException(status_code=400, detail="Decapsulation failed: Cryptographic error.")


@app.post("/api/v1/verify/document")
def verify_document_signature(valid_data: dict = Depends(verify_signature_dependency)): 
    with oqs.Signature("ML-DSA-65") as verifier:
        try:
            is_valid = verifier.verify(valid_data["msg"], valid_data["sig"], valid_data["key"])
        except Exception as e:
            raise CryptographicError(
                message="Verification processing failed", 
                internal_error=str(e)
            )

        if is_valid:
            return {"status": "success"}
        else:
            raise HTTPException(status_code=401, detail="Signature mismatch.")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)