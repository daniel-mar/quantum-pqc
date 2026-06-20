from oqs import Signature

# post-quantum signature algorithm (e.g., ML-DSA-65)
alg_name = "ML-DSA-65"

with Signature(alg_name) as signer:
    # 1. Generate keypair
    public_key = signer.generate_keypair()
    message = b"This is a sensitive document that needs signing."

    # 2. Sign the message (using private key)
    signature = signer.sign(message)
    
    # 3. Verification (using public key)
    is_valid = signer.verify(message, signature, public_key)
    
    print(f"Algorithm: {alg_name}")
    print(f"Is signature valid? {is_valid}")