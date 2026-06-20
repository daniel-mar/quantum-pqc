import oqs
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="oqs")

def run_kyber_test():
    # Verify that the library installed correctly
    mechanisms = oqs.get_enabled_kem_mechanisms()
    target = "Kyber768"
    
    if target not in mechanisms:
        print(f"Error: {target} is not enabled in this build.")
        print(f"Supported mechanisms: {mechanisms}")
        return

    print(f"Success: {target} is supported.")

    # 2. Key Encapsulation Mechanism (KEM) test
    # Alice generates a keypair
    with oqs.KeyEncapsulation(target) as alice:
        public_key = alice.generate_keypair()
        
        # Bob encapsulates a secret for Alice
        with oqs.KeyEncapsulation(target) as bob:
            ciphertext, shared_secret_bob = bob.encap_secret(public_key)
            
        # Alice decapsulates the ciphertext to recover the shared secret
        shared_secret_alice = alice.decap_secret(ciphertext)

    # Verification
    if shared_secret_alice == shared_secret_bob:
        print("Success: The shared secrets match!")
        print(f"Secret (first 16 bytes): {shared_secret_alice[:16].hex()}...")
    else:
        print("Failure: The shared secrets do not match.")

if __name__ == "__main__":
    run_kyber_test()