"""
Complete end-to-end demonstration of TLSNotary functionality.
"""

import time
from .notary import NotaryServer
from .prover import APIProver

def main():
    """Run the complete TLSNotary demo."""
    
    # Example API endpoint (using httpbin.org as it's public and supports HTTPS)
    API_URL = "https://httpbin.org/get"
    
    print("TLSNotary Demo")
    print("=============")
    
    # Start notary server
    with NotaryServer() as notary:
        print("\nNotary server started successfully")
        
        # Give server time to initialize
        time.sleep(2)
        
        # Create prover and prove API request
        print("\nProving API request...")
        prover = APIProver()
        
        try:
            proof_path = prover.prove_request(API_URL)
            print(f"\nSuccess! Proof saved to {proof_path}")
            print("\nYou can now use this proof to verify the API response.")
            
        except Exception as e:
            print(f"\nError during demo: {e}")
            raise
            
if __name__ == "__main__":
    main()
