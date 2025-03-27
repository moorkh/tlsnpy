"""
Complete end-to-end demonstration of TLSNotary functionality.
"""

import time
import sys
from .notary import NotaryServer
from .prover import APIProver

def main():
    """Run the complete TLSNotary demo."""
    
    # Example API endpoint (using httpbin.org as it's public and supports HTTPS)
    API_URL = "https://httpbin.org/get"
    
    print("TLSNotary Demo")
    print("=============")
    
    try:
        # Start notary server
        with NotaryServer() as notary:
            print("\nNotary server started successfully")
            
            # Give server time to initialize
            print("Waiting for server to initialize...")
            time.sleep(3)
            
            # Create prover and prove API request
            print("\nProving API request...")
            prover = APIProver()
            
            try:
                proof_path = prover.prove_request(API_URL)
                print(f"\nSuccess! Proof saved to {proof_path}")
                print("\nYou can now use this proof to verify the API response.")
                
            except Exception as e:
                print(f"\nError during proving: {e}", file=sys.stderr)
                raise
                
    except Exception as e:
        print(f"\nError during demo: {e}", file=sys.stderr)
        sys.exit(1)
            
if __name__ == "__main__":
    main()
