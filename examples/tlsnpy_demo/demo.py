"""
Complete end-to-end demonstration of TLSNotary functionality.
"""

import time
import sys
import socket
from .notary import NotaryServer
from .prover import APIProver

def wait_for_server(host, port, timeout=10, retry_interval=0.5):
    """Wait for server to accept connections."""
    start_time = time.time()
    while True:
        try:
            with socket.create_connection((host, port), timeout=1) as sock:
                return True
        except (socket.timeout, ConnectionRefusedError):
            if time.time() - start_time > timeout:
                return False
            time.sleep(retry_interval)

def main():
    """Run the complete TLSNotary demo."""
    
    # Example API endpoint (using httpbin.org as it's public and supports HTTPS)
    API_URL = "https://httpbin.org/get"
    NOTARY_HOST = "127.0.0.1"
    NOTARY_PORT = 7047
    
    print("TLSNotary Demo")
    print("=============")
    
    try:
        # Start notary server
        with NotaryServer(host=NOTARY_HOST, port=NOTARY_PORT) as notary:
            print("\nStarting notary server...")
            
            # Wait for server to accept connections
            if not wait_for_server(NOTARY_HOST, NOTARY_PORT):
                raise RuntimeError("Notary server failed to start")
            print("Notary server started successfully")
            
            # Create prover and prove API request
            print("\nProving API request...")
            prover = APIProver(notary_host=NOTARY_HOST, notary_port=NOTARY_PORT)
            
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
