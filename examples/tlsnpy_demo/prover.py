"""
Prover setup and API request proving for the TLSNotary demo.
"""

import time
import urllib.parse
from pathlib import Path
from tlsnpy import PyProver

class APIProver:
    """Manages a TLSNotary prover instance for proving API responses."""
    
    def __init__(self, notary_host="127.0.0.1", notary_port=7047):
        """Initialize the prover with connection to notary server."""
        self.notary_host = notary_host
        self.notary_port = notary_port
        self.data_dir = Path("demo_data")
        self.data_dir.mkdir(exist_ok=True)
        
    def _retry_operation(self, operation, max_retries=3, retry_delay=1):
        """Retry an operation with exponential backoff."""
        last_error = None
        for attempt in range(max_retries):
            try:
                return operation()
            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    delay = retry_delay * (2 ** attempt)
                    print(f"Attempt {attempt + 1} failed, retrying in {delay} seconds...")
                    time.sleep(delay)
        raise last_error
        
    def prove_request(self, url):
        """Prove a GET request to the specified URL."""
        # Parse URL to get host and path
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc
        port = 443  # Always use HTTPS
        
        # Create prover instance
        prover = PyProver(
            notary_host=self.notary_host,
            notary_port=self.notary_port,
            server_name=host
        )
        
        try:
            # Initialize connection with retries
            print("Setting up prover...")
            self._retry_operation(lambda: prover.reset())
            
            # Connect to server with retries
            print(f"Connecting to {host}...")
            self._retry_operation(lambda: prover.connect(host, port))
            
            # Start notarization
            print("Starting notarization...")
            prover.start_notarize()
            
            # Generate proof
            print("Generating proof...")
            proof = prover.finalize_notarize()
            
            # Save proof
            proof_path = self.data_dir / "api_response.proof"
            with open(proof_path, "wb") as f:
                f.write(proof)
                
            print(f"Proof saved to {proof_path}")
            return proof_path
            
        except Exception as e:
            print(f"Error during proving: {e}")
            raise
