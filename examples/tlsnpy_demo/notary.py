"""
Notary server setup and management for the TLSNotary demo.
"""

import os
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from tlsnpy import PyNotary

class NotaryServer:
    """Manages a TLSNotary server instance with automatic key generation."""
    
    def __init__(self, host="127.0.0.1", port=7047):
        """Initialize the notary server with default configuration."""
        self.host = host
        self.port = port
        self.data_dir = Path("demo_data")
        self.data_dir.mkdir(exist_ok=True)
        
        # Key paths
        self.notary_key_path = self.data_dir / "notary_key.pem"
        self.notary_pub_key_path = self.data_dir / "notary_pub_key.pem"
        
        # Generate keys if they don't exist
        if not self.notary_key_path.exists():
            self._generate_notary_keys()
            
        # Create server instance
        self.server = PyNotary(
            host=host,
            port=port,
            max_sent_data=100000,  # 100KB
            max_recv_data=100000,  # 100KB
            timeout_seconds=30,
            tls_enabled=False,      # Disable TLS for demo
            tls_cert_path=None,
            tls_key_path=None,
            notary_key_path=str(self.notary_key_path),
            notary_pub_key_path=str(self.notary_pub_key_path)
        )
        
    def _generate_notary_keys(self):
        """Generate notary signing key pair."""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Get public key
        public_key = private_key.public_key()
        
        # Save private key
        with open(self.notary_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        # Save public key
        with open(self.notary_pub_key_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    def start(self):
        """Start the notary server."""
        print(f"Starting notary server on {self.host}:{self.port}")
        self.server.start()
        
    def stop(self):
        """Stop the notary server."""
        print("Stopping notary server...")
        self.server.stop()
        
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
