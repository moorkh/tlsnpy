"""
Notary server setup and management for the TLSNotary demo.
"""

import os
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
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
        if not self.notary_key_path.exists() or not self.notary_pub_key_path.exists():
            print("Generating new notary key pair...")
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
            notary_key_path=str(self.notary_key_path.absolute()),
            notary_pub_key_path=str(self.notary_pub_key_path.absolute())
        )
        
    def _generate_notary_keys(self):
        """Generate notary signing key pair using secp256k1 curve."""
        try:
            # Generate K256 (secp256k1) private key
            private_key = ec.generate_private_key(
                ec.SECP256K1()  # Use secp256k1 curve as required
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Save private key in PKCS#8 format
            pem_private = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Save public key
            pem_public = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Write keys atomically using temporary files
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp_private:
                tmp_private.write(pem_private)
                tmp_private.flush()
                os.replace(tmp_private.name, self.notary_key_path)
                
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp_public:
                tmp_public.write(pem_public)
                tmp_public.flush()
                os.replace(tmp_public.name, self.notary_pub_key_path)
                
            print(f"Keys generated and saved to {self.data_dir}")
            
            # Verify the keys can be loaded back
            with open(self.notary_key_path, 'rb') as f:
                loaded_private = serialization.load_pem_private_key(f.read(), password=None)
                if not isinstance(loaded_private, ec.EllipticCurvePrivateKey):
                    raise ValueError("Generated key is not an EC private key")
                if not isinstance(loaded_private.curve, ec.SECP256K1):
                    raise ValueError("Generated key is not using secp256k1 curve")
                
            with open(self.notary_pub_key_path, 'rb') as f:
                loaded_public = serialization.load_pem_public_key(f.read())
                if not isinstance(loaded_public, ec.EllipticCurvePublicKey):
                    raise ValueError("Generated key is not an EC public key")
                if not isinstance(loaded_public.curve, ec.SECP256K1):
                    raise ValueError("Generated key is not using secp256k1 curve")
                
        except Exception as e:
            print(f"Error generating keys: {e}")
            # Clean up any partially written files
            for path in [self.notary_key_path, self.notary_pub_key_path]:
                try:
                    path.unlink(missing_ok=True)
                except Exception:
                    pass
            raise
    
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
