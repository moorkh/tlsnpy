# TLSNotary Python Example

This example demonstrates how to use the `tlsnpy` package to:
1. Run a notary server
2. Create a prover instance
3. Prove a real API response using TLSNotary

## Structure

- `tlsnpy_demo/notary.py`: Notary server setup and management
- `tlsnpy_demo/prover.py`: Prover setup and API request proving
- `tlsnpy_demo/demo.py`: Complete end-to-end demonstration
- `pyproject.toml`: Project metadata and dependencies

## Usage

1. Install the package in development mode:
```bash
pip install -e examples/tlsnpy_demo
```

2. Run the demo:
```bash
python -m tlsnpy_demo.demo
```

This will:
- Start a notary server
- Make an API request to a public API
- Generate a proof of the response
- Verify the proof works correctly

## Notes

- The notary server requires TLS key pairs for operation
- The example uses a public API that doesn't require authentication
- All temporary files and proofs are stored in a `demo_data` directory
