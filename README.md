# bedrock-python

Python bindings for the [Bedrock](https://github.com/tectonic-labs/bedrock) cryptographic library, providing post-quantum digital signature schemes and hierarchical deterministic (HD) wallet functionality.

## Features

- **Falcon (FN-DSA)** - NIST post-quantum digital signature standard
  - FN-DSA-512, FN-DSA-1024, and Ethereum-compatible variants
  - Key generation, signing, and verification
  - Serialization/deserialization support

- **ML-DSA (Dilithium)** - NIST post-quantum digital signature standard
  - ML-DSA-44, ML-DSA-65, and ML-DSA-87 security levels
  - Key generation, signing, and verification
  - Serialization/deserialization support

- **HHD Wallet** - Hierarchical HD wallet for post-quantum cryptography
  - BIP-39 compatible mnemonic generation
  - Deterministic key derivation for multiple signature schemes
  - Support for ECDSA secp256k1, Falcon, and ML-DSA

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/tectonic-labs/bedrock-python.git
cd bedrock-python

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install build dependencies
pip install maturin

# Build and install in development mode
maturin develop

# Or build a wheel for distribution
maturin build --release
```

### Requirements

- Python >= 3.8
- Rust toolchain (for building from source)
- maturin >= 1.0

## Usage

### Falcon (FN-DSA) Signatures

```python
import bedrock_python as bedrock

# Create a Falcon scheme (DSA-512, DSA-1024, or Ethereum)
scheme = bedrock.FalconScheme.dsa_512()
# Or use: bedrock.FalconScheme.dsa_1024()
# Or use: bedrock.FalconScheme.ethereum()

# Generate a keypair
keypair = scheme.keypair()

# Sign a message
message = b"Hello, post-quantum world!"
signature = scheme.sign(message, keypair)

# Verify the signature
public_key = keypair.public_key()
is_valid = scheme.verify(message, signature, public_key)
print(f"Signature valid: {is_valid}")

# Serialize keys for storage
keypair_json = keypair.to_string()
pk_json = public_key.to_string()
sig_json = signature.to_string()

# Deserialize
restored_keypair = bedrock.FalconKeyPair.parse(keypair_json)
restored_pk = bedrock.FalconVerificationKey.parse(pk_json)
restored_sig = bedrock.FalconSignature.parse(sig_json)
```

### ML-DSA (Dilithium) Signatures

```python
import bedrock_python as bedrock

# Create an ML-DSA scheme (44, 65, or 87 security level)
scheme = bedrock.MlDsaScheme.dsa_44()
# Or use: bedrock.MlDsaScheme.dsa_65()
# Or use: bedrock.MlDsaScheme.dsa_87()

# Generate a keypair
keypair = scheme.keypair()

# Sign a message
message = b"Hello, ML-DSA!"
signature = scheme.sign(message, keypair)

# Verify the signature
public_key = keypair.public_key()
is_valid = scheme.verify(message, signature, public_key)
print(f"Signature valid: {is_valid}")

# Serialize/deserialize works the same as Falcon
keypair_json = keypair.to_string()
restored = bedrock.MlDsaKeyPair.parse(keypair_json)
```

### HHD Wallet (Hierarchical Deterministic)

```python
import bedrock_python as bedrock

# Define which signature schemes you want to use
schemes = [
    bedrock.SignatureScheme.ecdsa_secp256k1(),
    bedrock.SignatureScheme.fn_dsa_512(),
    bedrock.SignatureScheme.ml_dsa_44(),
]

# Create a new wallet (generates a new mnemonic)
wallet = bedrock.HhdWallet.new(schemes)

# Or create with a password for additional security
wallet = bedrock.HhdWallet.new(schemes, password="my-secret-password")

# Get the mnemonic phrase (store this securely!)
mnemonic = wallet.mnemonic()
print(f"Mnemonic: {mnemonic}")

# Restore a wallet from an existing mnemonic
restored_wallet = bedrock.HhdWallet.new_from_mnemonic(mnemonic, schemes)

# Derive ECDSA secp256k1 keys
ecdsa_keys = wallet.derive_ecdsa_secp256k1_keypair(index=0)
print(f"ECDSA secret key: {ecdsa_keys['secret_key'].hex()}")
print(f"ECDSA public key: {ecdsa_keys['public_key'].hex()}")

# Derive Falcon keys
falcon_keypair = wallet.derive_fn_dsa512_keypair(index=0)
falcon_pk = falcon_keypair.public_key()

# Derive ML-DSA keys
ml_dsa_keypair = wallet.derive_ml_dsa44_keypair(index=0)
# Also available: derive_ml_dsa65_keypair(), derive_ml_dsa87_keypair()

# Use derived keys for signing
falcon_scheme = bedrock.FalconScheme.dsa_512()
message = b"Sign with derived key"
signature = falcon_scheme.sign(message, falcon_keypair)
is_valid = falcon_scheme.verify(message, signature, falcon_pk)
```

### Using Scheme Constants

```python
import bedrock_python as bedrock

# Module-level constants
print(bedrock.FALCON_DSA_512)      # 1
print(bedrock.FALCON_DSA_512_STR)  # "FN-DSA-512"

print(bedrock.ML_DSA_44)           # 1
print(bedrock.ML_DSA_44_STR)       # "ML-DSA-44"

# Class-level constants
print(bedrock.FalconScheme.DSA_512)      # 1
print(bedrock.FalconScheme.DSA_512_STR)  # "FN-DSA-512"

# Create schemes from constants
scheme = bedrock.FalconScheme.try_from(bedrock.FALCON_DSA_512)
scheme = bedrock.FalconScheme.parse(bedrock.FALCON_DSA_512_STR)
```

## API Reference

### Falcon Module

| Class | Description |
|-------|-------------|
| `FalconScheme` | Falcon signature scheme configuration |
| `FalconKeyPair` | Public and private key pair |
| `FalconVerificationKey` | Public key for verification |
| `FalconSigningKey` | Private key for signing |
| `FalconSignature` | Digital signature |

**FalconScheme Methods:**
- `new()` - Create default scheme
- `dsa_512()`, `dsa_1024()`, `ethereum()` - Factory methods
- `try_from(int)`, `parse(str)` - Create from value
- `to_int()`, `to_string()` - Convert to value
- `keypair()` - Generate random keypair
- `keypair_from_seed(bytes)` - Deterministic keypair
- `sign(message, keypair)` - Sign a message
- `verify(message, signature, public_key)` - Verify signature

### ML-DSA Module

| Class | Description |
|-------|-------------|
| `MlDsaScheme` | ML-DSA signature scheme configuration |
| `MlDsaKeyPair` | Public and private key pair |
| `MlDsaVerificationKey` | Public key for verification |
| `MlDsaSigningKey` | Private key for signing |
| `MlDsaSignature` | Digital signature |

**MlDsaScheme Methods:**
- `new()` - Create default scheme
- `dsa_44()`, `dsa_65()`, `dsa_87()` - Factory methods
- `try_from(int)`, `parse(str)` - Create from value
- `to_int()`, `to_string()` - Convert to value
- `keypair()` - Generate random keypair
- `keypair_from_seed(bytes)` - Deterministic keypair
- `sign(message, keypair)` - Sign a message
- `verify(message, signature, public_key)` - Verify signature

### HHD Module

| Class | Description |
|-------|-------------|
| `HhdWallet` | Hierarchical deterministic wallet |
| `SignatureScheme` | Signature scheme selector for HHD |

**SignatureScheme Factory Methods:**
- `ecdsa_secp256k1()` - ECDSA on secp256k1
- `fn_dsa_512()` - Falcon DSA-512
- `ml_dsa_44()`, `ml_dsa_65()`, `ml_dsa_87()` - ML-DSA variants

**HhdWallet Methods:**
- `new(schemes, password=None)` - Create new wallet
- `new_from_mnemonic(mnemonic, schemes, password=None)` - Restore wallet
- `mnemonic()` - Get BIP-39 mnemonic phrase
- `master_seeds()` - Get master seeds dictionary
- `derive_ecdsa_secp256k1_keypair(index)` - Derive ECDSA keys
- `derive_fn_dsa512_keypair(index)` - Derive Falcon keys
- `derive_ml_dsa44_keypair(index)` - Derive ML-DSA-44 keys
- `derive_ml_dsa65_keypair(index)` - Derive ML-DSA-65 keys
- `derive_ml_dsa87_keypair(index)` - Derive ML-DSA-87 keys

## Development

### Setup

```bash
# Clone and enter directory
git clone https://github.com/tectonic-labs/bedrock-python.git
cd bedrock-python

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install development dependencies
pip install maturin pytest

# Build in development mode
maturin develop
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_falcon.py -v
pytest tests/test_ml_dsa.py -v
pytest tests/test_hhd.py -v
```

### Building for Release

```bash
# Build optimized wheel
maturin build --release

# The wheel will be in target/wheels/
```

## Building & Distributing Packages

### Building a Wheel for Local Installation

Build a wheel that can be installed via `pip`:

```bash
# Build release wheel for your current platform
maturin build --release

# The wheel will be created in target/wheels/
# Example: target/wheels/bedrock_python-0.1.0-cp311-cp311-macosx_11_0_arm64.whl

# Install the wheel with pip
pip install target/wheels/bedrock_python-0.1.0-*.whl
```

### Building Wheels for Multiple Python Versions

```bash
# Build for a specific Python version
maturin build --release --interpreter python3.10

# Build for multiple Python versions
maturin build --release --interpreter python3.9 python3.10 python3.11 python3.12
```

### Building Universal macOS Wheels

```bash
# Build universal2 wheel for macOS (supports both Intel and Apple Silicon)
maturin build --release --target universal2-apple-darwin
```

### Building many Linux Wheels (for Linux distribution)

For distributing on Linux, you should build `manylinux` compatible wheels using Docker:

```bash
# Build manylinux wheels using the official maturin Docker image
docker run --rm -v $(pwd):/io ghcr.io/pyo3/maturin build --release

# Or for a specific manylinux version
docker run --rm -v $(pwd):/io ghcr.io/pyo3/maturin build --release --manylinux 2_28
```

### Publishing to PyPI

To publish your package to PyPI:

```bash
# First, create an account on https://pypi.org and generate an API token

# Build release wheels
maturin build --release

# Publish to PyPI (will prompt for credentials or use MATURIN_PYPI_TOKEN env var)
maturin publish

# Or publish to TestPyPI first for testing
maturin publish --repository testpypi
```

You can also set up credentials:

```bash
# Using environment variable
export MATURIN_PYPI_TOKEN=pypi-your-token-here
maturin publish

# Or using a .pypirc file
# Create ~/.pypirc with:
# [pypi]
# username = __token__
# password = pypi-your-token-here
```

### Installing from PyPI

Once published, users can install with:

```bash
pip install bedrock-python
```

### Installing from a Local Wheel

```bash
# Install from a wheel file
pip install path/to/bedrock_python-0.1.0-cp311-cp311-macosx_11_0_arm64.whl

# Or install directly from the build
cd bedrock-python
pip install .
```

### Installing from Git

```bash
# Install directly from GitHub (requires Rust toolchain)
pip install git+https://github.com/tectonic-labs/bedrock-python.git

# Or with a specific tag/branch
pip install git+https://github.com/tectonic-labs/bedrock-python.git@v0.1.0
```

### Creating a Source Distribution

```bash
# Build source distribution (sdist)
maturin sdist

# The sdist will be in target/wheels/
# Users installing from sdist will need Rust toolchain
```

## Feature Flags

The following Cargo features control which functionality is included:

| Feature | Description |
|---------|-------------|
| `hhd` | Hierarchical HD wallet support |
| `kgen` | Key generation |
| `sign` | Signing operations |
| `vrfy` | Verification operations |
| `fn-dsa` | Falcon signature scheme |
| `eth-falcon` | Ethereum-compatible Falcon |
| `ml-dsa` | ML-DSA (Dilithium) signature scheme |

All features are enabled by default.