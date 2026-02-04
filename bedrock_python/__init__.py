"""
Bedrock Python bindings for the Bedrock cryptographic library.

The main bedrock_python module is built from Rust and provides
cryptographic primitives. This package also includes KATS testing
utilities in the bedrock_python.kats submodule.
"""

__version__ = "0.1.0"

# Re-export all symbols from the Rust extension module
from .bedrock_python import *

