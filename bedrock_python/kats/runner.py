"""
Test runner for ML-DSA key generation KATS vectors.
"""

try:
    import bedrock_python as bedrock
except ImportError:
    # For development/testing, try importing the built module
    import sys
    import importlib
    # The module might be named differently during development
    bedrock = importlib.import_module('bedrock_python')

from dataclasses import dataclass
from typing import Optional

from .parser import KeyGenTestCase


@dataclass
class TestResult:
    """Result of a single test case execution."""
    passed: bool
    test_id: Optional[str]
    error_message: Optional[str] = None
    scheme: Optional[int] = None


def run_keygen_test(test_case: KeyGenTestCase) -> TestResult:
    """
    Execute a single key generation test case.
    
    Args:
        test_case: The test case to execute
        
    Returns:
        TestResult indicating pass/fail status
    """
    try:
        # Get the appropriate scheme
        scheme_obj = _get_scheme(test_case.scheme)
        if scheme_obj is None:
            return TestResult(
                passed=False,
                test_id=test_case.test_id,
                scheme=test_case.scheme,
                error_message=f"Unsupported scheme: {test_case.scheme}"
            )
        
        # Generate keypair from seed
        keypair = scheme_obj.keypair_from_seed(test_case.seed)
        
        # Get the generated keys
        generated_pk = keypair.public_key()
        generated_sk = keypair.secret_key()
        
        if generated_sk is None:
            return TestResult(
                passed=False,
                test_id=test_case.test_id,
                scheme=test_case.scheme,
                error_message="Generated keypair does not contain secret key"
            )
        
        # Serialize the generated keys for comparison
        # The keys are serialized as JSON strings, so we need to compare
        # the serialized format or parse and compare the raw bytes
        generated_pk_str = generated_pk.to_string()
        generated_sk_str = generated_sk.to_string()
        
        # Compare keys - extract hex value from generated JSON and compare with expected hex
        expected_pk_match = _compare_keys(generated_pk_str, test_case.expected_pk)
        expected_sk_match = _compare_keys(generated_sk_str, test_case.expected_sk)
        
        if expected_pk_match and expected_sk_match:
            return TestResult(
                passed=True,
                test_id=test_case.test_id,
                scheme=test_case.scheme
            )
        else:
            errors = []
            if not expected_pk_match:
                errors.append("Public key mismatch")
            if not expected_sk_match:
                errors.append("Secret key mismatch")
            
            return TestResult(
                passed=False,
                test_id=test_case.test_id,
                scheme=test_case.scheme,
                error_message="; ".join(errors)
            )
    
    except Exception as e:
        return TestResult(
            passed=False,
            test_id=test_case.test_id,
            scheme=test_case.scheme,
            error_message=f"Exception during test: {str(e)}"
        )


def _get_scheme(scheme: int):
    """Get the MlDsaScheme object for the given scheme variant."""
    if scheme == 44:
        return bedrock.MlDsaScheme.dsa_44()
    elif scheme == 65:
        return bedrock.MlDsaScheme.dsa_65()
    elif scheme == 87:
        return bedrock.MlDsaScheme.dsa_87()
    else:
        return None


def _compare_keys(generated_key_str: str, expected_key_hex: str) -> bool:
    """
    Compare a generated key (serialized as JSON string) with expected key hex string.
    
    Bedrock serializes keys as JSON with format: {"scheme":"ML-DSA-XX","value":"hex_string"}
    NIST ACVP format provides keys as hex strings directly.
    
    Args:
        generated_key_str: JSON-serialized key from bedrock API
        expected_key_hex: Expected key as hex string (from NIST format)
        key_type: "pk" for public key, "sk" for secret key
        
    Returns:
        True if keys match, False otherwise
    """
    import json
    
    try:
        # Parse the generated key JSON to extract the hex value
        generated_json = json.loads(generated_key_str)
        generated_hex = generated_json.get('value', '')
        
        # Normalize both hex strings (uppercase, no spaces) for comparison
        generated_hex_normalized = generated_hex.upper().replace(' ', '')
        expected_hex_normalized = expected_key_hex.upper().replace(' ', '')
        
        return generated_hex_normalized == expected_hex_normalized
    except (json.JSONDecodeError, AttributeError, KeyError):
        return False



