"""
Parser for KATS (Known Answer Tests) vectors for ML-DSA key generation.

Supports NIST ACVP JSON format from RELEASE/v1.1.0.40.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Union


@dataclass
class KeyGenTestCase:
    """Represents a single key generation test case."""
    scheme: int  # 44, 65, or 87
    seed: bytes
    expected_pk: str  # Expected public key (hex string)
    expected_sk: str  # Expected secret key (hex string)
    test_id: Optional[str] = None  # Optional test identifier


def parse_nist_json(prompt_file: Union[str, Path], expected_file: Union[str, Path]) -> List[KeyGenTestCase]:
    """
    Parse NIST ACVP JSON format test vectors from RELEASE/v1.1.0.40.
    
    Format structure:
    - prompt.json: Contains testGroups with tests, each test has a "seed" (hex string)
    - expectedResults.json: Contains testGroups with tests, each test has "pk" and "sk" (hex strings)
    - Test groups are matched by tgId, tests are matched by tcId
    - Scheme is determined from parameterSet field (ML-DSA-44, ML-DSA-65, ML-DSA-87)
    
    Args:
        prompt_file: Path to prompt.json file
        expected_file: Path to expectedResults.json file
        
    Returns:
        List of KeyGenTestCase objects
    """
    prompt_path = Path(prompt_file)
    expected_path = Path(expected_file)
    
    if not prompt_path.exists():
        raise FileNotFoundError(f"Prompt file not found: {prompt_file}")
    if not expected_path.exists():
        raise FileNotFoundError(f"Expected results file not found: {expected_file}")
    
    with open(prompt_path, 'r') as f:
        prompts = json.load(f)
    
    with open(expected_path, 'r') as f:
        expected = json.load(f)
    
    test_cases = []
    
    # Create a map of expected results by (tgId, tcId) for quick lookup
    expected_map = {}
    for test_group in expected.get('testGroups', []):
        group_id = test_group.get('tgId')
        for test in test_group.get('tests', []):
            test_id = test.get('tcId')
            if group_id is not None and test_id is not None:
                expected_map[(group_id, test_id)] = test
    
    # Process prompt test groups
    for test_group in prompts.get('testGroups', []):
        # Determine scheme from parameterSet field
        parameter_set = test_group.get('parameterSet', '')
        scheme = _extract_scheme_from_parameter_set(parameter_set)
        if scheme is None:
            continue
        
        group_id = test_group.get('tgId')
        
        # Extract key generation tests
        for test in test_group.get('tests', []):
            test_id = test.get('tcId')
            
            # Get seed from prompt test
            seed_hex = test.get('seed')
            if seed_hex is None:
                continue
            
            # Get expected keys from expected results
            expected_test = expected_map.get((group_id, test_id))
            if expected_test is None:
                continue
            
            pk_hex = expected_test.get('pk')
            sk_hex = expected_test.get('sk')
            
            if pk_hex is None or sk_hex is None:
                continue
            
            try:
                # NIST format uses hex strings - normalize to uppercase, no spaces
                seed = bytes.fromhex(seed_hex.upper().replace(' ', ''))
                pk_hex_normalized = pk_hex.upper().replace(' ', '')
                sk_hex_normalized = sk_hex.upper().replace(' ', '')
                
                test_cases.append(KeyGenTestCase(
                    scheme=scheme,
                    seed=seed,
                    expected_pk=pk_hex_normalized,
                    expected_sk=sk_hex_normalized,
                    test_id=str(test_id) if test_id else None
                ))
            except ValueError as e:
                # Skip invalid hex data
                continue
    
    return test_cases


def _extract_scheme_from_parameter_set(parameter_set: str) -> Optional[int]:
    """Extract ML-DSA scheme variant from parameterSet string."""
    parameter_set = parameter_set.upper()
    
    if 'ML-DSA-44' in parameter_set or 'MLDSA44' in parameter_set:
        return 44
    elif 'ML-DSA-65' in parameter_set or 'MLDSA65' in parameter_set:
        return 65
    elif 'ML-DSA-87' in parameter_set or 'MLDSA87' in parameter_set:
        return 87
    
    return None



