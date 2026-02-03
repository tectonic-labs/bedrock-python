"""
Command-line interface for testing ML-DSA KATS vectors.
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

from .parser import KeyGenTestCase, parse_nist_json
from .runner import TestResult, run_keygen_test


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="Test ML-DSA KATS vectors for key generation from seed",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test NIST JSON format (requires both files)
  python -m bedrock_python.kats.cli prompt.json expectedResults.json

  # Test specific scheme only
  python -m bedrock_python.kats.cli --scheme 44 prompt.json expectedResults.json
        """
    )
    
    parser.add_argument(
        'prompt_file',
        help='Path to prompt.json file from NIST ACVP vectors (RELEASE/v1.1.0.40)'
    )
    
    parser.add_argument(
        'expected_file',
        help='Path to expectedResults.json file from NIST ACVP vectors (RELEASE/v1.1.0.40)'
    )
    
    parser.add_argument(
        '--scheme',
        type=int,
        choices=[44, 65, 87],
        help='Filter by ML-DSA scheme variant (44, 65, or 87)'
    )
    
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Show detailed test results'
    )
    
    parser.add_argument(
        '--quiet',
        '-q',
        action='store_true',
        help='Only show summary (suppress per-test output)'
    )
    
    args = parser.parse_args()
    
    prompt_file = Path(args.prompt_file)
    expected_file = Path(args.expected_file)
    
    if not prompt_file.exists():
        print(f"Error: Prompt file not found: {prompt_file}", file=sys.stderr)
        sys.exit(1)
    
    if not expected_file.exists():
        print(f"Error: Expected results file not found: {expected_file}", file=sys.stderr)
        sys.exit(1)
    
    try:
        test_cases = parse_nist_json(prompt_file, expected_file)
    except Exception as e:
        print(f"Error parsing test vectors: {e}", file=sys.stderr)
        sys.exit(1)
    
    if not test_cases:
        print("Error: No test cases found", file=sys.stderr)
        sys.exit(1)
    
    # Filter by scheme if specified
    if args.scheme:
        test_cases = [tc for tc in test_cases if tc.scheme == args.scheme]
        if not test_cases:
            print(f"Error: No test cases found for scheme {args.scheme}", file=sys.stderr)
            sys.exit(1)
    
    # Run tests
    results = run_tests(test_cases, verbose=args.verbose, quiet=args.quiet)
    
    # Print summary
    print_summary(results, verbose=args.verbose)
    
    # Exit with appropriate code
    if all(r.passed for r in results):
        sys.exit(0)
    else:
        sys.exit(1)


def run_tests(test_cases: List[KeyGenTestCase], verbose: bool = False, quiet: bool = False) -> List[TestResult]:
    """Run all test cases and return results."""
    results = []
    
    # Use progress bar if available and not quiet
    if HAS_TQDM and not quiet and len(test_cases) > 10:
        iterator = tqdm(test_cases, desc="Running tests", unit="test")
    else:
        iterator = test_cases
    
    for test_case in iterator:
        result = run_keygen_test(test_case)
        results.append(result)
        
        if verbose and not quiet:
            status = "✓" if result.passed else "✗"
            test_id = result.test_id or "unknown"
            scheme = result.scheme or "?"
            print(f"{status} Test {test_id} (ML-DSA-{scheme}): ", end="")
            if result.passed:
                print("PASSED")
            else:
                print(f"FAILED - {result.error_message}")
        elif not quiet and not result.passed:
            # Show failures even if not verbose
            test_id = result.test_id or "unknown"
            scheme = result.scheme or "?"
            print(f"✗ Test {test_id} (ML-DSA-{scheme}): FAILED - {result.error_message}")
    
    return results


def print_summary(results: List[TestResult], verbose: bool = False):
    """Print test summary statistics."""
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    print(f"Total tests:  {total}")
    print(f"Passed:      {passed}")
    print(f"Failed:      {failed}")
    
    if failed > 0:
        print("\nFailed tests:")
        for result in results:
            if not result.passed:
                test_id = result.test_id or "unknown"
                scheme = result.scheme or "?"
                print(f"  - Test {test_id} (ML-DSA-{scheme}): {result.error_message}")
    
    print("=" * 60)
    
    # Group by scheme
    by_scheme = {}
    for result in results:
        scheme = result.scheme or 0
        if scheme not in by_scheme:
            by_scheme[scheme] = {'total': 0, 'passed': 0}
        by_scheme[scheme]['total'] += 1
        if result.passed:
            by_scheme[scheme]['passed'] += 1
    
    if len(by_scheme) > 1:
        print("\nBy Scheme:")
        for scheme in sorted(by_scheme.keys()):
            stats = by_scheme[scheme]
            print(f"  ML-DSA-{scheme}: {stats['passed']}/{stats['total']} passed")


if __name__ == '__main__':
    main()

