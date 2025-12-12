"""
Tests for the ML-DSA signature scheme bindings.

Setup and run commands:

    # Create virtual environment
    python3 -m venv .venv

    # Activate virtual environment
    source .venv/bin/activate

    # Install dependencies
    pip install maturin pytest

    # Build and install the module in development mode
    maturin develop

    # Run the tests
    pytest tests/test_ml_dsa.py -v

    # Or run tests directly with venv Python
    .venv/bin/python -m pytest tests/test_ml_dsa.py -v

Note: Always activate the virtual environment before running tests,
or the module won't be found.
"""

import pytest

# Import the module - adjust the import based on your module name
import bedrock_python as bedrock


class TestMlDsaScheme:
    """Tests for MlDsaScheme class."""

    def test_new(self):
        """Test creating a new default MlDsaScheme."""
        scheme = bedrock.MlDsaScheme.new()
        assert scheme is not None

    def test_try_from_valid(self):
        """Test creating MlDsaScheme from valid u8 values."""
        # Get a valid scheme value from the default scheme
        default_scheme = bedrock.MlDsaScheme.new()
        valid_value = default_scheme.to_int()
        
        scheme = bedrock.MlDsaScheme.try_from(valid_value)
        assert scheme is not None
        assert scheme.to_int() == valid_value

    def test_try_from_invalid(self):
        """Test creating MlDsaScheme from invalid u8 value."""
        with pytest.raises(ValueError):
            bedrock.MlDsaScheme.try_from(255)

    def test_parse_and_to_string(self):
        """Test parsing scheme from string and converting back."""
        scheme = bedrock.MlDsaScheme.new()
        scheme_str = scheme.to_string()
        assert isinstance(scheme_str, str)
        assert len(scheme_str) > 0

        # Parse back from string
        parsed_scheme = bedrock.MlDsaScheme.parse(scheme_str)
        assert parsed_scheme.to_string() == scheme_str

    def test_parse_invalid(self):
        """Test parsing invalid scheme string."""
        with pytest.raises(ValueError):
            bedrock.MlDsaScheme.parse("invalid_scheme_name")

    def test_to_int(self):
        """Test converting scheme to integer."""
        scheme = bedrock.MlDsaScheme.new()
        scheme_int = scheme.to_int()
        assert isinstance(scheme_int, int)
        assert 0 <= scheme_int <= 255


class TestMlDsaSchemeConstants:
    """Tests for ML-DSA scheme constants and factory methods."""

    def test_module_integer_constants(self):
        """Test module-level integer constants."""
        assert bedrock.ML_DSA_44 == 1
        assert bedrock.ML_DSA_65 == 2
        assert bedrock.ML_DSA_87 == 3

    def test_module_string_constants(self):
        """Test module-level string constants."""
        assert bedrock.ML_DSA_44_STR == "ML-DSA-44"
        assert bedrock.ML_DSA_65_STR == "ML-DSA-65"
        assert bedrock.ML_DSA_87_STR == "ML-DSA-87"

    def test_class_integer_constants(self):
        """Test class-level integer constants."""
        assert bedrock.MlDsaScheme.DSA_44 == 1
        assert bedrock.MlDsaScheme.DSA_65 == 2
        assert bedrock.MlDsaScheme.DSA_87 == 3

    def test_class_string_constants(self):
        """Test class-level string constants."""
        assert bedrock.MlDsaScheme.DSA_44_STR == "ML-DSA-44"
        assert bedrock.MlDsaScheme.DSA_65_STR == "ML-DSA-65"
        assert bedrock.MlDsaScheme.DSA_87_STR == "ML-DSA-87"

    def test_constants_match(self):
        """Test that module and class constants match."""
        assert bedrock.ML_DSA_44 == bedrock.MlDsaScheme.DSA_44
        assert bedrock.ML_DSA_65 == bedrock.MlDsaScheme.DSA_65
        assert bedrock.ML_DSA_87 == bedrock.MlDsaScheme.DSA_87
        assert bedrock.ML_DSA_44_STR == bedrock.MlDsaScheme.DSA_44_STR
        assert bedrock.ML_DSA_65_STR == bedrock.MlDsaScheme.DSA_65_STR
        assert bedrock.ML_DSA_87_STR == bedrock.MlDsaScheme.DSA_87_STR

    def test_dsa_44_factory(self):
        """Test MlDsaScheme.dsa_44() factory method."""
        scheme = bedrock.MlDsaScheme.dsa_44()
        assert scheme is not None
        assert scheme.to_int() == bedrock.ML_DSA_44
        assert scheme.to_string() == bedrock.ML_DSA_44_STR

    def test_dsa_65_factory(self):
        """Test MlDsaScheme.dsa_65() factory method."""
        scheme = bedrock.MlDsaScheme.dsa_65()
        assert scheme is not None
        assert scheme.to_int() == bedrock.ML_DSA_65
        assert scheme.to_string() == bedrock.ML_DSA_65_STR

    def test_dsa_87_factory(self):
        """Test MlDsaScheme.dsa_87() factory method."""
        scheme = bedrock.MlDsaScheme.dsa_87()
        assert scheme is not None
        assert scheme.to_int() == bedrock.ML_DSA_87
        assert scheme.to_string() == bedrock.ML_DSA_87_STR

    def test_try_from_with_constants(self):
        """Test creating schemes using constants with try_from."""
        dsa_44 = bedrock.MlDsaScheme.try_from(bedrock.ML_DSA_44)
        assert dsa_44.to_int() == 1

        dsa_65 = bedrock.MlDsaScheme.try_from(bedrock.ML_DSA_65)
        assert dsa_65.to_int() == 2

        dsa_87 = bedrock.MlDsaScheme.try_from(bedrock.ML_DSA_87)
        assert dsa_87.to_int() == 3

    def test_parse_with_string_constants(self):
        """Test creating schemes using string constants with parse."""
        dsa_44 = bedrock.MlDsaScheme.parse(bedrock.ML_DSA_44_STR)
        assert dsa_44.to_string() == "ML-DSA-44"

        dsa_65 = bedrock.MlDsaScheme.parse(bedrock.ML_DSA_65_STR)
        assert dsa_65.to_string() == "ML-DSA-65"

        dsa_87 = bedrock.MlDsaScheme.parse(bedrock.ML_DSA_87_STR)
        assert dsa_87.to_string() == "ML-DSA-87"

    def test_sign_verify_with_different_schemes(self):
        """Test sign/verify works with all scheme variants."""
        message = b"Test message for all schemes"

        for factory, name in [
            (bedrock.MlDsaScheme.dsa_44, "DSA-44"),
            (bedrock.MlDsaScheme.dsa_65, "DSA-65"),
            (bedrock.MlDsaScheme.dsa_87, "DSA-87"),
        ]:
            scheme = factory()
            keypair = scheme.keypair()
            signature = scheme.sign(message, keypair)
            pk = keypair.public_key()
            result = scheme.verify(message, signature, pk)
            assert result is True, f"Sign/verify failed for {name}"


class TestMlDsaKeyGeneration:
    """Tests for ML-DSA key generation."""

    def test_keypair(self):
        """Test generating a random keypair."""
        scheme = bedrock.MlDsaScheme.new()
        keypair = scheme.keypair()
        assert keypair is not None

    def test_keypair_from_seed(self):
        """Test generating a keypair from a seed."""
        scheme = bedrock.MlDsaScheme.new()
        # Use a 32-byte seed
        seed = bytes([i % 256 for i in range(32)])
        keypair = scheme.keypair_from_seed(seed)
        assert keypair is not None

    def test_keypair_from_seed_deterministic(self):
        """Test that keypair generation from seed is deterministic."""
        scheme = bedrock.MlDsaScheme.new()
        seed = bytes([42] * 32)

        keypair1 = scheme.keypair_from_seed(seed)
        keypair2 = scheme.keypair_from_seed(seed)

        # Same seed should produce same keys
        assert keypair1.public_key().to_string() == keypair2.public_key().to_string()


class TestMlDsaKeyPair:
    """Tests for MlDsaKeyPair class."""

    @pytest.fixture
    def keypair(self):
        """Create a keypair for testing."""
        scheme = bedrock.MlDsaScheme.new()
        return scheme.keypair()

    def test_public_key(self, keypair):
        """Test extracting public key from keypair."""
        pk = keypair.public_key()
        assert pk is not None

    def test_secret_key(self, keypair):
        """Test extracting secret key from keypair."""
        sk = keypair.secret_key()
        assert sk is not None

    def test_to_string_and_parse(self, keypair):
        """Test serializing and deserializing keypair."""
        keypair_str = keypair.to_string()
        assert isinstance(keypair_str, str)
        assert len(keypair_str) > 0

        # Parse back
        parsed_keypair = bedrock.MlDsaKeyPair.parse(keypair_str)
        assert parsed_keypair.to_string() == keypair_str

    def test_with_public_key(self, keypair):
        """Test creating keypair with only public key."""
        pk = keypair.public_key()
        pk_only_keypair = bedrock.MlDsaKeyPair.with_public_key(pk)

        # Should have public key
        assert pk_only_keypair.public_key() is not None

        # Should not have secret key
        assert pk_only_keypair.secret_key() is None


class TestMlDsaVerificationKey:
    """Tests for MlDsaVerificationKey class."""

    @pytest.fixture
    def verification_key(self):
        """Create a verification key for testing."""
        scheme = bedrock.MlDsaScheme.new()
        keypair = scheme.keypair()
        return keypair.public_key()

    def test_to_string(self, verification_key):
        """Test serializing verification key."""
        pk_str = verification_key.to_string()
        assert isinstance(pk_str, str)
        assert len(pk_str) > 0

    def test_parse(self, verification_key):
        """Test parsing verification key from string."""
        pk_str = verification_key.to_string()
        parsed_pk = bedrock.MlDsaVerificationKey.parse(pk_str)
        assert parsed_pk.to_string() == pk_str

    def test_parse_invalid(self):
        """Test parsing invalid verification key string."""
        with pytest.raises(ValueError):
            bedrock.MlDsaVerificationKey.parse("invalid json")


class TestMlDsaSigningKey:
    """Tests for MlDsaSigningKey class."""

    @pytest.fixture
    def signing_key(self):
        """Create a signing key for testing."""
        scheme = bedrock.MlDsaScheme.new()
        keypair = scheme.keypair()
        return keypair.secret_key()

    def test_to_string(self, signing_key):
        """Test serializing signing key."""
        sk_str = signing_key.to_string()
        assert isinstance(sk_str, str)
        assert len(sk_str) > 0

    def test_parse(self, signing_key):
        """Test parsing signing key from string."""
        sk_str = signing_key.to_string()
        parsed_sk = bedrock.MlDsaSigningKey.parse(sk_str)
        assert parsed_sk.to_string() == sk_str

    def test_parse_invalid(self):
        """Test parsing invalid signing key string."""
        with pytest.raises(ValueError):
            bedrock.MlDsaSigningKey.parse("invalid json")


class TestMlDsaSignature:
    """Tests for MlDsaSignature class."""

    @pytest.fixture
    def signature(self):
        """Create a signature for testing."""
        scheme = bedrock.MlDsaScheme.new()
        keypair = scheme.keypair()
        message = b"test message"
        return scheme.sign(message, keypair)

    def test_to_string(self, signature):
        """Test serializing signature."""
        sig_str = signature.to_string()
        assert isinstance(sig_str, str)
        assert len(sig_str) > 0

    def test_parse(self, signature):
        """Test parsing signature from string."""
        sig_str = signature.to_string()
        parsed_sig = bedrock.MlDsaSignature.parse(sig_str)
        assert parsed_sig.to_string() == sig_str

    def test_parse_invalid(self):
        """Test parsing invalid signature string."""
        with pytest.raises(ValueError):
            bedrock.MlDsaSignature.parse("invalid json")


class TestMlDsaSignAndVerify:
    """Tests for signing and verification."""

    @pytest.fixture
    def scheme(self):
        """Create a scheme for testing."""
        return bedrock.MlDsaScheme.new()

    @pytest.fixture
    def keypair(self, scheme):
        """Create a keypair for testing."""
        return scheme.keypair()

    def test_sign(self, scheme, keypair):
        """Test signing a message."""
        message = b"Hello, ML-DSA!"
        signature = scheme.sign(message, keypair)
        assert signature is not None

    def test_verify_valid(self, scheme, keypair):
        """Test verifying a valid signature."""
        message = b"Hello, ML-DSA!"
        signature = scheme.sign(message, keypair)
        pk = keypair.public_key()

        result = scheme.verify(message, signature, pk)
        assert result is True

    def test_verify_invalid_message(self, scheme, keypair):
        """Test verifying with wrong message fails."""
        message = b"Hello, ML-DSA!"
        wrong_message = b"Wrong message!"
        signature = scheme.sign(message, keypair)
        pk = keypair.public_key()

        with pytest.raises(ValueError):
            scheme.verify(wrong_message, signature, pk)

    def test_verify_wrong_key(self, scheme, keypair):
        """Test verifying with wrong public key fails."""
        message = b"Hello, ML-DSA!"
        signature = scheme.sign(message, keypair)

        # Generate a different keypair
        other_keypair = scheme.keypair()
        other_pk = other_keypair.public_key()

        with pytest.raises(ValueError):
            scheme.verify(message, signature, other_pk)

    def test_sign_without_secret_key_fails(self, scheme, keypair):
        """Test that signing without secret key fails."""
        pk = keypair.public_key()
        pk_only_keypair = bedrock.MlDsaKeyPair.with_public_key(pk)

        message = b"Hello, ML-DSA!"
        with pytest.raises(ValueError):
            scheme.sign(message, pk_only_keypair)

    def test_sign_empty_message(self, scheme, keypair):
        """Test signing an empty message."""
        message = b""
        signature = scheme.sign(message, keypair)
        pk = keypair.public_key()

        result = scheme.verify(message, signature, pk)
        assert result is True

    def test_sign_large_message(self, scheme, keypair):
        """Test signing a large message."""
        message = bytes([i % 256 for i in range(10000)])
        signature = scheme.sign(message, keypair)
        pk = keypair.public_key()

        result = scheme.verify(message, signature, pk)
        assert result is True


class TestRoundTrips:
    """Tests for serialization round trips."""

    def test_full_workflow_with_serialization(self):
        """Test a complete sign/verify workflow with serialization."""
        # Create scheme and keypair
        scheme = bedrock.MlDsaScheme.new()
        keypair = scheme.keypair()

        # Serialize keypair
        keypair_json = keypair.to_string()

        # Sign a message
        message = b"Important document"
        signature = scheme.sign(message, keypair)

        # Serialize signature and public key
        signature_json = signature.to_string()
        pk_json = keypair.public_key().to_string()

        # Now simulate receiving the data and deserializing
        received_signature = bedrock.MlDsaSignature.parse(signature_json)
        received_pk = bedrock.MlDsaVerificationKey.parse(pk_json)

        # Verify
        result = scheme.verify(message, received_signature, received_pk)
        assert result is True

    def test_keypair_serialization_preserves_keys(self):
        """Test that keypair serialization preserves both keys."""
        scheme = bedrock.MlDsaScheme.new()
        original_keypair = scheme.keypair()

        # Serialize and deserialize
        keypair_json = original_keypair.to_string()
        restored_keypair = bedrock.MlDsaKeyPair.parse(keypair_json)

        # Both should be able to sign
        message = b"test"
        sig1 = scheme.sign(message, original_keypair)
        sig2 = scheme.sign(message, restored_keypair)

        # Both signatures should verify with either public key
        pk1 = original_keypair.public_key()
        pk2 = restored_keypair.public_key()

        assert scheme.verify(message, sig1, pk1) is True
        assert scheme.verify(message, sig1, pk2) is True
        assert scheme.verify(message, sig2, pk1) is True
        assert scheme.verify(message, sig2, pk2) is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
