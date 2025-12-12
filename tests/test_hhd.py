"""
Tests for the HHD (Hierarchical HD) wallet bindings.

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
    pytest tests/test_hhd.py -v

    # Or run tests directly with venv Python
    .venv/bin/python -m pytest tests/test_hhd.py -v

Note: Always activate the virtual environment before running tests,
or the module won't be found.
"""

import pytest

# Import the module
import bedrock_python as bedrock


class TestSignatureScheme:
    """Tests for SignatureScheme class."""

    def test_ecdsa_secp256k1(self):
        """Test creating ECDSA secp256k1 scheme."""
        scheme = bedrock.SignatureScheme.ecdsa_secp256k1()
        assert scheme is not None
        assert "EcdsaSecp256k1" in scheme.to_string()

    def test_fn_dsa_512(self):
        """Test creating FN-DSA-512 scheme."""
        scheme = bedrock.SignatureScheme.fn_dsa_512()
        assert scheme is not None
        # The string representation may be "Falcon512" or similar
        scheme_str = scheme.to_string()
        assert "512" in scheme_str or "Falcon" in scheme_str

    def test_ml_dsa_44(self):
        """Test creating ML-DSA-44 scheme."""
        scheme = bedrock.SignatureScheme.ml_dsa_44()
        assert scheme is not None
        assert "MlDsa44" in scheme.to_string()

    def test_ml_dsa_65(self):
        """Test creating ML-DSA-65 scheme."""
        scheme = bedrock.SignatureScheme.ml_dsa_65()
        assert scheme is not None
        assert "MlDsa65" in scheme.to_string()

    def test_ml_dsa_87(self):
        """Test creating ML-DSA-87 scheme."""
        scheme = bedrock.SignatureScheme.ml_dsa_87()
        assert scheme is not None
        assert "MlDsa87" in scheme.to_string()


class TestHhdWalletCreation:
    """Tests for HhdWallet creation."""

    def test_new_with_single_scheme(self):
        """Test creating wallet with a single scheme."""
        scheme = bedrock.SignatureScheme.ecdsa_secp256k1()
        wallet = bedrock.HhdWallet.new([scheme])
        assert wallet is not None

    def test_new_with_multiple_schemes(self):
        """Test creating wallet with multiple schemes."""
        schemes = [
            bedrock.SignatureScheme.ecdsa_secp256k1(),
            bedrock.SignatureScheme.fn_dsa_512(),
            bedrock.SignatureScheme.ml_dsa_44(),
        ]
        wallet = bedrock.HhdWallet.new(schemes)
        assert wallet is not None

    def test_new_with_password(self):
        """Test creating wallet with a password."""
        scheme = bedrock.SignatureScheme.ecdsa_secp256k1()
        wallet = bedrock.HhdWallet.new([scheme], password="test_password")
        assert wallet is not None

    def test_new_without_password(self):
        """Test creating wallet without a password (None)."""
        scheme = bedrock.SignatureScheme.ecdsa_secp256k1()
        wallet = bedrock.HhdWallet.new([scheme], password=None)
        assert wallet is not None


class TestHhdWalletMnemonic:
    """Tests for HhdWallet mnemonic functionality."""

    def test_mnemonic_returns_string(self):
        """Test that mnemonic returns a string."""
        scheme = bedrock.SignatureScheme.ecdsa_secp256k1()
        wallet = bedrock.HhdWallet.new([scheme])
        mnemonic = wallet.mnemonic()
        assert isinstance(mnemonic, str)
        assert len(mnemonic) > 0

    def test_mnemonic_has_words(self):
        """Test that mnemonic contains multiple words."""
        scheme = bedrock.SignatureScheme.ecdsa_secp256k1()
        wallet = bedrock.HhdWallet.new([scheme])
        mnemonic = wallet.mnemonic()
        words = mnemonic.split()
        # BIP-39 mnemonics are typically 12, 15, 18, 21, or 24 words
        assert len(words) >= 12

    def test_new_from_mnemonic(self):
        """Test creating wallet from existing mnemonic."""
        # First create a wallet to get a valid mnemonic
        scheme = bedrock.SignatureScheme.ecdsa_secp256k1()
        original_wallet = bedrock.HhdWallet.new([scheme])
        mnemonic = original_wallet.mnemonic()

        # Create new wallet from the mnemonic
        restored_wallet = bedrock.HhdWallet.new_from_mnemonic(mnemonic, [scheme])
        assert restored_wallet is not None
        assert restored_wallet.mnemonic() == mnemonic

    def test_new_from_mnemonic_with_password(self):
        """Test creating wallet from mnemonic with password."""
        scheme = bedrock.SignatureScheme.ecdsa_secp256k1()
        original_wallet = bedrock.HhdWallet.new([scheme], password="secret")
        mnemonic = original_wallet.mnemonic()

        restored_wallet = bedrock.HhdWallet.new_from_mnemonic(
            mnemonic, [scheme], password="secret"
        )
        assert restored_wallet is not None

    def test_new_from_mnemonic_invalid(self):
        """Test that invalid mnemonic raises error."""
        scheme = bedrock.SignatureScheme.ecdsa_secp256k1()
        with pytest.raises(ValueError):
            bedrock.HhdWallet.new_from_mnemonic("invalid mnemonic phrase", [scheme])


class TestHhdWalletMasterSeeds:
    """Tests for HhdWallet master seeds."""

    def test_master_seeds_returns_dict(self):
        """Test that master_seeds returns a dictionary."""
        schemes = [
            bedrock.SignatureScheme.ecdsa_secp256k1(),
            bedrock.SignatureScheme.fn_dsa_512(),
        ]
        wallet = bedrock.HhdWallet.new(schemes)
        seeds = wallet.master_seeds()
        assert isinstance(seeds, dict)

    def test_master_seeds_has_entries_for_schemes(self):
        """Test that master_seeds has entries for each scheme."""
        schemes = [
            bedrock.SignatureScheme.ecdsa_secp256k1(),
            bedrock.SignatureScheme.fn_dsa_512(),
        ]
        wallet = bedrock.HhdWallet.new(schemes)
        seeds = wallet.master_seeds()
        assert len(seeds) == len(schemes)

    def test_master_seeds_values_are_bytes_or_list(self):
        """Test that master seed values are byte-like (bytes or list of ints)."""
        scheme = bedrock.SignatureScheme.ecdsa_secp256k1()
        wallet = bedrock.HhdWallet.new([scheme])
        seeds = wallet.master_seeds()
        for key, value in seeds.items():
            # PyO3 may return Vec<u8> as list or bytes
            assert isinstance(value, (bytes, list))
            assert len(value) > 0


class TestHhdWalletEcdsaDerivation:
    """Tests for ECDSA key derivation."""

    @pytest.fixture
    def wallet(self):
        """Create a wallet with ECDSA scheme for testing."""
        scheme = bedrock.SignatureScheme.ecdsa_secp256k1()
        return bedrock.HhdWallet.new([scheme])

    def test_derive_ecdsa_keypair(self, wallet):
        """Test deriving an ECDSA keypair."""
        keypair = wallet.derive_ecdsa_secp256k1_keypair(0)
        assert isinstance(keypair, dict)
        assert "secret_key" in keypair
        assert "public_key" in keypair

    def test_derive_ecdsa_keypair_keys_are_bytes_or_list(self, wallet):
        """Test that derived ECDSA keys are byte-like (bytes or list of ints)."""
        keypair = wallet.derive_ecdsa_secp256k1_keypair(0)
        # PyO3 may return Vec<u8> as list or bytes
        assert isinstance(keypair["secret_key"], (bytes, list))
        assert isinstance(keypair["public_key"], (bytes, list))
        # secp256k1 secret key is 32 bytes
        assert len(keypair["secret_key"]) == 32
        # Compressed public key is 33 bytes
        assert len(keypair["public_key"]) == 33

    def test_derive_ecdsa_different_indices(self, wallet):
        """Test that different indices produce different keys."""
        keypair0 = wallet.derive_ecdsa_secp256k1_keypair(0)
        keypair1 = wallet.derive_ecdsa_secp256k1_keypair(1)
        assert keypair0["secret_key"] != keypair1["secret_key"]
        assert keypair0["public_key"] != keypair1["public_key"]

    def test_derive_ecdsa_same_index_deterministic(self, wallet):
        """Test that same index produces same keys."""
        keypair1 = wallet.derive_ecdsa_secp256k1_keypair(42)
        keypair2 = wallet.derive_ecdsa_secp256k1_keypair(42)
        assert keypair1["secret_key"] == keypair2["secret_key"]
        assert keypair1["public_key"] == keypair2["public_key"]


class TestHhdWalletFalconDerivation:
    """Tests for Falcon (FN-DSA) key derivation."""

    @pytest.fixture
    def wallet(self):
        """Create a wallet with FN-DSA-512 scheme for testing."""
        scheme = bedrock.SignatureScheme.fn_dsa_512()
        return bedrock.HhdWallet.new([scheme])

    def test_derive_fn_dsa512_keypair(self, wallet):
        """Test deriving a Falcon DSA-512 keypair."""
        keypair = wallet.derive_fn_dsa512_keypair(0)
        assert keypair is not None

    def test_derive_fn_dsa512_has_keys(self, wallet):
        """Test that derived Falcon keypair has both keys."""
        keypair = wallet.derive_fn_dsa512_keypair(0)
        pk = keypair.public_key()
        sk = keypair.secret_key()
        assert pk is not None
        assert sk is not None

    def test_derive_fn_dsa512_different_indices(self, wallet):
        """Test that different indices produce different keys."""
        keypair0 = wallet.derive_fn_dsa512_keypair(0)
        keypair1 = wallet.derive_fn_dsa512_keypair(1)
        assert keypair0.public_key().to_string() != keypair1.public_key().to_string()

    def test_derive_fn_dsa512_same_index_deterministic(self, wallet):
        """Test that same index produces same keys."""
        keypair1 = wallet.derive_fn_dsa512_keypair(42)
        keypair2 = wallet.derive_fn_dsa512_keypair(42)
        assert keypair1.public_key().to_string() == keypair2.public_key().to_string()

    def test_derive_fn_dsa512_can_sign_verify(self, wallet):
        """Test that derived Falcon keys can sign and verify."""
        keypair = wallet.derive_fn_dsa512_keypair(0)
        scheme = bedrock.FalconScheme.dsa_512()
        message = b"Test message"

        signature = scheme.sign(message, keypair)
        pk = keypair.public_key()
        result = scheme.verify(message, signature, pk)
        assert result is True


class TestHhdWalletMlDsaDerivation:
    """Tests for ML-DSA key derivation."""

    def test_derive_ml_dsa44_keypair(self):
        """Test deriving an ML-DSA-44 keypair."""
        scheme = bedrock.SignatureScheme.ml_dsa_44()
        wallet = bedrock.HhdWallet.new([scheme])
        keypair = wallet.derive_ml_dsa44_keypair(0)
        assert keypair is not None
        assert keypair.public_key() is not None
        assert keypair.secret_key() is not None

    def test_derive_ml_dsa65_keypair(self):
        """Test deriving an ML-DSA-65 keypair."""
        scheme = bedrock.SignatureScheme.ml_dsa_65()
        wallet = bedrock.HhdWallet.new([scheme])
        keypair = wallet.derive_ml_dsa65_keypair(0)
        assert keypair is not None
        assert keypair.public_key() is not None
        assert keypair.secret_key() is not None

    def test_derive_ml_dsa87_keypair(self):
        """Test deriving an ML-DSA-87 keypair."""
        scheme = bedrock.SignatureScheme.ml_dsa_87()
        wallet = bedrock.HhdWallet.new([scheme])
        keypair = wallet.derive_ml_dsa87_keypair(0)
        assert keypair is not None
        assert keypair.public_key() is not None
        assert keypair.secret_key() is not None

    def test_derive_ml_dsa44_different_indices(self):
        """Test that different indices produce different ML-DSA-44 keys."""
        scheme = bedrock.SignatureScheme.ml_dsa_44()
        wallet = bedrock.HhdWallet.new([scheme])
        keypair0 = wallet.derive_ml_dsa44_keypair(0)
        keypair1 = wallet.derive_ml_dsa44_keypair(1)
        assert keypair0.public_key().to_string() != keypair1.public_key().to_string()

    def test_derive_ml_dsa44_same_index_deterministic(self):
        """Test that same index produces same ML-DSA-44 keys."""
        scheme = bedrock.SignatureScheme.ml_dsa_44()
        wallet = bedrock.HhdWallet.new([scheme])
        keypair1 = wallet.derive_ml_dsa44_keypair(42)
        keypair2 = wallet.derive_ml_dsa44_keypair(42)
        assert keypair1.public_key().to_string() == keypair2.public_key().to_string()

    def test_derive_ml_dsa44_can_sign_verify(self):
        """Test that derived ML-DSA-44 keys can sign and verify."""
        hhd_scheme = bedrock.SignatureScheme.ml_dsa_44()
        wallet = bedrock.HhdWallet.new([hhd_scheme])
        keypair = wallet.derive_ml_dsa44_keypair(0)

        dsa_scheme = bedrock.MlDsaScheme.dsa_44()
        message = b"Test message"

        signature = dsa_scheme.sign(message, keypair)
        pk = keypair.public_key()
        result = dsa_scheme.verify(message, signature, pk)
        assert result is True

    def test_derive_ml_dsa65_can_sign_verify(self):
        """Test that derived ML-DSA-65 keys can sign and verify."""
        hhd_scheme = bedrock.SignatureScheme.ml_dsa_65()
        wallet = bedrock.HhdWallet.new([hhd_scheme])
        keypair = wallet.derive_ml_dsa65_keypair(0)

        dsa_scheme = bedrock.MlDsaScheme.dsa_65()
        message = b"Test message"

        signature = dsa_scheme.sign(message, keypair)
        pk = keypair.public_key()
        result = dsa_scheme.verify(message, signature, pk)
        assert result is True

    def test_derive_ml_dsa87_can_sign_verify(self):
        """Test that derived ML-DSA-87 keys can sign and verify."""
        hhd_scheme = bedrock.SignatureScheme.ml_dsa_87()
        wallet = bedrock.HhdWallet.new([hhd_scheme])
        keypair = wallet.derive_ml_dsa87_keypair(0)

        dsa_scheme = bedrock.MlDsaScheme.dsa_87()
        message = b"Test message"

        signature = dsa_scheme.sign(message, keypair)
        pk = keypair.public_key()
        result = dsa_scheme.verify(message, signature, pk)
        assert result is True


class TestHhdWalletRestoration:
    """Tests for wallet restoration from mnemonic."""

    def test_restore_ecdsa_keys(self):
        """Test that restored wallet produces same ECDSA keys."""
        scheme = bedrock.SignatureScheme.ecdsa_secp256k1()
        original = bedrock.HhdWallet.new([scheme])
        mnemonic = original.mnemonic()

        restored = bedrock.HhdWallet.new_from_mnemonic(mnemonic, [scheme])

        orig_keypair = original.derive_ecdsa_secp256k1_keypair(0)
        rest_keypair = restored.derive_ecdsa_secp256k1_keypair(0)

        assert orig_keypair["secret_key"] == rest_keypair["secret_key"]
        assert orig_keypair["public_key"] == rest_keypair["public_key"]

    def test_restore_falcon_keys(self):
        """Test that restored wallet produces same Falcon keys."""
        scheme = bedrock.SignatureScheme.fn_dsa_512()
        original = bedrock.HhdWallet.new([scheme])
        mnemonic = original.mnemonic()

        restored = bedrock.HhdWallet.new_from_mnemonic(mnemonic, [scheme])

        orig_keypair = original.derive_fn_dsa512_keypair(0)
        rest_keypair = restored.derive_fn_dsa512_keypair(0)

        assert orig_keypair.public_key().to_string() == rest_keypair.public_key().to_string()

    def test_restore_ml_dsa_keys(self):
        """Test that restored wallet produces same ML-DSA keys."""
        scheme = bedrock.SignatureScheme.ml_dsa_44()
        original = bedrock.HhdWallet.new([scheme])
        mnemonic = original.mnemonic()

        restored = bedrock.HhdWallet.new_from_mnemonic(mnemonic, [scheme])

        orig_keypair = original.derive_ml_dsa44_keypair(0)
        rest_keypair = restored.derive_ml_dsa44_keypair(0)

        assert orig_keypair.public_key().to_string() == rest_keypair.public_key().to_string()


class TestHhdWalletMultiScheme:
    """Tests for wallets with multiple signature schemes."""

    def test_wallet_with_all_schemes(self):
        """Test creating wallet with all supported schemes."""
        schemes = [
            bedrock.SignatureScheme.ecdsa_secp256k1(),
            bedrock.SignatureScheme.fn_dsa_512(),
            bedrock.SignatureScheme.ml_dsa_44(),
            bedrock.SignatureScheme.ml_dsa_65(),
            bedrock.SignatureScheme.ml_dsa_87(),
        ]
        wallet = bedrock.HhdWallet.new(schemes)
        assert wallet is not None

        # Verify we can derive keys for each scheme type
        ecdsa_keys = wallet.derive_ecdsa_secp256k1_keypair(0)
        assert ecdsa_keys is not None

        falcon_keys = wallet.derive_fn_dsa512_keypair(0)
        assert falcon_keys is not None

        ml_dsa_keys = wallet.derive_ml_dsa44_keypair(0)
        assert ml_dsa_keys is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
