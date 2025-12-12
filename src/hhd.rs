use crate::{falcon::FalconKeyPair, ml_dsa::MlDsaKeyPair};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

#[pyclass]
#[repr(transparent)]
pub struct HhdWallet(bedrock::hhd::HHDWallet);

#[pymethods]
impl HhdWallet {
    #[staticmethod]
    #[pyo3(signature = (schemes, password=None))]
    pub fn new(schemes: Vec<PyRef<'_, SignatureScheme>>, password: Option<&str>) -> PyResult<Self> {
        let schemes = schemes.iter().map(|scheme| scheme.0).collect::<Vec<_>>();
        bedrock::hhd::HHDWallet::new(schemes, password)
            .map(Self)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    #[staticmethod]
    #[pyo3(signature = (mnemonic, schemes, password=None))]
    pub fn new_from_mnemonic(
        mnemonic: &str,
        schemes: Vec<PyRef<'_, SignatureScheme>>,
        password: Option<&str>,
    ) -> PyResult<Self> {
        let mnemonic = bedrock::hhd::Mnemonic::from_phrase(mnemonic)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let schemes = schemes.iter().map(|scheme| scheme.0).collect::<Vec<_>>();
        bedrock::hhd::HHDWallet::new_from_mnemonic(mnemonic, schemes, password)
            .map(Self)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    pub fn mnemonic(&self) -> String {
        self.0.mnemonic().to_phrase().to_string()
    }

    pub fn master_seeds<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new_bound(py);
        for (scheme, seed) in self.0.master_seeds().iter() {
            let key = SignatureScheme(*scheme).into_py(py);
            let value = seed.as_seed().as_bytes().to_vec().into_py(py);
            dict.set_item(key, value)?;
        }
        Ok(dict)
    }

    pub fn derive_ecdsa_secp256k1_keypair<'py>(
        &self,
        index: u32,
        py: Python<'py>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new_bound(py);
        let (secret_key, public_key) = self
            .0
            .derive_ecdsa_secp256k1_keypair(index)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        dict.set_item("secret_key", secret_key.to_bytes().to_vec())?;
        dict.set_item(
            "public_key",
            public_key.to_encoded_point(true).as_bytes().to_vec(),
        )?;
        Ok(dict)
    }

    pub fn derive_fn_dsa512_keypair(&self, index: u32) -> PyResult<FalconKeyPair> {
        let (secret_key, public_key) = self
            .0
            .derive_fn_dsa512_keypair(index)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(FalconKeyPair {
            public_key,
            secret_key: Some(secret_key),
        })
    }

    pub fn derive_ml_dsa44_keypair(&self, index: u32) -> PyResult<MlDsaKeyPair> {
        let (secret_key, public_key) = self
            .0
            .derive_mldsa44_keypair(index)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(MlDsaKeyPair {
            public_key,
            secret_key: Some(secret_key),
        })
    }

    pub fn derive_ml_dsa65_keypair(&self, index: u32) -> PyResult<MlDsaKeyPair> {
        let (secret_key, public_key) = self
            .0
            .derive_mldsa65_keypair(index)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(MlDsaKeyPair {
            public_key,
            secret_key: Some(secret_key),
        })
    }

    pub fn derive_ml_dsa87_keypair(&self, index: u32) -> PyResult<MlDsaKeyPair> {
        let (secret_key, public_key) = self
            .0
            .derive_mldsa87_keypair(index)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(MlDsaKeyPair {
            public_key,
            secret_key: Some(secret_key),
        })
    }
}

#[derive(Debug, Clone)]
#[pyclass]
#[repr(transparent)]
pub struct SignatureScheme(pub(crate) bedrock::hhd::SignatureScheme);

#[pymethods]
impl SignatureScheme {
    /// Create an ECDSA secp256k1 signature scheme
    #[staticmethod]
    pub fn ecdsa_secp256k1() -> Self {
        Self(bedrock::hhd::SignatureScheme::EcdsaSecp256k1)
    }

    /// Create an FN-DSA-512 (Falcon) signature scheme
    #[staticmethod]
    pub fn fn_dsa_512() -> Self {
        Self(bedrock::hhd::SignatureScheme::Falcon512)
    }

    /// Create an ML-DSA-44 signature scheme
    #[staticmethod]
    pub fn ml_dsa_44() -> Self {
        Self(bedrock::hhd::SignatureScheme::MlDsa44)
    }

    /// Create an ML-DSA-65 signature scheme
    #[staticmethod]
    pub fn ml_dsa_65() -> Self {
        Self(bedrock::hhd::SignatureScheme::MlDsa65)
    }

    /// Create an ML-DSA-87 signature scheme
    #[staticmethod]
    pub fn ml_dsa_87() -> Self {
        Self(bedrock::hhd::SignatureScheme::MlDsa87)
    }

    pub fn to_string(&self) -> String {
        format!("{:?}", self.0)
    }
}
