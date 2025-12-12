use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

// ML-DSA scheme integer constants
pub const ML_DSA_44: u8 = 1;
pub const ML_DSA_65: u8 = 2;
pub const ML_DSA_87: u8 = 3;

// ML-DSA scheme string constants
pub const ML_DSA_44_STR: &str = "ML-DSA-44";
pub const ML_DSA_65_STR: &str = "ML-DSA-65";
pub const ML_DSA_87_STR: &str = "ML-DSA-87";

#[pyclass]
#[repr(transparent)]
pub struct MlDsaScheme(bedrock::ml_dsa::MlDsaScheme);

#[pymethods]
impl MlDsaScheme {
    // Class constants for scheme integer values
    #[classattr]
    const DSA_44: u8 = ML_DSA_44;
    #[classattr]
    const DSA_65: u8 = ML_DSA_65;
    #[classattr]
    const DSA_87: u8 = ML_DSA_87;

    // Class constants for scheme string names
    #[classattr]
    const DSA_44_STR: &'static str = ML_DSA_44_STR;
    #[classattr]
    const DSA_65_STR: &'static str = ML_DSA_65_STR;
    #[classattr]
    const DSA_87_STR: &'static str = ML_DSA_87_STR;

    #[staticmethod]
    pub fn new() -> Self {
        Self(bedrock::ml_dsa::MlDsaScheme::default())
    }

    /// Create a MlDsaScheme for ML-DSA-44
    #[staticmethod]
    pub fn dsa_44() -> PyResult<Self> {
        Self::try_from(ML_DSA_44)
    }

    /// Create a MlDsaScheme for ML-DSA-65
    #[staticmethod]
    pub fn dsa_65() -> PyResult<Self> {
        Self::try_from(ML_DSA_65)
    }

    /// Create a MlDsaScheme for ML-DSA-87
    #[staticmethod]
    pub fn dsa_87() -> PyResult<Self> {
        Self::try_from(ML_DSA_87)
    }

    #[staticmethod]
    pub fn try_from(scheme: u8) -> PyResult<Self> {
        bedrock::ml_dsa::MlDsaScheme::try_from(scheme)
            .map(Self)
            .map_err(|_| PyValueError::new_err("Invalid scheme"))
    }

    #[staticmethod]
    pub fn parse(scheme: &str) -> PyResult<Self> {
        scheme
            .parse()
            .map(Self)
            .map_err(|_| PyValueError::new_err("Invalid scheme"))
    }

    pub fn to_int(&self) -> u8 {
        self.0.into()
    }

    pub fn to_string(&self) -> String {
        self.0.to_string()
    }

    #[cfg(feature = "kgen")]
    pub fn keypair(&self) -> PyResult<MlDsaKeyPair> {
        let (pk, sk) = self
            .0
            .keypair()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(MlDsaKeyPair {
            public_key: pk,
            secret_key: Some(sk),
        })
    }

    #[cfg(feature = "kgen")]
    pub fn keypair_from_seed(&self, seed: &[u8]) -> PyResult<MlDsaKeyPair> {
        let (pk, sk) = self
            .0
            .keypair_from_seed(seed)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(MlDsaKeyPair {
            public_key: pk,
            secret_key: Some(sk),
        })
    }

    #[cfg(feature = "sign")]
    pub fn sign(&self, message: &[u8], keypair: &MlDsaKeyPair) -> PyResult<MlDsaSignature> {
        if let Some(sk) = &keypair.secret_key {
            sk.scheme()
                .sign(message, &sk)
                .map(MlDsaSignature)
                .map_err(|e| PyValueError::new_err(e.to_string()))
        } else {
            Err(PyValueError::new_err(
                "Key pair does not contain a signing key",
            ))
        }
    }

    #[cfg(feature = "vrfy")]
    pub fn verify(
        &self,
        message: &[u8],
        signature: &MlDsaSignature,
        pk: &MlDsaVerificationKey,
    ) -> PyResult<bool> {
        pk.0.scheme()
            .verify(message, &signature.0, &pk.0)
            .map(|_| true)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[pyclass]
pub struct MlDsaKeyPair {
    pub(crate) public_key: bedrock::ml_dsa::MlDsaVerificationKey,
    pub(crate) secret_key: Option<bedrock::ml_dsa::MlDsaSigningKey>,
}

#[pymethods]
impl MlDsaKeyPair {
    #[staticmethod]
    pub fn parse(s: &str) -> PyResult<Self> {
        serde_json::from_str(s).map_err(|e| PyValueError::new_err(e.to_string()))
    }

    #[staticmethod]
    pub fn with_public_key(pk: &MlDsaVerificationKey) -> Self {
        Self {
            public_key: pk.0.clone(),
            secret_key: None,
        }
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(&self).expect("Failed to serialize ML-DSA key pair")
    }

    pub fn public_key(&self) -> MlDsaVerificationKey {
        MlDsaVerificationKey(self.public_key.clone())
    }

    pub fn secret_key(&self) -> Option<MlDsaSigningKey> {
        self.secret_key.clone().map(MlDsaSigningKey)
    }
}

#[derive(Debug)]
#[pyclass]
#[repr(transparent)]
pub struct MlDsaVerificationKey(pub(crate) bedrock::ml_dsa::MlDsaVerificationKey);

#[pymethods]
impl MlDsaVerificationKey {
    #[staticmethod]
    pub fn parse(s: &str) -> PyResult<Self> {
        serde_json::from_str(s)
            .map(Self)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(&self.0).expect("Failed to serialize ML-DSA verification key")
    }
}

#[derive(Debug)]
#[pyclass]
#[repr(transparent)]
pub struct MlDsaSigningKey(pub(crate) bedrock::ml_dsa::MlDsaSigningKey);

#[pymethods]
impl MlDsaSigningKey {
    #[staticmethod]
    pub fn parse(s: &str) -> PyResult<Self> {
        serde_json::from_str(s)
            .map(Self)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(&self.0).expect("Failed to serialize ML-DSA signing key")
    }
}

#[derive(Debug)]
#[pyclass]
#[repr(transparent)]
pub struct MlDsaSignature(pub(crate) bedrock::ml_dsa::MlDsaSignature);

#[pymethods]
impl MlDsaSignature {
    #[staticmethod]
    pub fn parse(s: &str) -> PyResult<Self> {
        serde_json::from_str(s)
            .map(Self)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(&self.0).expect("Failed to serialize ML-DSA signature")
    }
}
