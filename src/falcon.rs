use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

// Falcon scheme integer constants
pub const FALCON_DSA_512: u8 = 1;
pub const FALCON_DSA_1024: u8 = 2;
pub const FALCON_ETHEREUM: u8 = 3;

// Falcon scheme string constants
pub const FALCON_DSA_512_STR: &str = "FN-DSA-512";
pub const FALCON_DSA_1024_STR: &str = "FN-DSA-1024";
pub const FALCON_ETHEREUM_STR: &str = "ETHFALCON";

#[pyclass]
#[repr(transparent)]
pub struct FalconScheme(bedrock::falcon::FalconScheme);

#[pymethods]
impl FalconScheme {
    // Class constants for scheme integer values
    #[classattr]
    const DSA_512: u8 = FALCON_DSA_512;
    #[classattr]
    const DSA_1024: u8 = FALCON_DSA_1024;
    #[classattr]
    const ETHEREUM: u8 = FALCON_ETHEREUM;

    // Class constants for scheme string names
    #[classattr]
    const DSA_512_STR: &'static str = FALCON_DSA_512_STR;
    #[classattr]
    const DSA_1024_STR: &'static str = FALCON_DSA_1024_STR;
    #[classattr]
    const ETHEREUM_STR: &'static str = FALCON_ETHEREUM_STR;

    #[staticmethod]
    pub fn new() -> Self {
        Self(bedrock::falcon::FalconScheme::default())
    }

    /// Create a FalconScheme for FN-DSA-512
    #[staticmethod]
    pub fn dsa_512() -> PyResult<Self> {
        Self::try_from(FALCON_DSA_512)
    }

    /// Create a FalconScheme for FN-DSA-1024
    #[staticmethod]
    pub fn dsa_1024() -> PyResult<Self> {
        Self::try_from(FALCON_DSA_1024)
    }

    /// Create a FalconScheme for Ethereum (ETHFALCON)
    #[staticmethod]
    pub fn ethereum() -> PyResult<Self> {
        Self::try_from(FALCON_ETHEREUM)
    }

    #[staticmethod]
    pub fn try_from(scheme: u8) -> PyResult<Self> {
        bedrock::falcon::FalconScheme::try_from(scheme)
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
    pub fn keypair(&self) -> PyResult<FalconKeyPair> {
        let (pk, sk) = self
            .0
            .keypair()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(FalconKeyPair {
            public_key: pk,
            secret_key: Some(sk),
        })
    }

    #[cfg(feature = "kgen")]
    pub fn keypair_from_seed(&self, seed: &[u8]) -> PyResult<FalconKeyPair> {
        let (pk, sk) = self
            .0
            .keypair_from_seed(seed)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(FalconKeyPair {
            public_key: pk,
            secret_key: Some(sk),
        })
    }

    #[cfg(feature = "sign")]
    pub fn sign(&self, message: &[u8], keypair: &FalconKeyPair) -> PyResult<FalconSignature> {
        if let Some(sk) = &keypair.secret_key {
            sk.scheme()
                .sign(message, &sk)
                .map(FalconSignature)
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
        signature: &FalconSignature,
        pk: &FalconVerificationKey,
    ) -> PyResult<bool> {
        pk.0.scheme()
            .verify(message, &signature.0, &pk.0)
            .map(|_| true)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[pyclass]
pub struct FalconKeyPair {
    pub(crate) public_key: bedrock::falcon::FalconVerificationKey,
    pub(crate) secret_key: Option<bedrock::falcon::FalconSigningKey>,
}

#[pymethods]
impl FalconKeyPair {
    #[staticmethod]
    pub fn parse(s: &str) -> PyResult<Self> {
        serde_json::from_str(s).map_err(|e| PyValueError::new_err(e.to_string()))
    }

    #[staticmethod]
    pub fn with_public_key(pk: &FalconVerificationKey) -> Self {
        Self {
            public_key: pk.0.clone(),
            secret_key: None,
        }
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(&self).expect("Failed to serialize Falcon key pair")
    }

    pub fn public_key(&self) -> FalconVerificationKey {
        FalconVerificationKey(self.public_key.clone())
    }

    pub fn secret_key(&self) -> Option<FalconSigningKey> {
        self.secret_key.clone().map(FalconSigningKey)
    }
}

#[derive(Debug)]
#[pyclass]
#[repr(transparent)]
pub struct FalconVerificationKey(pub(crate) bedrock::falcon::FalconVerificationKey);

#[pymethods]
impl FalconVerificationKey {
    #[staticmethod]
    pub fn parse(s: &str) -> PyResult<Self> {
        serde_json::from_str(s)
            .map(Self)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(&self.0).expect("Failed to serialize Falcon verification key")
    }
}

#[derive(Debug)]
#[pyclass]
#[repr(transparent)]
pub struct FalconSigningKey(pub(crate) bedrock::falcon::FalconSigningKey);

#[pymethods]
impl FalconSigningKey {
    #[staticmethod]
    pub fn parse(s: &str) -> PyResult<Self> {
        serde_json::from_str(s)
            .map(Self)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(&self.0).expect("Failed to serialize Falcon signing key")
    }
}

#[derive(Debug)]
#[pyclass]
#[repr(transparent)]
pub struct FalconSignature(pub(crate) bedrock::falcon::FalconSignature);

#[pymethods]
impl FalconSignature {
    #[staticmethod]
    pub fn parse(s: &str) -> PyResult<Self> {
        serde_json::from_str(s)
            .map(Self)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(&self.0).expect("Failed to serialize Falcon signature")
    }
}
