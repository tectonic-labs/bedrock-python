use pyo3::prelude::*;

#[cfg(any(feature = "eth-falcon", feature = "fn-dsa", feature = "hhd"))]
mod falcon;

#[cfg(any(feature = "eth-falcon", feature = "fn-dsa", feature = "hhd"))]
pub use falcon::*;

#[cfg(any(feature = "ml-dsa", feature = "hhd"))]
mod ml_dsa;

#[cfg(any(feature = "ml-dsa", feature = "hhd"))]
pub use ml_dsa::*;

#[cfg(feature = "hhd")]
mod hhd;

#[cfg(feature = "hhd")]
pub use hhd::*;

#[pymodule]
fn bedrock_python(m: &Bound<'_, PyModule>) -> PyResult<()> {
    #[cfg(any(feature = "eth-falcon", feature = "fn-dsa", feature = "hhd"))]
    {
        // Falcon scheme integer constants
        m.add("FALCON_DSA_512", falcon::FALCON_DSA_512)?;
        m.add("FALCON_DSA_1024", falcon::FALCON_DSA_1024)?;
        m.add("FALCON_ETHEREUM", falcon::FALCON_ETHEREUM)?;

        // Falcon scheme string constants
        m.add("FALCON_DSA_512_STR", falcon::FALCON_DSA_512_STR)?;
        m.add("FALCON_DSA_1024_STR", falcon::FALCON_DSA_1024_STR)?;
        m.add("FALCON_ETHEREUM_STR", falcon::FALCON_ETHEREUM_STR)?;

        // Falcon classes
        m.add_class::<FalconScheme>()?;
        m.add_class::<FalconKeyPair>()?;
        m.add_class::<FalconVerificationKey>()?;
        m.add_class::<FalconSigningKey>()?;
        m.add_class::<FalconSignature>()?;
    }

    #[cfg(any(feature = "ml-dsa", feature = "hhd"))]
    {
        // ML-DSA scheme integer constants
        m.add("ML_DSA_44", ml_dsa::ML_DSA_44)?;
        m.add("ML_DSA_65", ml_dsa::ML_DSA_65)?;
        m.add("ML_DSA_87", ml_dsa::ML_DSA_87)?;

        // ML-DSA scheme string constants
        m.add("ML_DSA_44_STR", ml_dsa::ML_DSA_44_STR)?;
        m.add("ML_DSA_65_STR", ml_dsa::ML_DSA_65_STR)?;
        m.add("ML_DSA_87_STR", ml_dsa::ML_DSA_87_STR)?;

        // ML-DSA classes
        m.add_class::<MlDsaScheme>()?;
        m.add_class::<MlDsaKeyPair>()?;
        m.add_class::<MlDsaVerificationKey>()?;
        m.add_class::<MlDsaSigningKey>()?;
        m.add_class::<MlDsaSignature>()?;
    }

    #[cfg(feature = "hhd")]
    {
        // HHD classes
        m.add_class::<HhdWallet>()?;
        m.add_class::<hhd::SignatureScheme>()?;
    }

    Ok(())
}
