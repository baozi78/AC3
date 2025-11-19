use thiserror::Error;

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Invalid credential")]
    InvalidCredential,

    #[error("Usage limit exceeded")]
    UsageLimitExceeded,

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Key generation error: {0}")]
    KeyGenError(String),

    #[error("Signature error: {0}")]
    SignatureError(String),

    #[error("Verification error: {0}")]
    VerificationError(String),

    #[error("Range proof error: {0}")]
    RangeProofError(String),

    #[error("Ursa error: {0}")]
    UrsaError(String),

    #[error("RSA error: {0}")]
    RsaError(String),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Invalid key size")]
    InvalidKeySize,

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Tag already used")]
    TagAlreadyUsed,

    #[error("Proof verification failed")]
    ProofVerificationFailed,
}

pub type Result<T> = std::result::Result<T, CredentialError>;
