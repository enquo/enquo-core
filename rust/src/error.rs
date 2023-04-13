use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to encode value: {0}")]
    EncodingError(String),
    #[error("failed to decode value: {0}")]
    DecodingError(String),
    #[error("failed to encrypt value: {0}")]
    EncryptionError(String),
    #[error("failed to decrypt value: {0}")]
    DecryptionError(String),
    #[error("failed to derive key material: {0}")]
    KeyError(String),
    #[error("could not perform requested operation: {0}")]
    OperationError(String),
    #[error("failed to collate text string: {0}")]
    CollationError(String),
}
