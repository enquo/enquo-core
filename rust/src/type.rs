use thiserror::Error;

mod i64;
mod i64v1;

pub use self::i64::I64;

#[derive(Debug, Error)]
pub enum TypeError {
    #[error("failed to encode value: {0}")]
    EncodingError(String),
    #[error("failed to decode value: {0}")]
    DecodingError(String),
    #[error("failed to convert value to encoded type: {0}")]
    ConversionError(String),
    #[error("failure while performing cryptographic operation: {0}")]
    CryptoError(String),
}
