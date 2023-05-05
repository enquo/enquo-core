//! Where the wild things are
//!

use thiserror::Error;

/// All the different kinds of problems that can occur in Enquo.
#[derive(Error, Debug)]
#[non_exhaustive]
#[allow(missing_docs, clippy::missing_docs_in_private_items)] // if the error name and description don't explain it, a one-line comment isn't going to help either
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
    #[error("value was not within the valid range for the plaintext type: {0}")]
    RangeError(String),
    #[error("could not perform requested operation: {0}")]
    OperationError(String),
    #[error("failed to collate text string: {0}")]
    CollationError(String),
    #[error("overflow detected {0}")]
    OverflowError(String),
    #[error("attempted operation on data value with Unknown version")]
    UnknownVersionError(),
}
