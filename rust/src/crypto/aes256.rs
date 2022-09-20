use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::aes256v1::AES256v1;
use crate::Field;

#[derive(Debug, Serialize, Deserialize)]
pub enum AES256 {
    #[allow(non_camel_case_types)]
    v1(AES256v1),
}

#[derive(Debug, Error)]
pub enum AES256Error {
    #[error("{0}")]
    EncryptionError(String),
    #[error("{0}")]
    DecryptionError(String),
}

impl AES256 {
    pub fn new(plaintext: &[u8], context: &[u8], field: &Field) -> Result<AES256, AES256Error> {
        Ok(AES256::v1(AES256v1::new(plaintext, context, field)?))
    }

    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<Vec<u8>, AES256Error> {
        match self {
            AES256::v1(a) => a.decrypt(context, field),
        }
    }
}
