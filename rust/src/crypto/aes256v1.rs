//! Our means of safely encrypting arbitrary data
//!

use aes_gcm_siv::{aead::Aead, aead::Payload, Aes256GcmSiv, KeyInit, Nonce};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaChaRng,
};
use serde::{Deserialize, Serialize};

use crate::{Error, Field};

/// An AES-256 encrypted byte sequence
#[derive(Debug, Serialize, Deserialize, Clone)]
#[doc(hidden)]
pub struct AES256v1 {
    /// The nonce, IV, what-have-you, for the encryption
    #[serde(rename = "iv", with = "serde_bytes")]
    nonce: Vec<u8>,
    /// The actual encrypted data
    #[serde(rename = "ct", with = "serde_bytes")]
    ciphertext: Vec<u8>,
}

/// The identifier for the field subkey used for encryption
#[allow(non_upper_case_globals)]
const AES256v1_KEY_IDENTIFIER: &[u8] = b"AES256v1_key";

impl AES256v1 {
    /// Encrypt the plaintext using the given `field`, bound by AEAD to the `context`
    pub(crate) fn new(plaintext: &[u8], context: &[u8], field: &Field) -> Result<AES256v1, Error> {
        let mut key: aes_gcm_siv::Key<Aes256GcmSiv> = Default::default();
        field.subkey(&mut key, AES256v1_KEY_IDENTIFIER)?;
        let cipher = Aes256GcmSiv::new(&key);

        let mut rng = ChaChaRng::from_entropy();
        let mut nonce: Nonce = Default::default();
        rng.try_fill_bytes(&mut nonce).map_err(|e| {
            Error::OperationError(format!("failed to generate nonce for AES256v1: {e}"))
        })?;

        let ct = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: context,
                },
            )
            .map_err(|e| {
                Error::EncryptionError(format!("failed to AES256-encrypt plaintext ({e})"))
            })?;

        Ok(AES256v1 {
            nonce: nonce.to_vec(),
            ciphertext: ct,
        })
    }

    /// (Attempt to) decrypt the ciphertext back into a plaintext, validating that the `context`
    /// matches that given when the ciphertext was created
    pub(crate) fn decrypt(&self, context: &[u8], field: &Field) -> Result<Vec<u8>, Error> {
        let mut key: aes_gcm_siv::Key<Aes256GcmSiv> = Default::default();
        field.subkey(&mut key, AES256v1_KEY_IDENTIFIER)?;
        let cipher = Aes256GcmSiv::new(&key);

        cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: context,
                },
            )
            .map_err(|e| {
                Error::DecryptionError(format!("failed to decrypt AES256 ciphertext ({e})"))
            })
    }
}
