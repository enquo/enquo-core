use aes_gcm_siv::{aead::Aead, aead::Payload, Aes256GcmSiv, KeyInit, Nonce};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaChaRng,
};
use serde::{Deserialize, Serialize};

use super::aes256::AES256Error;
use crate::Field;

#[derive(Debug, Serialize, Deserialize)]
pub struct AES256v1 {
    #[serde(rename = "iv")]
    nonce: Vec<u8>,
    #[serde(rename = "ct")]
    ciphertext: Vec<u8>,
}

#[allow(non_upper_case_globals)]
const AES256v1_KEY_IDENTIFIER: &[u8] = b"AES256v1_key";

impl AES256v1 {
    pub fn new(plaintext: &[u8], context: &[u8], field: &Field) -> Result<AES256v1, AES256Error> {
        let key: &[u8] = &field.subkey(AES256v1_KEY_IDENTIFIER);
        let cipher = Aes256GcmSiv::new(key.into());

        let mut rng = ChaChaRng::from_entropy();
        let mut nonce: Nonce = Default::default();
        rng.try_fill_bytes(&mut nonce).unwrap();

        let ct = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: context,
                },
            )
            .map_err(|_| AES256Error::EncryptionError("failed to encrypt plaintext".to_string()))?;

        Ok(AES256v1 {
            nonce: nonce.to_vec(),
            ciphertext: ct,
        })
    }

    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<Vec<u8>, AES256Error> {
        let key: &[u8] = &field.subkey(AES256v1_KEY_IDENTIFIER);
        let cipher = Aes256GcmSiv::new(key.into());

        cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: context,
                },
            )
            .map_err(|_| AES256Error::DecryptionError("failed to decrypt ciphertext".to_string()))
    }
}
