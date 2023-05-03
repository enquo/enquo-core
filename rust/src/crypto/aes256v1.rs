use aes_gcm_siv::{aead::Aead, aead::Payload, Aes256GcmSiv, KeyInit, Nonce};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaChaRng,
};
use serde::{Deserialize, Serialize};

use crate::{Error, Field};

#[derive(Debug, Serialize, Deserialize)]
pub struct AES256v1 {
    #[serde(rename = "iv", with = "serde_bytes")]
    nonce: Vec<u8>,
    #[serde(rename = "ct", with = "serde_bytes")]
    ciphertext: Vec<u8>,
}

#[allow(non_upper_case_globals)]
const AES256v1_KEY_IDENTIFIER: &[u8] = b"AES256v1_key";

impl AES256v1 {
    pub fn new(plaintext: &[u8], context: &[u8], field: &Field) -> Result<AES256v1, Error> {
        let mut key: aes_gcm_siv::Key<Aes256GcmSiv> = Default::default();
        field.subkey(&mut key, AES256v1_KEY_IDENTIFIER)?;
        let cipher = Aes256GcmSiv::new(&key);

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
            .map_err(|_| {
                Error::EncryptionError("failed to AES256-encrypt plaintext".to_string())
            })?;

        Ok(AES256v1 {
            nonce: nonce.to_vec(),
            ciphertext: ct,
        })
    }

    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<Vec<u8>, Error> {
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
            .map_err(|_| Error::DecryptionError("failed to decrypt AES256 ciphertext".to_string()))
    }
}
