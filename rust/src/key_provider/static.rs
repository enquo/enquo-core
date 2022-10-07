use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::KeyProvider;
use crate::Error;

#[derive(Clone)]
pub struct Static {
    pub key: Vec<u8>,
}

impl Static {
    pub fn new(key: &[u8]) -> Static {
        Static { key: key.to_vec() }
    }

    #[cfg(test)]
    pub fn key(&self) -> Vec<u8> {
        self.key.to_owned()
    }
}

impl KeyProvider for Static {
    fn derive_key(&self, id: &[u8]) -> Result<Vec<u8>, Error> {
        let mut keygen = Hmac::<Sha256>::new_from_slice(&self.key)
            .map_err(|_| Error::KeyError("Failed to create HMAC KBKDF instance".to_string()))?;
        keygen.update(id);

        Ok(keygen.finalize().into_bytes().to_vec())
    }
}
