use cretrit::kbkdf::{KBKDFInit, CMACAES256, KBKDF};

use super::KeyProvider;
use crate::Error;

#[derive(Clone)]
pub struct Static {
    pub kdf: CMACAES256,
}

impl Static {
    pub fn new(key: &[u8; 32]) -> Result<Static, Error> {
        Ok(Static {
            kdf: *CMACAES256::new(key).map_err(|e| Error::KeyError(e.to_string()))?,
        })
    }
}

impl KeyProvider for Static {
    fn derive_key(&self, subkey: &mut [u8], id: &[u8]) -> Result<(), Error> {
        self.kdf
            .derive_key(subkey, id)
            .map_err(|e| Error::KeyError(e.to_string()))
    }
}
