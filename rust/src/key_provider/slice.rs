use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::KeyProvider;
use crate::Error;

impl KeyProvider for &[u8] {
    fn derive_key(&self, id: &[u8]) -> Result<Vec<u8>, Error> {
        let k: &[u8] = self;
        let mut keygen = Hmac::<Sha256>::new_from_slice(k).unwrap();
        keygen.update(id);

        Ok(keygen.finalize().into_bytes().to_vec())
    }
}

impl KeyProvider for Vec<u8> {
    fn derive_key(&self, id: &[u8]) -> Result<Vec<u8>, Error> {
        let mut keygen = Hmac::<Sha256>::new_from_slice(self).unwrap();
        keygen.update(id);

        Ok(keygen.finalize().into_bytes().to_vec())
    }
}
