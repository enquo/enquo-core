//! Derives keys from locally provided key material.
//!

use cretrit::kbkdf::{KBKDFInit, CMACAES256, KBKDF};

use super::KeyProvider;
use crate::Error;

/// A straightforward means of generating keys from a locally provided key
///
/// Takes a 256 bit key as input, and uses a KBKDF to derive keys for any purpose to which you may
/// wish to use them.
///
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Static {
    /// The KDF we're using
    pub kdf: CMACAES256,
}

impl Static {
    /// Create a new Static key provider
    ///
    /// # Errors
    ///
    /// Can return an error if the key-derivation function fails to initialise.  Why this would
    /// happen, though, is a bit of a mystery.
    ///
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
