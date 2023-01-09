use cretrit::{aes128v1::ere, SerializableCipherText};
use serde::{Deserialize, Serialize};

use crate::{Error, Field};

#[derive(Debug, Serialize, Deserialize)]
pub struct ERE64v1 {
    #[serde(rename = "l", with = "serde_bytes")]
    pub left: Option<Vec<u8>>,
    #[serde(rename = "r", with = "serde_bytes")]
    pub right: Vec<u8>,
}

#[allow(non_upper_case_globals)]
const ERE64v1_KEY_IDENTIFIER: &[u8] = b"ERE64v1.key";

impl ERE64v1 {
    pub fn new(plaintext: u64, _context: &[u8], field: &Field) -> Result<ERE64v1, Error> {
        let cipher = Self::cipher(field)?;
        let ct = cipher.right_encrypt(plaintext.into()).map_err(|e| {
            Error::EncryptionError(format!("Failed to encrypt ERE ciphertext: {:?}", e))
        })?;

        Ok(ERE64v1 {
            left: None,
            right: ct.right.to_vec(),
        })
    }

    pub fn new_with_left(plaintext: u64, _context: &[u8], field: &Field) -> Result<ERE64v1, Error> {
        let cipher = Self::cipher(field)?;
        let ct = cipher.full_encrypt(plaintext.into()).map_err(|e| {
            Error::EncryptionError(format!("Failed to encrypt ERE ciphertext: {:?}", e))
        })?;

        Ok(ERE64v1 {
            left: Some(
                ct.left
                    .expect(
                        "CAN'T HAPPEN: cipher.full_encrypt returned ciphertext without left part!",
                    )
                    .to_vec(),
            ),
            right: ct.right.to_vec(),
        })
    }

    fn cipher(field: &Field) -> Result<ere::Cipher<16, 16>, Error> {
        let mut key: [u8; 16] = Default::default();

        key.clone_from_slice(&field.subkey(ERE64v1_KEY_IDENTIFIER)?[0..16]);

        ere::Cipher::<16, 16>::new(key).map_err(|e| {
            Error::EncryptionError(format!("Failed to initialize ERE cipher: {:?}", e))
        })
    }

    fn ciphertext(&self) -> Result<ere::CipherText<16, 16>, Error> {
        Ok(ere::CipherText::<16, 16> {
            left: match &self.left {
                None => None,
                Some(l) => Some(
                    ere::LeftCipherText::<16, 16>::from_slice(l)
                        .map_err(|e| Error::DecodingError(e.to_string()))?,
                ),
            },
            right: ere::RightCipherText::<16, 16>::from_slice(&self.right)
                .map_err(|e| Error::DecodingError(e.to_string()))?,
        })
    }
}

impl PartialEq for ERE64v1 {
    fn eq(&self, other: &Self) -> bool {
        if self.left.is_none() {
            if other.left.is_none() {
                panic!("Neither value in the comparison contains a left ERE ciphertext!");
            } else {
                // The left-hand operand needs to have a left ciphertext
                // in order for the comparison algorithm to do its
                // magic, so we'll just swap the call order and the
                // right answer will fall out.
                other == self
            }
        } else {
            let self_ere = self.ciphertext().unwrap();
            let other_ere = other.ciphertext().unwrap();

            self_ere == other_ere
        }
    }
}

impl Eq for ERE64v1 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{key_provider::Static, Field, Root};

    fn field() -> Field {
        Root::new(&Static::new(b"testkey"))
            .unwrap()
            .field(b"foo", b"bar")
            .unwrap()
    }

    quickcheck! {
        fn comparison(a: u64, b: u64) -> bool {
            let ca = ERE64v1::new_with_left(a, b"test", &field()).unwrap();
            let cb = ERE64v1::new_with_left(b, b"test", &field()).unwrap();

            (ca == cb) == (a == b)
        }

        fn comparison_first_missing_left(a: u64, b: u64) -> bool {
            let ca = ERE64v1::new(a, b"test", &field()).unwrap();
            let cb = ERE64v1::new_with_left(b, b"test", &field()).unwrap();

            (ca == cb) == (a == b)
        }

        fn comparison_second_missing_left(a: u64, b: u64) -> bool {
            let ca = ERE64v1::new_with_left(a, b"test", &field()).unwrap();
            let cb = ERE64v1::new(b, b"test", &field()).unwrap();

            (ca == cb) == (a == b)
        }
    }
}
