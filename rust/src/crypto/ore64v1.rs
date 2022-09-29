use cretrit::{
    aes128v1::ore,
    SerializableCipherText,
};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

use crate::{Error, Field};

#[derive(Debug, Serialize, Deserialize)]
pub struct ORE64v1 {
    #[serde(rename = "l")]
    pub left: Option<Vec<u8>>,
    #[serde(rename = "r")]
    pub right: Vec<u8>,
}

#[allow(non_upper_case_globals)]
const ORE64v1_KEY_IDENTIFIER: &[u8] = b"ORE64v1.prf_key";

impl ORE64v1 {
    pub fn new(plaintext: u64, _context: &[u8], field: &Field) -> Result<ORE64v1, Error> {
        let mut key: [u8; 16] = Default::default();

        key.clone_from_slice(&field.subkey(ORE64v1_KEY_IDENTIFIER)?[0..16]);

        let cipher = ore::Cipher::<8, 256>::new(key).map_err(|e| {
            Error::EncryptionError(format!("Failed to initialize ORE cipher: {:?}", e))
        })?;
        let ct = cipher.encrypt(plaintext.into()).map_err(|e| {
            Error::EncryptionError(format!("Failed to encrypt ORE ciphertext: {:?}", e))
        })?;

        Ok(ORE64v1 {
            left: Some(ct.left.expect("CAN'T HAPPEN: cipher.encrypt returned ciphertext without left part!").to_vec()),
            right: ct.right.to_vec(),
        })
    }

    fn ciphertext(&self) -> Result<ore::CipherText<8, 256>, Error> {
        Ok(ore::CipherText::<8, 256> {
            left: match &self.left {
                None => None,
                Some(l) => Some(ore::LeftCipherText::<8, 256>::from_slice(&l).map_err(|e| Error::DecodingError(e.to_string()))?),
            },
            right: ore::RightCipherText::<8, 256>::from_slice(&self.right).map_err(|e| Error::DecodingError(e.to_string()))?,
        })
    }
}

impl Ord for ORE64v1 {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.left == None {
            if other.left == None {
                panic!("Neither value in the comparison contains a left ORE ciphertext!");
            } else {
                // The left-hand operand needs to have a left ciphertext
                // in order for the ORE comparison algorithm to do its
                // magic, so we'll swap call order and result to get the
                // right answer
                match other.cmp(self) {
                    Ordering::Equal => Ordering::Equal,
                    Ordering::Less => Ordering::Greater,
                    Ordering::Greater => Ordering::Less,
                }
            }
        } else {
            let self_ore = self.ciphertext().unwrap();
            let other_ore = other.ciphertext().unwrap();

            self_ore.cmp(&other_ore)
        }
    }
}

impl PartialOrd for ORE64v1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ORE64v1 {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for ORE64v1 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Field, Root};

    fn field() -> Field {
        let rk: &[u8] = b"testkey";
        Root::new(&rk).unwrap().field(b"foo", b"bar").unwrap()
    }

    quickcheck! {
        fn comparison(a: u64, b: u64) -> bool {
            let ca = ORE64v1::new(a, b"test", &field()).unwrap();
            let cb = ORE64v1::new(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_first_missing_left(a: u64, b: u64) -> bool {
            let mut ca = ORE64v1::new(a, b"test", &field()).unwrap();
            let cb = ORE64v1::new(b, b"test", &field()).unwrap();

            ca.left = None;

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_second_missing_left(a: u64, b: u64) -> bool {
            let ca = ORE64v1::new(a, b"test", &field()).unwrap();
            let mut cb = ORE64v1::new(b, b"test", &field()).unwrap();

            cb.left = None;

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }
    }
}
