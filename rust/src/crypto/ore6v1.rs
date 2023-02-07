use cretrit::{aes128v1::ore, SerializableCipherText};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

use crate::{Error, Field};

#[derive(Debug, Serialize, Deserialize)]
pub struct ORE6v1 {
    #[serde(rename = "l", with = "serde_bytes")]
    pub left: Option<Vec<u8>>,
    #[serde(rename = "r", with = "serde_bytes")]
    pub right: Vec<u8>,
}

#[allow(non_upper_case_globals)]
const ORE6v1_KEY_IDENTIFIER: &[u8] = b"ORE6v1.prf_key";

impl ORE6v1 {
    pub fn new(plaintext: u8, _context: &[u8], field: &Field) -> Result<ORE6v1, Error> {
        let cipher = Self::cipher(field)?;
        let ct = cipher.right_encrypt(plaintext.into()).map_err(|e| {
            Error::EncryptionError(format!("Failed to encrypt ORE ciphertext: {e:?}"))
        })?;

        Ok(ORE6v1 {
            left: None,
            right: ct.right.to_vec(),
        })
    }

    pub fn new_with_left(plaintext: u8, _context: &[u8], field: &Field) -> Result<ORE6v1, Error> {
        let cipher = Self::cipher(field)?;
        let ct = cipher.full_encrypt(plaintext.into()).map_err(|e| {
            Error::EncryptionError(format!("Failed to encrypt ORE ciphertext: {e:?}"))
        })?;

        Ok(ORE6v1 {
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

    fn cipher(field: &Field) -> Result<ore::Cipher<1, 32>, Error> {
        let mut key: [u8; 16] = Default::default();

        key.clone_from_slice(&field.subkey(ORE6v1_KEY_IDENTIFIER)?[0..16]);

        ore::Cipher::<1, 32>::new(key)
            .map_err(|e| Error::EncryptionError(format!("Failed to initialize ORE cipher: {e:?}")))
    }

    fn ciphertext(&self) -> Result<ore::CipherText<1, 32>, Error> {
        Ok(ore::CipherText::<1, 32> {
            left: match &self.left {
                None => None,
                Some(l) => Some(
                    ore::LeftCipherText::<1, 32>::from_slice(l)
                        .map_err(|e| Error::DecodingError(e.to_string()))?,
                ),
            },
            right: ore::RightCipherText::<1, 32>::from_slice(&self.right)
                .map_err(|e| Error::DecodingError(e.to_string()))?,
        })
    }
}

impl Ord for ORE6v1 {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.left.is_none() {
            if other.left.is_none() {
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

impl PartialOrd for ORE6v1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ORE6v1 {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for ORE6v1 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{key_provider::Static, Field, Root};
    use quickcheck::TestResult;

    fn field() -> Field {
        Root::new(&Static::new(b"testkey"))
            .unwrap()
            .field(b"foo", b"bar")
            .unwrap()
    }

    quickcheck! {
        fn comparison(a: u8, b: u8) -> TestResult {
            if a > 31 || b > 31 {
                return TestResult::discard();
            }

            let ca = ORE6v1::new_with_left(a, b"test", &field()).unwrap();
            let cb = ORE6v1::new_with_left(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => TestResult::from_bool(a == b),
                Ordering::Less => TestResult::from_bool(a < b),
                Ordering::Greater => TestResult::from_bool(a > b),
            }
        }

        fn comparison_first_missing_left(a: u8, b: u8) -> TestResult {
            if a > 31 || b > 31 {
                return TestResult::discard();
            }

            let ca = ORE6v1::new(a, b"test", &field()).unwrap();
            let cb = ORE6v1::new_with_left(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => TestResult::from_bool(a == b),
                Ordering::Less => TestResult::from_bool(a < b),
                Ordering::Greater => TestResult::from_bool(a > b),
            }
        }

        fn comparison_second_missing_left(a: u8, b: u8) -> TestResult {
            if a > 31 || b > 31 {
                return TestResult::discard();
            }

            let ca = ORE6v1::new_with_left(a, b"test", &field()).unwrap();
            let cb = ORE6v1::new(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => TestResult::from_bool(a == b),
                Ordering::Less => TestResult::from_bool(a < b),
                Ordering::Greater => TestResult::from_bool(a > b),
            }
        }
    }
}
