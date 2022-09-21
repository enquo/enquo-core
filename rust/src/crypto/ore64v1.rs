use ore_rs::{scheme::bit2::OREAES128, CipherText, Left, ORECipher, Right};
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
const ORE64v1_PRF_KEY_IDENTIFIER: &[u8] = b"OREv1.prf_key";
#[allow(non_upper_case_globals)]
const ORE64v1_PRP_KEY_IDENTIFIER: &[u8] = b"OREv1.prp_key";

impl ORE64v1 {
    pub fn new(plaintext: u64, _context: &[u8], field: &Field) -> Result<ORE64v1, Error> {
        let mut prf_key: [u8; 16] = Default::default();
        let mut prp_key: [u8; 16] = Default::default();

        prf_key.clone_from_slice(&field.subkey(ORE64v1_PRF_KEY_IDENTIFIER)?[0..16]);
        prp_key.clone_from_slice(&field.subkey(ORE64v1_PRP_KEY_IDENTIFIER)?[0..16]);

        let seed: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
        let cipher: OREAES128 = ORECipher::init(prf_key, prp_key, &seed).map_err(|e| {
            Error::EncryptionError(format!("Failed to initialize ORE cipher: {:?}", e))
        })?;
        let ore = OREAES128::encrypt(&cipher, &plaintext.to_be_bytes()).map_err(|e| {
            Error::EncryptionError(format!("Failed to encrypt ORE ciphertext: {:?}", e))
        })?;

        Ok(ORE64v1 {
            left: Some(ore.left.to_bytes()),
            right: ore.right.to_bytes(),
        })
    }

    fn ore_ciphertext(&self) -> CipherText<OREAES128, 8> {
        match &self.left {
            None => CipherText::<OREAES128, 8> {
                left: Left::<OREAES128, 8> {
                    f: [Default::default(); 8],
                    xt: [0; 8],
                },
                right: Right::<OREAES128, 8>::from_bytes(&self.right).unwrap(),
            },
            Some(l) => CipherText::<OREAES128, 8> {
                left: Left::<OREAES128, 8>::from_bytes(l).unwrap(),
                right: Right::<OREAES128, 8>::from_bytes(&self.right).unwrap(),
            },
        }
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
            let self_ore = self.ore_ciphertext();
            let other_ore = other.ore_ciphertext();

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
                Ordering::Equal => panic!("This isn't supposed to be able to happen!"),
                Ordering::Less => a <= b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_second_missing_left(a: u64, b: u64) -> bool {
            let ca = ORE64v1::new(a, b"test", &field()).unwrap();
            let mut cb = ORE64v1::new(b, b"test", &field()).unwrap();

            cb.left = None;

            match ca.cmp(&cb) {
                Ordering::Equal => panic!("This isn't supposed to be able to happen!"),
                Ordering::Less => a <= b,
                Ordering::Greater => a > b,
            }
        }
    }
}
