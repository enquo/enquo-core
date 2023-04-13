use cretrit::{aes128v1::ore, PlainText, SerializableCipherText};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::cmp::Ordering;
use std::marker::PhantomData;

use crate::{Error, Field};

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OREv1<const N: usize, const W: u16, T> {
    #[serde(rename = "l", with = "serde_bytes", default)]
    pub(crate) left: Option<Vec<u8>>,
    #[serde(rename = "r", with = "serde_bytes")]
    pub(crate) right: Vec<u8>,

    #[serde(skip)]
    oooh: PhantomData<T>,
}

impl<const N: usize, const W: u16, T> OREv1<N, W, T>
where
    PlainText<N, W>: From<T>,
{
    pub fn new(plaintext: T, subkey_id: &[u8], field: &Field) -> Result<OREv1<N, W, T>, Error> {
        let cipher = Self::cipher(subkey_id, field)?;
        let ct = cipher.right_encrypt(plaintext.into()).map_err(|e| {
            Error::EncryptionError(format!("Failed to encrypt ORE ciphertext: {e:?}"))
        })?;

        Ok(OREv1::<N, W, T> {
            left: None,
            right: ct.right.to_vec(),
            oooh: PhantomData,
        })
    }

    pub fn new_with_left(
        plaintext: T,
        subkey_id: &[u8],
        field: &Field,
    ) -> Result<OREv1<N, W, T>, Error> {
        let cipher = Self::cipher(subkey_id, field)?;
        let ct = cipher.full_encrypt(plaintext.into()).map_err(|e| {
            Error::EncryptionError(format!("Failed to encrypt ORE ciphertext: {e:?}"))
        })?;

        Ok(OREv1::<N, W, T> {
            left: Some(
                ct.left
                    .expect(
                        "CAN'T HAPPEN: cipher.full_encrypt returned ciphertext without left part!",
                    )
                    .to_vec(),
            ),
            right: ct.right.to_vec(),
            oooh: PhantomData,
        })
    }

    fn cipher(subkey_id: &[u8], field: &Field) -> Result<ore::Cipher<N, W>, Error> {
        let mut key: [u8; 16] = Default::default();

        key.clone_from_slice(&field.subkey(subkey_id)?[0..16]);

        ore::Cipher::<N, W>::new(key)
            .map_err(|e| Error::EncryptionError(format!("Failed to initialize ORE cipher: {e:?}")))
    }

    fn ciphertext(&self) -> Result<ore::CipherText<N, W>, Error> {
        Ok(ore::CipherText::<N, W> {
            left: match &self.left {
                None => None,
                Some(l) => Some(
                    ore::LeftCipherText::<N, W>::from_slice(l)
                        .map_err(|e| Error::DecodingError(e.to_string()))?,
                ),
            },
            right: ore::RightCipherText::<N, W>::from_slice(&self.right)
                .map_err(|e| Error::DecodingError(e.to_string()))?,
        })
    }
}

impl<const N: usize, const W: u16, T> Ord for OREv1<N, W, T>
where
    PlainText<N, W>: From<T>,
{
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

impl<const N: usize, const W: u16, T> PartialOrd for OREv1<N, W, T>
where
    PlainText<N, W>: From<T>,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize, const W: u16, T> PartialEq for OREv1<N, W, T>
where
    PlainText<N, W>: From<T>,
{
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl<const N: usize, const W: u16, T> Eq for OREv1<N, W, T> where PlainText<N, W>: From<T> {}

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
        fn comparison_u64(a: u64, b: u64) -> bool {
            let ca = OREv1::<8, 256, u64>::new_with_left(a, b"test", &field()).unwrap();
            let cb = OREv1::<8, 256, u64>::new_with_left(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_u32(a: u32, b: u32) -> bool {
            let ca = OREv1::<4, 256, u32>::new_with_left(a, b"test", &field()).unwrap();
            let cb = OREv1::<4, 256, u32>::new_with_left(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_u16(a: u16, b: u16) -> bool {
            let ca = OREv1::<2, 256, u16>::new_with_left(a, b"test", &field()).unwrap();
            let cb = OREv1::<2, 256, u16>::new_with_left(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_u8(a: u8, b: u8) -> bool {
            let ca = OREv1::<1, 256, u8>::new_with_left(a, b"test", &field()).unwrap();
            let cb = OREv1::<1, 256, u8>::new_with_left(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_bool(a: bool, b: bool) -> bool {
            let ca = OREv1::<1, 2, bool>::new_with_left(a, b"test", &field()).unwrap();
            let cb = OREv1::<1, 2, bool>::new_with_left(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_u64_first_missing_left(a: u64, b: u64) -> bool {
            let ca = OREv1::<8, 256, u64>::new(a, b"test", &field()).unwrap();
            let cb = OREv1::<8, 256, u64>::new_with_left(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_u64_second_missing_left(a: u64, b: u64) -> bool {
            let ca = OREv1::<8, 256, u64>::new_with_left(a, b"test", &field()).unwrap();
            let cb = OREv1::<8, 256, u64>::new(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }
    }
}
