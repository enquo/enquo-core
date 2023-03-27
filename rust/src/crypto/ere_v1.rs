use cretrit::{aes128v1::ere, PlainText, SerializableCipherText};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use crate::{Error, Field};

#[derive(Debug, Serialize, Deserialize)]
pub struct EREv1<const N: usize, const W: u16, T> {
    #[serde(rename = "l", with = "serde_bytes")]
    pub left: Option<Vec<u8>>,
    #[serde(rename = "r", with = "serde_bytes")]
    pub right: Vec<u8>,

    oooh: PhantomData<T>,
}

#[allow(non_upper_case_globals)]
const EREv1_KEY_IDENTIFIER: &[u8] = b"EREv1.key";

impl<const N: usize, const W: u16, T> EREv1<N, W, T>
where
    PlainText<N, W>: From<T>,
{
    pub fn new(plaintext: T, _context: &[u8], field: &Field) -> Result<EREv1<N, W, T>, Error> {
        let cipher = Self::cipher(field)?;
        let ct = cipher.right_encrypt(plaintext.into()).map_err(|e| {
            Error::EncryptionError(format!("Failed to encrypt ERE ciphertext: {e:?}"))
        })?;

        Ok(EREv1::<N, W, T> {
            left: None,
            right: ct.right.to_vec(),
            oooh: PhantomData,
        })
    }

    pub fn new_with_left(
        plaintext: T,
        _context: &[u8],
        field: &Field,
    ) -> Result<EREv1<N, W, T>, Error> {
        let cipher = Self::cipher(field)?;
        let ct = cipher.full_encrypt(plaintext.into()).map_err(|e| {
            Error::EncryptionError(format!("Failed to encrypt ERE ciphertext: {e:?}"))
        })?;

        Ok(EREv1::<N, W, T> {
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

    fn cipher(field: &Field) -> Result<ere::Cipher<N, W>, Error> {
        let mut key: [u8; 16] = Default::default();

        key.clone_from_slice(&field.subkey(EREv1_KEY_IDENTIFIER)?[0..16]);

        ere::Cipher::<N, W>::new(key)
            .map_err(|e| Error::EncryptionError(format!("Failed to initialize ERE cipher: {e:?}")))
    }

    fn ciphertext(&self) -> Result<ere::CipherText<N, W>, Error> {
        Ok(ere::CipherText::<N, W> {
            left: match &self.left {
                None => None,
                Some(l) => Some(
                    ere::LeftCipherText::<N, W>::from_slice(l)
                        .map_err(|e| Error::DecodingError(e.to_string()))?,
                ),
            },
            right: ere::RightCipherText::<N, W>::from_slice(&self.right)
                .map_err(|e| Error::DecodingError(e.to_string()))?,
        })
    }
}

impl<const N: usize, const W: u16, T> PartialEq for EREv1<N, W, T>
where
    PlainText<N, W>: From<T>,
{
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

impl<const N: usize, const W: u16, T> Eq for EREv1<N, W, T> where PlainText<N, W>: From<T> {}

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
            let ca = EREv1::<16, 16, u64>::new_with_left(a, b"test", &field()).unwrap();
            let cb = EREv1::<16, 16, u64>::new_with_left(b, b"test", &field()).unwrap();

            (ca == cb) == (a == b)
        }

        fn comparison_u64_first_missing_left(a: u64, b: u64) -> bool {
            let ca = EREv1::<16, 16, u64>::new(a, b"test", &field()).unwrap();
            let cb = EREv1::<16, 16, u64>::new_with_left(b, b"test", &field()).unwrap();

            (ca == cb) == (a == b)
        }

        fn comparison_u64_second_missing_left(a: u64, b: u64) -> bool {
            let ca = EREv1::<16, 16, u64>::new_with_left(a, b"test", &field()).unwrap();
            let cb = EREv1::<16, 16, u64>::new(b, b"test", &field()).unwrap();

            (ca == cb) == (a == b)
        }
    }
}
