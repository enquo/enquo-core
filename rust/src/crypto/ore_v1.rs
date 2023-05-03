use cretrit::{aes128v1::ore, PlainText};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::cmp::Ordering;

use crate::{Error, Field};

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OREv1<const N: usize, const W: u16> {
    #[serde(rename = "o")]
    pub(crate) ore_ciphertext: ore::CipherText<N, W>,
}

impl<const N: usize, const W: u16> OREv1<N, W> {
    pub fn new<T>(plaintext: T, subkey_id: &[u8], field: &Field) -> Result<OREv1<N, W>, Error>
    where
        PlainText<N, W>: TryFrom<T>,
        <PlainText<N, W> as TryFrom<T>>::Error: std::fmt::Display,
    {
        let cipher = Self::cipher(subkey_id, field)?;
        let ct = cipher
            .right_encrypt(&plaintext.try_into().map_err(
                |e: <PlainText<N, W> as TryFrom<T>>::Error| Error::RangeError(e.to_string()),
            )?)
            .map_err(|e| {
                Error::EncryptionError(format!("Failed to encrypt ORE ciphertext: {e:?}"))
            })?;

        Ok(OREv1::<N, W> { ore_ciphertext: ct })
    }

    pub fn new_with_left<T>(
        plaintext: T,
        subkey_id: &[u8],
        field: &Field,
    ) -> Result<OREv1<N, W>, Error>
    where
        PlainText<N, W>: TryFrom<T>,
        <PlainText<N, W> as TryFrom<T>>::Error: std::fmt::Display,
    {
        let cipher = Self::cipher(subkey_id, field)?;
        let ct = cipher
            .full_encrypt(&plaintext.try_into().map_err(
                |e: <PlainText<N, W> as TryFrom<T>>::Error| Error::RangeError(e.to_string()),
            )?)
            .map_err(|e| {
                Error::EncryptionError(format!("Failed to encrypt ORE ciphertext: {e}"))
            })?;

        Ok(OREv1::<N, W> { ore_ciphertext: ct })
    }

    pub fn has_left(&self) -> bool {
        self.ore_ciphertext.has_left()
    }

    fn cipher(subkey_id: &[u8], field: &Field) -> Result<ore::Cipher<N, W>, Error> {
        let mut key: [u8; 32] = Default::default();

        field.subkey(&mut key, subkey_id)?;

        ore::Cipher::<N, W>::new(&key)
            .map_err(|e| Error::EncryptionError(format!("Failed to initialize ORE cipher: {e:?}")))
    }
}

impl<const N: usize, const W: u16> Ord for OREv1<N, W> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ore_ciphertext.cmp(&other.ore_ciphertext)
    }
}

impl<const N: usize, const W: u16> PartialOrd for OREv1<N, W> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize, const W: u16> PartialEq for OREv1<N, W> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl<const N: usize, const W: u16> Eq for OREv1<N, W> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{key_provider::Static, Field, Root};
    use std::sync::Arc;

    fn field() -> Field {
        Root::new(Arc::new(
            Static::new(b"this is a suuuuper long test key").unwrap(),
        ))
        .unwrap()
        .field(b"foo", b"bar")
        .unwrap()
    }

    quickcheck! {
        fn comparison_u64(a: u64, b: u64) -> bool {
            let ca = OREv1::<8, 256>::new_with_left(a, b"test", &field()).unwrap();
            let cb = OREv1::<8, 256>::new_with_left(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_u32(a: u32, b: u32) -> bool {
            let ca = OREv1::<4, 256>::new_with_left(a, b"test", &field()).unwrap();
            let cb = OREv1::<4, 256>::new_with_left(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_u16(a: u16, b: u16) -> bool {
            let ca = OREv1::<2, 256>::new_with_left(a, b"test", &field()).unwrap();
            let cb = OREv1::<2, 256>::new_with_left(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_u8(a: u8, b: u8) -> bool {
            let ca = OREv1::<1, 256>::new_with_left(a, b"test", &field()).unwrap();
            let cb = OREv1::<1, 256>::new_with_left(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_bool(a: bool, b: bool) -> bool {
            let ca = OREv1::<1, 2>::new_with_left(a, b"test", &field()).unwrap();
            let cb = OREv1::<1, 2>::new_with_left(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_u64_first_missing_left(a: u64, b: u64) -> bool {
            let ca = OREv1::<8, 256>::new(a, b"test", &field()).unwrap();
            let cb = OREv1::<8, 256>::new_with_left(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_u64_second_missing_left(a: u64, b: u64) -> bool {
            let ca = OREv1::<8, 256>::new_with_left(a, b"test", &field()).unwrap();
            let cb = OREv1::<8, 256>::new(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }
    }
}
