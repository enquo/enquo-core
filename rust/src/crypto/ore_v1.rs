//! First version of an order-revealing ciphertext, of arbitrary dimensions
//!

// This trips out on deriving Serialize in 1.69.0, doesn't seem to trip in nightly as of
// 2023-05-05.  Revisit after 1.70 is out, see if the problem has gone away
#![allow(clippy::arithmetic_side_effects)]

use cretrit::{aes128v1::ore, PlainText};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::cmp::Ordering;

use crate::{Error, Field};

/// An order-revealing ciphertext
///
/// Can encrypt an arbitrary-sized unsigned integer into a form where the value can't be
/// determined, but the ordering relative to other similarly-encrypted integers *can* be discerned.
/// It's like magic, but real.
///
/// `N` is the number of separate blocks the value is divided into, while `W` is the "width" of
/// each block (the number of discrete values that the block can represent).  The range of a given
/// `OREv1`, therefore, is zero to W^N-1, inclusive.
///
#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
#[doc(hidden)]
pub struct OREv1<const N: usize, const W: u16> {
    /// Yon magical ciphertext
    #[serde(rename = "o")]
    pub(crate) ore_ciphertext: ore::CipherText<N, W>,
}

impl<const N: usize, const W: u16> OREv1<N, W> {
    /// Create a new `OREv1` ciphertext
    ///
    /// # Errors
    ///
    /// Can fail if the encryption fails, or if the value is outside the range of valid values
    /// given the N, W of the type.
    ///
    pub(crate) fn new<T>(
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
            .right_encrypt(&plaintext.try_into().map_err(
                |e: <PlainText<N, W> as TryFrom<T>>::Error| Error::RangeError(e.to_string()),
            )?)
            .map_err(|e| {
                Error::EncryptionError(format!("Failed to encrypt ORE ciphertext: {e:?}"))
            })?;

        Ok(OREv1::<N, W> { ore_ciphertext: ct })
    }

    /// Create a new `OREv1` ciphertext with reduced security guarantees
    ///
    /// See also: `new()`.
    ///
    pub(crate) fn new_with_left<T>(
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

    /// Helps tests to make sure that `new()` isn't doing something insecure
    #[cfg(test)]
    pub(crate) fn has_left(&self) -> bool {
        self.ore_ciphertext.has_left()
    }

    /// Generate a Cretrit cipher with which to encrypt the value
    ///
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
