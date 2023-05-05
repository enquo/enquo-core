//! First version of an order-revealing ciphertext, of arbitrary dimensions
//!

// This trips out on deriving Serialize in 1.69.0, doesn't seem to trip in nightly as of
// 2023-05-05.  Revisit after 1.70 is out, see if the problem has gone away
#![allow(clippy::arithmetic_side_effects)]

use cretrit::{aes128v1::ere, PlainText};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{Error, Field};

/// An equality-revealing ciphertext
///
/// Can encrypt an arbitrary-sized unsigned integer into a form where the value can't be
/// determined, but whether the ciphertext represents the same value as another similarly-encrypted
/// integer *can* be discerned.  It's like magic, but real.
///
/// `N` is the number of separate blocks the value is divided into, while `W` is the "width" of
/// each block (the number of discrete values that the block can represent).  The range of a given
/// `EREv1`, therefore, is zero to W^N-1, inclusive.
///
#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
#[doc(hidden)]
pub struct EREv1<const N: usize, const W: u16> {
    /// The ciphertext itself
    #[serde(rename = "e")]
    pub(crate) ere_ciphertext: ere::CipherText<N, W>,
}

impl<const N: usize, const W: u16> EREv1<N, W> {
    /// Create a new `EREv1` ciphertext
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
    ) -> Result<EREv1<N, W>, Error>
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
                Error::EncryptionError(format!("Failed to encrypt ERE ciphertext: {e:?}"))
            })?;

        Ok(EREv1::<N, W> { ere_ciphertext: ct })
    }

    /// Create a new `EREv1` ciphertext with reduced security guarantees
    ///
    /// See also: `new()`.
    ///
    pub(crate) fn new_with_left<T>(
        plaintext: T,
        subkey_id: &[u8],
        field: &Field,
    ) -> Result<EREv1<N, W>, Error>
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
                Error::EncryptionError(format!("Failed to encrypt ERE ciphertext: {e:?}"))
            })?;

        Ok(EREv1::<N, W> { ere_ciphertext: ct })
    }

    /// Helps tests to make sure that `new()` isn't playing fast and loose.
    #[cfg(test)]
    pub(crate) fn has_left(&self) -> bool {
        self.ere_ciphertext.has_left()
    }

    /// Creates a Cretrit cipher that will be used to create the ciphertext.
    fn cipher(subkey_id: &[u8], field: &Field) -> Result<ere::Cipher<N, W>, Error> {
        let mut key: [u8; 32] = Default::default();

        field.subkey(&mut key, subkey_id)?;

        ere::Cipher::<N, W>::new(&key)
            .map_err(|e| Error::EncryptionError(format!("Failed to initialize ERE cipher: {e:?}")))
    }
}

impl<const N: usize, const W: u16> PartialEq for EREv1<N, W> {
    fn eq(&self, other: &Self) -> bool {
        self.ere_ciphertext == other.ere_ciphertext
    }
}

impl<const N: usize, const W: u16> Eq for EREv1<N, W> {}

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
            let ca = EREv1::<16, 16>::new_with_left(a, b"test", &field()).unwrap();
            let cb = EREv1::<16, 16>::new_with_left(b, b"test", &field()).unwrap();

            (ca == cb) == (a == b)
        }

        fn comparison_u64_first_missing_left(a: u64, b: u64) -> bool {
            let ca = EREv1::<16, 16>::new(a, b"test", &field()).unwrap();
            let cb = EREv1::<16, 16>::new_with_left(b, b"test", &field()).unwrap();

            (ca == cb) == (a == b)
        }

        fn comparison_u64_second_missing_left(a: u64, b: u64) -> bool {
            let ca = EREv1::<16, 16>::new_with_left(a, b"test", &field()).unwrap();
            let cb = EREv1::<16, 16>::new(b, b"test", &field()).unwrap();

            (ca == cb) == (a == b)
        }
    }
}
