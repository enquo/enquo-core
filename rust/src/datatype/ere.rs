//! Equality-revealing ciphertexts
//!

// This trips out on deriving Serialize in 1.69.0, doesn't seem to trip in nightly as of
// 2023-05-05.  Revisit after 1.70 is out, see if the problem has gone away
#![allow(clippy::arithmetic_side_effects)]

use cretrit::PlainText;
use serde::{Deserialize, Serialize};

use crate::crypto::EREv1;
use crate::{
    datatype::kith::{Datatype as KithDatatype, Member as KithMember},
    field::KeyId,
    Error, Field,
};

/// Versioning support
#[derive(Debug, Serialize, Deserialize)]
#[allow(clippy::missing_docs_in_private_items)] // Hopefully these names are fairly self-describing...
enum Ciphertext<const N: usize, const W: u16> {
    #[allow(non_camel_case_types)]
    v1(EREv1<N, W>),
    Unknown,
}

/// A data type for representing equaling-revealing values
///
/// When querying, you typically don't care about keeping the value you're encrypting in any
/// long-term way; all you want is a blob of data you can wave at whatever you're querying against
/// to see which ones match.
///
/// That's where this data type comes in.
///
/// Rather than having to try and (mis)use some other data type (like, say, `I64`), you can use
/// this type to provide generic equality-revealing ciphertexts of arbitrary sizes to compare.  This
/// is primarily useful when you're looking to query on the sub-parts of more complex data types
/// (like the length of a string, or the month of a date).
///
/// If you start thinking that you'd like to start storing these somewhere in their own right, you
/// probably want to be defining a separate standalone data type.
///
#[derive(Debug, Serialize, Deserialize)]
pub struct ERE<const N: usize, const W: u16> {
    /// The ERE ciphertext itself
    #[serde(rename = "e")]
    ere_ciphertext: Ciphertext<N, W>,

    /// A serialisation-friendly form of the field key ID
    #[serde(rename = "k", with = "serde_bytes")]
    kid: Vec<u8>,
}

impl<const N: usize, const W: u16> ERE<N, W> {
    /// Create a new ERE value
    ///
    /// # Errors
    ///
    /// Can return an error if there was a problem performing the cryptography, or if the value to
    /// be encrypted could not be represented in the size of the type.
    ///
    pub fn new<T>(i: T, context: &[u8], field: &Field) -> Result<ERE<N, W>, Error>
    where
        PlainText<N, W>: TryFrom<T>,
        <PlainText<N, W> as TryFrom<T>>::Error: std::fmt::Display,
    {
        Ok(ERE::<N, W> {
            ere_ciphertext: Ciphertext::v1(EREv1::<N, W>::new(i, context, field)?),
            kid: field.key_id()?.into(),
        })
    }

    /// Create a new ERE value with parts that could allow an attacker to infer the value
    ///
    /// This is not as much of a problem to use as the equivalent function for other data types,
    /// because ERE values are intended for querying, rather than storage.  Still, don't leave the
    /// output of this function laying around anywhere.
    ///
    /// # Errors
    ///
    /// Can return an error if there was a problem performing the cryptography, or if the value to
    /// be encrypted could not be represented in the size of the type.
    ///
    pub fn new_with_unsafe_parts<T>(i: T, context: &[u8], field: &Field) -> Result<ERE<N, W>, Error>
    where
        PlainText<N, W>: TryFrom<T>,
        <PlainText<N, W> as TryFrom<T>>::Error: std::fmt::Display,
    {
        Ok(ERE::<N, W> {
            ere_ciphertext: Ciphertext::v1(EREv1::<N, W>::new_with_left(i, context, field)?),
            kid: field.key_id()?.into(),
        })
    }
}

impl<const N: usize, const W: u16> PartialEq for ERE<N, W> {
    #[allow(clippy::panic)] // No way to signal error from impl PartialEq
    fn eq(&self, other: &Self) -> bool {
        #[allow(clippy::match_wildcard_for_single_variants)]
        // Actually, that is exactly what I *do* want here
        match &self.ere_ciphertext {
            Ciphertext::v1(s) => match &other.ere_ciphertext {
                Ciphertext::v1(o) => s == o,
                _ => panic!("Cannot compare a v1 ERE ciphertext with any other type of ciphertext"),
            },
            Ciphertext::Unknown => {
                panic!("Cannot compare against an Unknown version ERE ciphertext")
            }
        }
    }
}

impl<const N: usize, const W: u16> Eq for ERE<N, W> {}

impl<const N: usize, const W: u16> KithMember for ERE<N, W> {}

impl<const N: usize, const W: u16> KithDatatype for ERE<N, W> {
    fn key_id(&self) -> KeyId {
        let mut key_id: KeyId = Default::default();
        key_id.copy_from_slice(&self.kid);
        key_id
    }

    fn ciphertext_version(&self) -> u32 {
        match self.ere_ciphertext {
            Ciphertext::v1(_) => 1,
            Ciphertext::Unknown => 0,
        }
    }
}

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
        fn comparison_u32(a: u32, b: u32) -> bool {
            let ca = ERE::<8, 16>::new_with_unsafe_parts(a, b"test", &field()).unwrap();
            let cb = ERE::<8, 16>::new_with_unsafe_parts(b, b"test", &field()).unwrap();

            (ca == cb) == (a == b)
        }

        fn comparison_u32_first_missing_left(a: u32, b: u32) -> bool {
            let ca = ERE::<8, 16>::new(a, b"test", &field()).unwrap();
            let cb = ERE::<8, 16>::new_with_unsafe_parts(b, b"test", &field()).unwrap();

            (ca == cb) == (a == b)
        }

        fn comparison_u32_second_missing_left(a: u32, b: u32) -> bool {
            let ca = ERE::<8, 16>::new_with_unsafe_parts(a, b"test", &field()).unwrap();
            let cb = ERE::<8, 16>::new(b, b"test", &field()).unwrap();

            (ca == cb) == (a == b)
        }
    }

    #[test]
    #[should_panic]
    fn need_one_left_ciphertext() {
        let ca = ERE::<8, 16>::new(8u8, b"test", &field()).unwrap();
        let cb = ERE::<8, 16>::new(16u8, b"test", &field()).unwrap();

        let _ = ca == cb;
    }
}
