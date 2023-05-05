//! Order-revealing ciphertexts
//!

// This trips out on deriving Serialize in 1.69.0, doesn't seem to trip in nightly as of
// 2023-05-05.  Revisit after 1.70 is out, see if the problem has gone away
#![allow(clippy::arithmetic_side_effects)]

use cretrit::PlainText;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

use crate::crypto::OREv1;
use crate::{
    datatype::kith::{Datatype as KithDatatype, Member as KithMember},
    field::KeyId,
    Error, Field,
};

/// Versioning support
#[derive(Debug, Serialize, Deserialize, Clone)]
#[allow(clippy::missing_docs_in_private_items)] // I think we can all tell what's going on in here
enum Ciphertext<const N: usize, const W: u16> {
    #[allow(non_camel_case_types)]
    v1(OREv1<N, W>),
    Unknown,
}

/// A data type for representing order-revealing values
///
/// When querying, you typically don't care about keeping the value you're encrypting in any
/// long-term way; all you want is a blob of data you can wave at whatever you're querying against
/// to see which ones match.
///
/// That's where this data type comes in.
///
/// Rather than having to try and (mis)use some other data type (like, say, `I64`), you can use
/// this type to provide generic order-revealing ciphertexts of arbitrary sizes to compare.  This
/// is primarily useful when you're looking to query on the sub-parts of more complex data types
/// (like the length of a string, or the month of a date).
///
/// If you start thinking that you'd like to start storing these somewhere in their own right, you
/// probably want to be defining a separate standalone data type.
///
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ORE<const N: usize, const W: u16> {
    /// The ORE ciphertext itself
    #[serde(rename = "o")]
    ore_ciphertext: Ciphertext<N, W>,

    /// The field key ID which was used to generate this ciphertext
    #[serde(rename = "k", with = "serde_bytes")]
    kid: Vec<u8>,
}

impl<const N: usize, const W: u16> ORE<N, W> {
    /// Create a new ORE value
    ///
    /// # Errors
    ///
    /// Can return an error if the encryption of the value fails.
    ///
    pub fn new<T>(i: T, context: &[u8], field: &Field) -> Result<ORE<N, W>, Error>
    where
        PlainText<N, W>: TryFrom<T>,
        <PlainText<N, W> as TryFrom<T>>::Error: std::fmt::Display,
        T: Clone,
    {
        Ok(ORE::<N, W> {
            ore_ciphertext: Ciphertext::v1(OREv1::<N, W>::new(i, context, field)?),
            kid: field.key_id()?.into(),
        })
    }

    /// Create a new ORE value with parts that could allow an attacker to infer the value
    ///
    /// This is not as much of a problem to use as the equivalent function for other data types,
    /// because ORE values are intended for querying, rather than storage.  Still, don't leave the
    /// output of this function laying around anywhere.
    ///
    /// # Errors
    ///
    /// Can return an error if the encryption of the value fails.
    ///
    pub fn new_with_unsafe_parts<T>(i: T, context: &[u8], field: &Field) -> Result<ORE<N, W>, Error>
    where
        PlainText<N, W>: TryFrom<T>,
        <PlainText<N, W> as TryFrom<T>>::Error: std::fmt::Display,
        T: Clone,
    {
        Ok(ORE::<N, W> {
            ore_ciphertext: Ciphertext::v1(OREv1::<N, W>::new_with_left(i, context, field)?),
            kid: field.key_id()?.into(),
        })
    }

    /// Create an ORE ciphertext from an `OREv1` ciphertext
    ///
    /// The `OREv1` type is a cryptographic primitive, which is what we use inside various
    /// datatypes.  This function essentially "wraps" that `OREv1` in something that can be used as
    /// a fully-fledged datatype value of its own.
    ///
    #[must_use]
    pub fn from_ore_v1(o: OREv1<N, W>, key_id: KeyId) -> ORE<N, W> {
        ORE::<N, W> {
            ore_ciphertext: Ciphertext::v1(o),
            kid: key_id.into(),
        }
    }
}

impl<const N: usize, const W: u16> KithMember for ORE<N, W> {}

impl<const N: usize, const W: u16> KithDatatype for ORE<N, W> {
    fn key_id(&self) -> KeyId {
        let mut key_id: KeyId = Default::default();
        key_id.copy_from_slice(&self.kid);
        key_id
    }

    fn ciphertext_version(&self) -> u32 {
        match self.ore_ciphertext {
            Ciphertext::v1(_) => 1,
            Ciphertext::Unknown => 0,
        }
    }
}

impl<const N: usize, const W: u16> Ord for ORE<N, W> {
    #[allow(clippy::panic)] // No way to signal an error from impl Ord
    fn cmp(&self, other: &Self) -> Ordering {
        match &self.ore_ciphertext {
            #[allow(clippy::match_wildcard_for_single_variants)]
            // Yes, I really *do* want to match *anything else*
            Ciphertext::v1(s) => match &other.ore_ciphertext {
                Ciphertext::v1(o) => s.cmp(o),
                _ => panic!("Cannot compare a v1 ORE ciphertext with any other type of ciphertext"),
            },
            Ciphertext::Unknown => {
                panic!("Cannot compare against an Unknown version ORE ciphertext")
            }
        }
    }
}

impl<const N: usize, const W: u16> PartialOrd for ORE<N, W> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize, const W: u16> PartialEq for ORE<N, W> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl<const N: usize, const W: u16> Eq for ORE<N, W> {}

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
            let ca = ORE::<8, 16>::new_with_unsafe_parts(a, b"test", &field()).unwrap();
            let cb = ORE::<8, 16>::new_with_unsafe_parts(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_u32_first_missing_left(a: u32, b: u32) -> bool {
            let ca = ORE::<8, 16>::new(a, b"test", &field()).unwrap();
            let cb = ORE::<8, 16>::new_with_unsafe_parts(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_u32_second_missing_left(a: u32, b: u32) -> bool {
            let ca = ORE::<8, 16>::new_with_unsafe_parts(a, b"test", &field()).unwrap();
            let cb = ORE::<8, 16>::new(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }
    }

    #[test]
    #[should_panic]
    fn need_one_left_ciphertext() {
        let ca = ORE::<8, 16>::new(8u8, b"test", &field()).unwrap();
        let cb = ORE::<8, 16>::new(16u8, b"test", &field()).unwrap();

        let _ = ca == cb;
    }
}
