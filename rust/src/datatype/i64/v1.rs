//! Our first attempt at a queryable encrypted signed 64-bit integer
//!
//! Seems to be working OK so far, at least.
//!

use ciborium::{cbor, value::Value};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::cmp::Ordering;

use crate::{
    crypto::{AES256v1, OREv1},
    field::KeyId,
    util::check_overflow,
    Error, Field,
};

/// The data itself
///
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[doc(hidden)]
pub struct V1 {
    /// The actual encrypted value
    #[serde(rename = "a")]
    aes_ciphertext: AES256v1,
    /// The value encrypted in a form that can be queried
    #[serde(rename = "o")]
    ore_ciphertext: Option<OREv1<8, 256>>,
    /// A serialisation-friendly form of the field key ID
    #[serde(rename = "k", with = "serde_bytes")]
    kid: Vec<u8>,
}

/// The value that needs to be added/subtracted to turn an i64 into a u64 (and vice versa)
///
const I64_OFFSET: i128 = 0x8000_0000_0000_0000;

impl V1 {
    /// Create an encrypted bigint
    ///
    pub(crate) fn new(i: i64, context: &[u8], field: &Field) -> Result<V1, Error> {
        Self::encrypt(i, context, field, false)
    }

    /// Create an encrypted bigint with lower security guarantees
    ///
    pub(crate) fn new_with_unsafe_parts(
        i: i64,
        context: &[u8],
        field: &Field,
    ) -> Result<V1, Error> {
        Self::encrypt(i, context, field, true)
    }

    /// Do the hard yards of actually poking the cryptography and assembling the struct
    ///
    fn encrypt(i: i64, context: &[u8], field: &Field, include_left: bool) -> Result<V1, Error> {
        let v = cbor!(i).map_err(|e| {
            Error::EncodingError(format!("failed to convert i64 to ciborium value: {e}"))
        })?;

        let mut msg: Vec<u8> = Default::default();
        ciborium::ser::into_writer(&v, &mut msg)
            .map_err(|e| Error::EncodingError(format!("failed to encode i64 value: {e}")))?;

        let aes = AES256v1::new(&msg, context, field)?;

        let u: u64 = (check_overflow(
            i128::from(i).overflowing_add(I64_OFFSET),
            "while offsetting i64",
        )?)
        .try_into()
        .map_err(|e| Error::EncodingError(format!("failed to convert i64 {i} to u64 ({e})")))?;

        let ore = if include_left {
            OREv1::<8, 256>::new_with_left(u, context, field)?
        } else {
            OREv1::<8, 256>::new(u, context, field)?
        };

        Ok(V1 {
            aes_ciphertext: aes,
            ore_ciphertext: Some(ore),
            kid: field.key_id()?.into(),
        })
    }

    /// Do the decryption
    ///
    pub(crate) fn decrypt(&self, context: &[u8], field: &Field) -> Result<i64, Error> {
        let pt = self.aes_ciphertext.decrypt(context, field)?;

        let v = ciborium::de::from_reader(&*pt)
            .map_err(|e| Error::DecodingError(format!("could not decode decrypted value: {e}")))?;

        #[allow(clippy::wildcard_enum_match_arm)] // Nope, that's exactly what I want
        match v {
            Value::Integer(i) => Ok(i.try_into().map_err(|e| {
                Error::DecodingError(format!("decoded value is not a valid i64 ({e})"))
            })?),
            _ => Err(Error::DecodingError(format!(
                "Decoded value is not an integer (got {v:?})"
            ))),
        }
    }

    /// Return the ciphertext's field key ID, in canonical form
    pub(crate) fn key_id(&self) -> KeyId {
        let mut key_id: KeyId = Default::default();
        key_id.copy_from_slice(&self.kid);
        key_id
    }

    /// Strip out everything that makes the "queryable" bit work
    pub(crate) fn make_unqueryable(&mut self) {
        self.ore_ciphertext = None;
    }
}

impl Ord for V1 {
    #[allow(clippy::panic, clippy::expect_used)] // No way to signal error from impl Ord
    fn cmp(&self, other: &Self) -> Ordering {
        assert!(
            self.kid == other.kid,
            "Cannot compare ciphertexts from different keys"
        );

        let lhs = self
            .ore_ciphertext
            .as_ref()
            .expect("Cannot compare without an ORE ciphertext on the left-hand side");
        let rhs = other
            .ore_ciphertext
            .as_ref()
            .expect("Cannot compare without an ORE ciphertext on the right-hand side");

        lhs.cmp(rhs)
    }
}

impl PartialOrd for V1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for V1 {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for V1 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{key_provider::Static, Root};
    use std::sync::Arc;

    fn field() -> Field {
        Root::new(Arc::new(
            Static::new(b"this is a suuuuper long test key").unwrap(),
        ))
        .unwrap()
        .field(b"foo", b"bar")
        .unwrap()
    }

    #[test]
    fn value_round_trips() {
        let value = V1::new(42, b"context", &field()).unwrap();

        assert_eq!(42, value.decrypt(b"context", &field()).unwrap());
    }

    #[test]
    fn incorrect_context_fails() {
        let value = V1::new(42, b"somecontext", &field()).unwrap();

        let err = value.decrypt(b"othercontext", &field()).err();
        assert!(matches!(err, Some(Error::DecryptionError(_))));
    }

    #[test]
    fn serialised_ciphertext_size() {
        let value = V1::new(42, b"somecontext", &field()).unwrap();
        let serde_value = cbor!(value).unwrap();

        let mut s: Vec<u8> = vec![];
        ciborium::ser::into_writer(&serde_value, &mut s).unwrap();
        assert!(s.len() < 600, "s.len() == {}", s.len());
    }

    #[test]
    fn default_encryption_is_safe() {
        let value = V1::new(42, b"somecontext", &field()).unwrap();

        assert!(!value.ore_ciphertext.unwrap().has_left());
    }
}
