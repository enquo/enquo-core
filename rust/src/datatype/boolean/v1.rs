//! Our v1 boolean
//!

use ciborium::{cbor, value::Value};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::cmp::Ordering;

use crate::{
    crypto::{AES256v1, OREv1},
    field::KeyId,
    Error, Field,
};

/// Das Bool
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[doc(hidden)]
pub struct V1 {
    /// The encrypted value
    #[serde(rename = "a")]
    aes_ciphertext: AES256v1,
    /// The queryable form of the encrypted value
    #[serde(rename = "o")]
    ore_ciphertext: Option<OREv1<1, 2>>,
    /// A serialisation-friendly format of the field key ID
    #[serde(rename = "k", with = "serde_bytes")]
    kid: Vec<u8>,
}

/// The identifier for the subkey that produces the ORE ciphertext
#[allow(non_upper_case_globals)]
const BOOLEANv1_ORE_KEY_IDENTIFIER: &[u8] = b"boolean::V1.ore_key";

impl V1 {
    /// Make the encrypted boolean
    pub(crate) fn new(b: bool, context: &[u8], field: &Field) -> Result<V1, Error> {
        Self::encrypt(b, context, field, false)
    }

    /// Make the encrypted boolean, with reduced security guarantees
    pub(crate) fn new_with_unsafe_parts(
        b: bool,
        context: &[u8],
        field: &Field,
    ) -> Result<V1, Error> {
        Self::encrypt(b, context, field, true)
    }

    /// Do the hard yards of generating the ciphertexts and assembling the struct
    fn encrypt(b: bool, context: &[u8], field: &Field, include_left: bool) -> Result<V1, Error> {
        let v = cbor!(b).map_err(|e| {
            Error::EncodingError(format!("failed to convert bool to ciborium value: {e}"))
        })?;

        let mut msg: Vec<u8> = Default::default();
        ciborium::ser::into_writer(&v, &mut msg)
            .map_err(|e| Error::EncodingError(format!("failed to encode bool value: {e}")))?;

        let aes = AES256v1::new(&msg, context, field)?;

        let ore = if include_left {
            OREv1::<1, 2>::new_with_left(b, BOOLEANv1_ORE_KEY_IDENTIFIER, field)?
        } else {
            OREv1::<1, 2>::new(b, BOOLEANv1_ORE_KEY_IDENTIFIER, field)?
        };

        Ok(V1 {
            aes_ciphertext: aes,
            ore_ciphertext: Some(ore),
            kid: field.key_id()?.into(),
        })
    }

    /// Extract a plaintext bool
    pub(crate) fn decrypt(&self, context: &[u8], field: &Field) -> Result<bool, Error> {
        let pt = self.aes_ciphertext.decrypt(context, field)?;

        let v = ciborium::de::from_reader(&*pt)
            .map_err(|e| Error::DecodingError(format!("could not decode decrypted value: {e}")))?;

        #[allow(clippy::wildcard_enum_match_arm)] // that is, indeed, exactly what I want here
        match v {
            Value::Bool(b) => Ok(b),
            _ => Err(Error::DecodingError(format!(
                "Decoded value is not a boolean (got {v:?})"
            ))),
        }
    }

    /// Return the field key ID in canonical form
    pub(crate) fn key_id(&self) -> KeyId {
        let mut key_id: KeyId = Default::default();
        key_id.copy_from_slice(&self.kid);
        key_id
    }

    /// Remove the "queryable" from "queryable encrypted boolean"
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
        let true_value = V1::new(true, b"context", &field()).unwrap();
        let false_value = V1::new(false, b"context", &field()).unwrap();

        assert_eq!(true, true_value.decrypt(b"context", &field()).unwrap());
        assert_eq!(false, false_value.decrypt(b"context", &field()).unwrap());
    }

    #[test]
    fn incorrect_context_fails() {
        let value = V1::new(true, b"somecontext", &field()).unwrap();

        let err = value.decrypt(b"othercontext", &field()).err();
        assert!(matches!(err, Some(Error::DecryptionError(_))));
    }

    #[test]
    fn serialised_ciphertext_size() {
        let value = V1::new(true, b"somecontext", &field()).unwrap();
        let serde_value = cbor!(value).unwrap();

        let mut s: Vec<u8> = vec![];
        ciborium::ser::into_writer(&serde_value, &mut s).unwrap();
        assert!(s.len() < 81, "s.len() == {}", s.len());
    }

    #[test]
    fn default_encryption_is_safe() {
        let value = V1::new(true, b"somecontext", &field()).unwrap();

        assert!(!value.ore_ciphertext.unwrap().has_left());
    }
}
