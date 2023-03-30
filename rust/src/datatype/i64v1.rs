use ciborium::{cbor, value::Value};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::cmp::Ordering;

use crate::{
    crypto::{AES256v1, OREv1},
    Error, Field,
};

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
pub struct I64v1 {
    #[serde(rename = "a")]
    pub aes_ciphertext: AES256v1,
    #[serde(rename = "o")]
    pub ore_ciphertext: Option<OREv1<8, 256, u64>>,
    #[serde(rename = "k", with = "serde_bytes")]
    pub key_id: Vec<u8>,
}

// AKA "2**63"
const I64_OFFSET: i128 = 9_223_372_036_854_775_808;

impl I64v1 {
    pub fn new(i: i64, context: &[u8], field: &Field) -> Result<I64v1, Error> {
        Self::encrypt(i, context, field, false)
    }

    pub fn new_with_unsafe_parts(i: i64, context: &[u8], field: &Field) -> Result<I64v1, Error> {
        Self::encrypt(i, context, field, true)
    }

    fn encrypt(i: i64, context: &[u8], field: &Field, include_left: bool) -> Result<I64v1, Error> {
        let v = cbor!(i).map_err(|e| {
            Error::EncodingError(format!("failed to convert i64 to ciborium value: {e}"))
        })?;

        let mut msg: Vec<u8> = Default::default();
        ciborium::ser::into_writer(&v, &mut msg)
            .map_err(|e| Error::EncodingError(format!("failed to encode i64 value: {e}")))?;

        let aes = AES256v1::new(&msg, context, field)?;

        let u: u64 = ((i as i128) + I64_OFFSET)
            .try_into()
            .map_err(|_| Error::EncodingError(format!("failed to convert i64 {i} to u64")))?;

        let ore = if include_left {
            OREv1::<8, 256, u64>::new_with_left(u, context, field)?
        } else {
            OREv1::<8, 256, u64>::new(u, context, field)?
        };

        Ok(I64v1 {
            aes_ciphertext: aes,
            ore_ciphertext: Some(ore),
            key_id: field.key_id()?,
        })
    }

    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<i64, Error> {
        let pt = self.aes_ciphertext.decrypt(context, field)?;

        let v = ciborium::de::from_reader(&*pt)
            .map_err(|e| Error::DecodingError(format!("could not decode decrypted value: {e}")))?;

        match v {
            Value::Integer(i) => Ok(i.try_into().map_err(|_| {
                Error::DecodingError("decoded value is not a valid i64".to_string())
            })?),
            _ => Err(Error::DecodingError(format!(
                "Decoded value is not an integer (got {v:?})"
            ))),
        }
    }

    pub fn make_unqueryable(&mut self) {
        self.ore_ciphertext = None;
    }
}

impl Ord for I64v1 {
    fn cmp(&self, other: &Self) -> Ordering {
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

impl PartialOrd for I64v1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for I64v1 {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for I64v1 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{key_provider::Static, Root};

    fn field() -> Field {
        Root::new(&Static::new(b"testkey"))
            .unwrap()
            .field(b"foo", b"bar")
            .unwrap()
    }

    #[test]
    fn value_round_trips() {
        let value = I64v1::new(42, b"context", &field()).unwrap();

        assert_eq!(42, value.decrypt(b"context", &field()).unwrap());
    }

    #[test]
    fn incorrect_context_fails() {
        let value = I64v1::new(42, b"somecontext", &field()).unwrap();

        let err = value.decrypt(b"othercontext", &field()).err();
        assert!(matches!(err, Some(Error::DecryptionError(_))));
    }

    #[test]
    fn serialised_ciphertext_size() {
        let value = I64v1::new(42, b"somecontext", &field()).unwrap();
        let serde_value = cbor!(value).unwrap();

        let mut s: Vec<u8> = vec![];
        ciborium::ser::into_writer(&serde_value, &mut s).unwrap();
        assert!(s.len() < 600, "s.len() == {}", s.len());
    }

    #[test]
    fn default_encryption_is_safe() {
        let value = I64v1::new(42, b"somecontext", &field()).unwrap();

        assert!(matches!(value.ore_ciphertext.unwrap().left, None));
    }
}
