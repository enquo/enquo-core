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
pub struct BooleanV1 {
    #[serde(rename = "a")]
    pub aes_ciphertext: AES256v1,
    #[serde(rename = "o")]
    pub ore_ciphertext: Option<OREv1<1, 2, bool>>,
    #[serde(rename = "k", with = "serde_bytes")]
    pub key_id: Vec<u8>,
}

#[allow(non_upper_case_globals)]
const BOOLEANv1_ORE_KEY_IDENTIFIER: &[u8] = b"BooleanV1.ore_key";

impl BooleanV1 {
    pub fn new(b: bool, context: &[u8], field: &Field) -> Result<BooleanV1, Error> {
        Self::encrypt(b, context, field, false)
    }

    pub fn new_with_unsafe_parts(
        b: bool,
        context: &[u8],
        field: &Field,
    ) -> Result<BooleanV1, Error> {
        Self::encrypt(b, context, field, true)
    }

    fn encrypt(
        b: bool,
        context: &[u8],
        field: &Field,
        include_left: bool,
    ) -> Result<BooleanV1, Error> {
        let v = cbor!(b).map_err(|e| {
            Error::EncodingError(format!("failed to convert bool to ciborium value: {e}"))
        })?;

        let mut msg: Vec<u8> = Default::default();
        ciborium::ser::into_writer(&v, &mut msg)
            .map_err(|e| Error::EncodingError(format!("failed to encode bool value: {e}")))?;

        let aes = AES256v1::new(&msg, context, field)?;

        let ore = if include_left {
            OREv1::<1, 2, bool>::new_with_left(b, BOOLEANv1_ORE_KEY_IDENTIFIER, field)?
        } else {
            OREv1::<1, 2, bool>::new(b, BOOLEANv1_ORE_KEY_IDENTIFIER, field)?
        };

        Ok(BooleanV1 {
            aes_ciphertext: aes,
            ore_ciphertext: Some(ore),
            key_id: field.key_id()?,
        })
    }

    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<bool, Error> {
        let pt = self.aes_ciphertext.decrypt(context, field)?;

        let v = ciborium::de::from_reader(&*pt)
            .map_err(|e| Error::DecodingError(format!("could not decode decrypted value: {e}")))?;

        match v {
            Value::Bool(b) => Ok(b),
            _ => Err(Error::DecodingError(format!(
                "Decoded value is not a boolean (got {v:?})"
            ))),
        }
    }

    pub fn make_unqueryable(&mut self) -> Result<(), Error> {
        self.ore_ciphertext = None;
        Ok(())
    }
}

impl Ord for BooleanV1 {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.key_id != other.key_id {
            panic!("Cannot compare ciphertexts from different keys");
        }
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

impl PartialOrd for BooleanV1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for BooleanV1 {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for BooleanV1 {}

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
        let true_value = BooleanV1::new(true, b"context", &field()).unwrap();
        let false_value = BooleanV1::new(false, b"context", &field()).unwrap();

        assert_eq!(true, true_value.decrypt(b"context", &field()).unwrap());
        assert_eq!(false, false_value.decrypt(b"context", &field()).unwrap());
    }

    #[test]
    fn incorrect_context_fails() {
        let value = BooleanV1::new(true, b"somecontext", &field()).unwrap();

        let err = value.decrypt(b"othercontext", &field()).err();
        assert!(matches!(err, Some(Error::DecryptionError(_))));
    }

    #[test]
    fn serialised_ciphertext_size() {
        let value = BooleanV1::new(true, b"somecontext", &field()).unwrap();
        let serde_value = cbor!(value).unwrap();

        let mut s: Vec<u8> = vec![];
        ciborium::ser::into_writer(&serde_value, &mut s).unwrap();
        assert!(s.len() < 81, "s.len() == {}", s.len());
    }

    #[test]
    fn default_encryption_is_safe() {
        let value = BooleanV1::new(true, b"somecontext", &field()).unwrap();

        assert!(matches!(value.ore_ciphertext.unwrap().left, None));
    }
}
