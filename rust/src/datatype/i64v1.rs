use ciborium::{cbor, value::Value};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

use crate::{
    crypto::{AES256v1, ORE64v1},
    Error, Field,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct I64v1 {
    #[serde(rename = "a")]
    pub aes_ciphertext: AES256v1,
    #[serde(rename = "o")]
    pub ore_ciphertext: ORE64v1,
    #[serde(rename = "k")]
    pub key_id: Vec<u8>,
}

// AKA "2**63"
const I64_OFFSET: i128 = 9_223_372_036_854_775_808;

impl I64v1 {
    pub fn new(i: i64, context: &[u8], field: &Field) -> Result<I64v1, Error> {
        let v = cbor!(i).map_err(|e| {
            Error::EncodingError(format!("failed to convert i64 to ciborium value: {}", e))
        })?;

        let mut msg: Vec<u8> = Default::default();
        ciborium::ser::into_writer(&v, &mut msg)
            .map_err(|e| Error::EncodingError(format!("failed to encode i64 value: {}", e)))?;

        let aes = AES256v1::new(&msg, context, field)?;

        let u: u64 = ((i as i128) + I64_OFFSET)
            .try_into()
            .map_err(|_| Error::EncodingError(format!("failed to convert i64 {} to u64", i)))?;
        let ore = ORE64v1::new(u, context, field)?;

        Ok(I64v1 {
            aes_ciphertext: aes,
            ore_ciphertext: ore,
            key_id: field.key_id()?,
        })
    }

    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<i64, Error> {
        let pt = self.aes_ciphertext.decrypt(context, field)?;

        let v = ciborium::de::from_reader(&*pt).map_err(|e| {
            Error::DecodingError(format!("could not decode decrypted value: {}", e))
        })?;

        match v {
            Value::Integer(i) => Ok(i.try_into().map_err(|_| {
                Error::DecodingError("decoded value is not a valid i64".to_string())
            })?),
            _ => Err(Error::DecodingError(format!(
                "Decoded value is not an integer (got {:?})",
                v
            ))),
        }
    }

    pub fn clear_left_ciphertexts(&mut self) {
        self.ore_ciphertext.left = None;
    }
}

impl Ord for I64v1 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ore_ciphertext.cmp(&other.ore_ciphertext)
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
    use crate::Root;

    fn field() -> Field {
        let k: &[u8] = b"testkey";
        Root::new(&k).unwrap().field(b"foo", b"bar").unwrap()
    }

    #[test]
    fn value_round_trips() {
        let cipher = I64v1::new(42, b"context", &field()).unwrap();

        assert_eq!(42, cipher.decrypt(b"context", &field()).unwrap());
    }

    #[test]
    fn incorrect_context_fails() {
        let cipher = I64v1::new(42, b"somecontext", &field()).unwrap();

        let err = cipher.decrypt(b"othercontext", &field()).err();
        assert!(matches!(err, Some(Error::DecryptionError(_))));
    }
}
