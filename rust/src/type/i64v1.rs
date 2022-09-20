use ciborium::{cbor, value::Value};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

use crate::{
    crypto::{AES256, ORE64},
    r#type::TypeError,
    Field,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct I64v1 {
    #[serde(rename = "a")]
    pub aes_ciphertext: AES256,
    #[serde(rename = "o")]
    pub ore_ciphertext: ORE64,
    #[serde(rename = "k")]
    pub key_id: Vec<u8>,
}

// AKA "2**63"
const I64_OFFSET: i128 = 9_223_372_036_854_775_808;

impl I64v1 {
    pub fn new(i: i64, context: &[u8], field: &Field) -> Result<I64v1, TypeError> {
        let v = cbor!(i)
            .map_err(|e| TypeError::EncodingError(format!("failed to encode i64: {}", e)))?;

        let mut msg: Vec<u8> = Default::default();
        ciborium::ser::into_writer(&v, &mut msg)
            .map_err(|e| TypeError::EncodingError(format!("failed to write i64 to msg: {}", e)))?;

        let aes =
            AES256::new(&msg, context, field).map_err(|e| TypeError::CryptoError(e.to_string()))?;

        let u: u64 = ((i as i128) + I64_OFFSET).try_into().map_err(|_| {
            TypeError::ConversionError(format!("failed to convert i64 {} to u64", i))
        })?;
        let ore =
            ORE64::new(u, context, field).map_err(|e| TypeError::CryptoError(e.to_string()))?;

        Ok(I64v1 {
            aes_ciphertext: aes,
            ore_ciphertext: ore,
            key_id: field.key_id(),
        })
    }

    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<i64, TypeError> {
        let pt = self
            .aes_ciphertext
            .decrypt(context, field)
            .map_err(|e| TypeError::CryptoError(format!("failed to decrypt i64: {}", e)))?;

        let v = ciborium::de::from_reader(&*pt).map_err(|e| {
            TypeError::DecodingError(format!("Could not decode decrypted value: {}", e))
        })?;

        match v {
            Value::Integer(i) => Ok(i.try_into().map_err(|_| {
                TypeError::DecodingError("Decoded value is not a valid u64".to_string())
            })?),
            _ => Err(TypeError::DecodingError(format!(
                "Decoded value is not an integer (got {:?})",
                v
            ))),
        }
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
        Root::new(b"testkey").unwrap().field(b"foo", b"bar")
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
        assert!(matches!(err, Some(TypeError::CryptoError(_))));
    }
}
