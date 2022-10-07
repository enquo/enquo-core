use ciborium::cbor;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

use crate::{
    crypto::{AES256v1, ORE16v1, ORE6v1},
    Error, Field,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct DateV1 {
    #[serde(rename = "a")]
    pub aes_ciphertext: AES256v1,
    #[serde(rename = "y")]
    pub year_ciphertext: Option<ORE16v1>,
    #[serde(rename = "m")]
    pub month_ciphertext: Option<ORE6v1>,
    #[serde(rename = "d")]
    pub day_ciphertext: Option<ORE6v1>,
    #[serde(rename = "k", with = "serde_bytes")]
    pub key_id: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredDate {
    y: i16,
    m: u8,
    d: u8,
}

// AKA "2**15"
const I16_OFFSET: i32 = 32_768;

impl DateV1 {
    pub fn new(date: (i16, u8, u8), context: &[u8], field: &Field) -> Result<DateV1, Error> {
        Self::encrypt(date, context, field, false)
    }

    pub fn new_with_unsafe_parts(
        date: (i16, u8, u8),
        context: &[u8],
        field: &Field,
    ) -> Result<DateV1, Error> {
        Self::encrypt(date, context, field, true)
    }

    fn encrypt(
        date: (i16, u8, u8),
        context: &[u8],
        field: &Field,
        include_left: bool,
    ) -> Result<DateV1, Error> {
        let (y, m, d) = date;
        let s_date = StoredDate { y, m, d };

        let v = cbor!(s_date).map_err(|e| {
            Error::EncodingError(format!("failed to convert date to ciborium value: {}", e))
        })?;

        let mut msg: Vec<u8> = Default::default();
        ciborium::ser::into_writer(&v, &mut msg)
            .map_err(|e| Error::EncodingError(format!("failed to encode date value: {}", e)))?;

        let aes = AES256v1::new(&msg, context, field)?;

        let uy: u16 = ((y as i32) + I16_OFFSET).try_into().map_err(|_| {
            Error::EncodingError(format!("failed to convert i16 year {} to u16", y))
        })?;

        let ore_year = if include_left {
            ORE16v1::new_with_left(uy, context, field)?
        } else {
            ORE16v1::new(uy, context, field)?
        };
        let ore_month = if include_left {
            ORE6v1::new_with_left(m, context, field)?
        } else {
            ORE6v1::new(m, context, field)?
        };
        let ore_day = if include_left {
            ORE6v1::new_with_left(d, context, field)?
        } else {
            ORE6v1::new(d, context, field)?
        };

        Ok(DateV1 {
            aes_ciphertext: aes,
            year_ciphertext: Some(ore_year),
            month_ciphertext: Some(ore_month),
            day_ciphertext: Some(ore_day),
            key_id: field.key_id()?,
        })
    }

    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<(i16, u8, u8), Error> {
        let pt = self.aes_ciphertext.decrypt(context, field)?;

        let s_date = ciborium::de::from_reader::<'_, StoredDate, &[u8]>(&*pt).map_err(|e| {
            Error::DecodingError(format!("could not decode decrypted value: {}", e))
        })?;

        Ok((s_date.y, s_date.m, s_date.d))
    }

    pub fn drop_ore_ciphertexts(&mut self) {
        self.year_ciphertext = None;
        self.month_ciphertext = None;
        self.day_ciphertext = None;
    }

    fn ore_parts(&self) -> (&ORE16v1, &ORE6v1, &ORE6v1) {
        let y = self
            .year_ciphertext
            .as_ref()
            .expect("Cannot extract 'year' from ciphertext");
        let m = self
            .month_ciphertext
            .as_ref()
            .expect("Cannot extract 'month' from ciphertext");
        let d = self
            .day_ciphertext
            .as_ref()
            .expect("Cannot extract 'day' from ciphertext");

        (y, m, d)
    }
}

impl Ord for DateV1 {
    fn cmp(&self, other: &Self) -> Ordering {
        let lhs = self.ore_parts();
        let rhs = other.ore_parts();

        lhs.cmp(&rhs)
    }
}

impl PartialOrd for DateV1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for DateV1 {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for DateV1 {}

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
        let value = DateV1::new((1970, 1, 1), b"context", &field()).unwrap();

        assert_eq!((1970, 1, 1), value.decrypt(b"context", &field()).unwrap());
    }

    #[test]
    fn incorrect_context_fails() {
        let value = DateV1::new((1970, 1, 1), b"somecontext", &field()).unwrap();

        let err = value.decrypt(b"othercontext", &field()).err();
        assert!(matches!(err, Some(Error::DecryptionError(_))));
    }

    #[test]
    fn serialised_ciphertext_size() {
        let value = DateV1::new((1970, 1, 1), b"somecontext", &field()).unwrap();
        let serde_value = cbor!(value).unwrap();

        let mut s: Vec<u8> = vec![];
        ciborium::ser::into_writer(&serde_value, &mut s).unwrap();
        assert!(s.len() < 300, "s.len() == {}", s.len());
    }

    #[test]
    fn default_encryption_is_safe() {
        let value = DateV1::new((1970, 1, 1), b"somecontext", &field()).unwrap();

        assert!(matches!(value.year_ciphertext.unwrap().left, None));
        assert!(matches!(value.month_ciphertext.unwrap().left, None));
        assert!(matches!(value.day_ciphertext.unwrap().left, None));
    }
}
