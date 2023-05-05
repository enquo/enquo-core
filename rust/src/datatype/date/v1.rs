//! Version 1.0mod0 of a Date datatype
//!

use ciborium::cbor;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::cmp::Ordering;

use crate::{
    crypto::{AES256v1, OREv1},
    field::KeyId,
    util::check_overflow,
    Error, Field,
};

/// The ciphertext and all its components
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[doc(hidden)]
pub struct V1 {
    /// The value in a form that can be decrypted again when needed
    #[serde(rename = "a")]
    aes_ciphertext: AES256v1,
    /// An orderable encrypted form of the year
    #[serde(rename = "y")]
    year_ciphertext: Option<OREv1<2, 256>>,
    /// An orderable encrypted form of the month-of-the-year
    #[serde(rename = "m")]
    month_ciphertext: Option<OREv1<1, 32>>,
    /// An orderable encrypted form of the day-of-the-month
    #[serde(rename = "d")]
    day_ciphertext: Option<OREv1<1, 32>>,
    /// A serialisation-friendly form of the field key ID
    #[serde(rename = "k", with = "serde_bytes")]
    kid: Vec<u8>,
}

/// The date gets stuffed into here before being serdefied
#[derive(Debug, Serialize, Deserialize)]
struct StoredDate {
    /// The year
    y: i16,
    /// The month
    m: u8,
    /// The day
    d: u8,
}

/// The value that needs to be added/subtracted to translate between an i16 and a u16
const I16_OFFSET: i32 = 0x8000;

impl V1 {
    /// Encrypt the date
    pub(crate) fn new(date: (i16, u8, u8), context: &[u8], field: &Field) -> Result<V1, Error> {
        Self::encrypt(date, context, field, false)
    }

    /// Encrypt the date in a degraded security form
    pub(crate) fn new_with_unsafe_parts(
        date: (i16, u8, u8),
        context: &[u8],
        field: &Field,
    ) -> Result<V1, Error> {
        Self::encrypt(date, context, field, true)
    }

    /// Do the hard yards of actually producing ciphertexts and constructing the struct
    fn encrypt(
        date: (i16, u8, u8),
        context: &[u8],
        field: &Field,
        include_left: bool,
    ) -> Result<V1, Error> {
        let (y, m, d) = date;
        let s_date = StoredDate { y, m, d };

        let v = cbor!(s_date).map_err(|e| {
            Error::EncodingError(format!("failed to convert date to ciborium value: {e}"))
        })?;

        let mut msg: Vec<u8> = Default::default();
        ciborium::ser::into_writer(&v, &mut msg)
            .map_err(|e| Error::EncodingError(format!("failed to encode date value: {e}")))?;

        let aes = AES256v1::new(&msg, context, field)?;

        let uy: u16 = check_overflow(
            i32::from(y).overflowing_add(I16_OFFSET),
            "while translating DateV1 year to u16",
        )?
        .try_into()
        .map_err(|e| {
            Error::EncodingError(format!("failed to convert i16 year {y} to u16 ({e})"))
        })?;

        let mut year_context = context.to_vec();
        year_context.extend_from_slice(b".year");
        let mut month_context = context.to_vec();
        month_context.extend_from_slice(b".month");
        let mut day_context = context.to_vec();
        day_context.extend_from_slice(b".day");

        let ore_year = if include_left {
            OREv1::<2, 256>::new_with_left(uy, &year_context, field)?
        } else {
            OREv1::<2, 256>::new(uy, &year_context, field)?
        };
        let ore_month = if include_left {
            OREv1::<1, 32>::new_with_left(m, &month_context, field)?
        } else {
            OREv1::<1, 32>::new(m, &month_context, field)?
        };
        let ore_day = if include_left {
            OREv1::<1, 32>::new_with_left(d, &day_context, field)?
        } else {
            OREv1::<1, 32>::new(d, &day_context, field)?
        };

        Ok(V1 {
            aes_ciphertext: aes,
            year_ciphertext: Some(ore_year),
            month_ciphertext: Some(ore_month),
            day_ciphertext: Some(ore_day),
            kid: field.key_id()?.into(),
        })
    }

    /// Turn the ciphertext back into a date, or at least a tuple representing a date
    pub(crate) fn decrypt(&self, context: &[u8], field: &Field) -> Result<(i16, u8, u8), Error> {
        let pt = self.aes_ciphertext.decrypt(context, field)?;

        let s_date = ciborium::de::from_reader::<'_, StoredDate, &[u8]>(&*pt)
            .map_err(|e| Error::DecodingError(format!("could not decode decrypted value: {e}")))?;

        Ok((s_date.y, s_date.m, s_date.d))
    }

    /// Get the field key ID in canonical form
    pub(crate) fn key_id(&self) -> KeyId {
        let mut key_id: KeyId = Default::default();
        key_id.copy_from_slice(&self.kid);
        key_id
    }

    /// Strip out everything that makes a queryable Date queryable, leaving just the readable
    /// encrypted value behind
    pub(crate) fn make_unqueryable(&mut self) {
        self.year_ciphertext = None;
        self.month_ciphertext = None;
        self.day_ciphertext = None;
    }

    /// Create a sortable structure of the various encrypted y/m/d components, for comparison
    /// purposes
    #[allow(clippy::expect_used)] // This is only used in impl Ord, which can't return an error
    fn ore_parts(&self) -> (&OREv1<2, 256>, &OREv1<1, 32>, &OREv1<1, 32>) {
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

impl Ord for V1 {
    #[allow(clippy::panic, clippy::expect_used)] // No way to signal error from impl Ord
    fn cmp(&self, other: &Self) -> Ordering {
        assert!(
            self.kid == other.kid,
            "Cannot compare ciphertexts from different keys"
        );

        let lhs = self.ore_parts();
        let rhs = other.ore_parts();

        lhs.cmp(&rhs)
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
        let value = V1::new((1970, 1, 1), b"context", &field()).unwrap();

        assert_eq!((1970, 1, 1), value.decrypt(b"context", &field()).unwrap());
    }

    #[test]
    fn incorrect_context_fails() {
        let value = V1::new((1970, 1, 1), b"somecontext", &field()).unwrap();

        let err = value.decrypt(b"othercontext", &field()).err();
        assert!(matches!(err, Some(Error::DecryptionError(_))));
    }

    #[test]
    fn serialised_ciphertext_size() {
        let value = V1::new((1970, 1, 1), b"somecontext", &field()).unwrap();
        let serde_value = cbor!(value).unwrap();

        let mut s: Vec<u8> = vec![];
        ciborium::ser::into_writer(&serde_value, &mut s).unwrap();
        assert!(s.len() < 300, "s.len() == {}", s.len());
    }

    #[test]
    fn default_encryption_is_safe() {
        let value = V1::new((1970, 1, 1), b"somecontext", &field()).unwrap();

        assert!(!value.year_ciphertext.unwrap().has_left());
        assert!(!value.month_ciphertext.unwrap().has_left());
        assert!(!value.day_ciphertext.unwrap().has_left());
    }
}
