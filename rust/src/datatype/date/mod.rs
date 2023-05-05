//! Store and query dates in an encrypted form
//!

mod v1;

use serde::{Deserialize, Serialize};

use self::v1::V1;
use crate::{datatype::kith::Datatype as KithDatatype, field::KeyId, Error, Field};

/// The encrypted, queryable date
///
#[derive(Debug, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[allow(missing_docs, clippy::missing_docs_in_private_items)] // I think we can figure it out from the name
#[non_exhaustive]
pub enum Date {
    #[allow(non_camel_case_types)]
    v1(Box<V1>),
    Unknown,
}

impl Date {
    /// Create a new encrypted, queryable date
    ///
    /// The date is represented as `(y, m, d)` in the tuple.
    ///
    #[doc = include_str!("../encryption_contexts.md")]
    ///
    /// # Errors
    ///
    /// Can return an error if the process of encrypting the data fails.
    ///
    pub fn new(date: (i16, u8, u8), context: &[u8], field: &Field) -> Result<Date, Error> {
        Ok(Date::v1(Box::new(V1::new(date, context, field)?)))
    }

    /// Create a new encrypted, queryable date with degraded security
    ///
    /// The date is represented as `(y, m, d)` in the tuple.
    ///
    /// While the date itself is securely encrypted, the ciphertexts produced by this function may
    /// contain components that allow an attacker to infer the plaintext or some part(s) thereof.
    ///
    /// See [the Enquo threat model](https://enquo.org/threat-models/) for more details.
    ///
    #[doc = include_str!("../encryption_contexts.md")]
    ///
    /// # Errors
    ///
    /// Can return an error if the process of encrypting the data fails.
    ///
    pub fn new_with_unsafe_parts(
        date: (i16, u8, u8),
        context: &[u8],
        field: &Field,
    ) -> Result<Date, Error> {
        Ok(Date::v1(Box::new(V1::new_with_unsafe_parts(
            date, context, field,
        )?)))
    }

    /// Decrypt the date, and return it as a `(y, m, d)` tuple
    ///
    /// # Errors
    ///
    /// Can return an error if the field could not be decrypted for some reason, such as if the
    /// wrong field was provided, or the decryption context was incorrect.  See
    /// [`Date::new()`](Date::new) for more details about encryption and decryption contexts.
    ///
    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<(i16, u8, u8), Error> {
        match self {
            Date::v1(d) => d.decrypt(context, field),
            Date::Unknown => Err(Error::UnknownVersionError()),
        }
    }

    /// Remove the ability to perform any queries on this value
    ///
    /// Sometimes you just want to be able to store a safely encrypted date, without any
    /// ability to query it.  In that case, you can save a fair chunk of space by calling this
    /// method before you serialise it.
    ///
    /// # Errors
    ///
    /// Can return an error if the object could not be made unqueryable, or if an attempt was made
    /// to make an Unknown version unqueryable.
    ///
    pub fn make_unqueryable(&mut self) -> Result<(), Error> {
        match self {
            Date::v1(d) => {
                d.make_unqueryable();
                Ok(())
            }
            Date::Unknown => Err(Error::UnknownVersionError()),
        }
    }
}

impl KithDatatype for Date {
    fn key_id(&self) -> KeyId {
        match self {
            Date::v1(t) => t.key_id(),
            Date::Unknown => Default::default(),
        }
    }

    fn ciphertext_version(&self) -> u32 {
        match self {
            Date::v1(_) => 1,
            Date::Unknown => 0,
        }
    }
}
