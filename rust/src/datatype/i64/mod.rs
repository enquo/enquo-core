//! An encrypted, yet queryable, signed 64-bit integer
//!

mod v1;

use serde::{Deserialize, Serialize};

use self::v1::V1;
use crate::{datatype::kith::Datatype as KithDatatype, field::KeyId, Error, Field};

/// Signed 64-bit encrypted integer
#[derive(Debug, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[allow(
    clippy::large_enum_variant,
    missing_docs,
    clippy::missing_docs_in_private_items
)] // ThisIsFineDog.jpg
#[non_exhaustive]
pub enum I64 {
    #[allow(non_camel_case_types)]
    v1(V1),
    Unknown,
}

impl I64 {
    /// Create a new encrypted, queryable signed 64-bit integer
    ///
    #[doc = include_str!("../encryption_contexts.md")]
    ///
    /// # Errors
    ///
    /// Can return an error if the process of encrypting the data fails.
    ///
    pub fn new(i: i64, context: &[u8], field: &Field) -> Result<I64, Error> {
        Ok(I64::v1(V1::new(i, context, field)?))
    }

    /// Create a new encrypted, queryable signed 64-bit integer with degraded security
    ///
    /// While the value itself is securely encrypted, the ciphertexts produced by this function may
    /// contain components that allow an attacker to infer, either precisely or approximately, the
    /// plaintext value.
    ///
    /// See [the Enquo threat model](https://enquo.org/threat-models/) for more details.
    ///
    #[doc = include_str!("../encryption_contexts.md")]
    ///
    /// # Errors
    ///
    /// Can return an error if the process of encrypting the data fails.
    ///
    pub fn new_with_unsafe_parts(i: i64, context: &[u8], field: &Field) -> Result<I64, Error> {
        Ok(I64::v1(V1::new_with_unsafe_parts(i, context, field)?))
    }

    /// Extract the value of the integer from the ciphertext
    ///
    /// The `context` parameter must match the value of the `context` parameter passed to
    /// `Text::new()` when this ciphertext was created.
    ///
    /// # Errors
    ///
    /// Can return an error if the value could not be successfully decrypted, which may happen
    /// because the wrong field was used, or because the decryption context was incorrect.  See
    /// [`I64::new()`](I64::new) for more details about encryption and decryption contexts.
    ///
    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<i64, Error> {
        match self {
            I64::v1(i) => i.decrypt(context, field),
            I64::Unknown => Err(Error::UnknownVersionError()),
        }
    }

    /// Remove the ability to perform any queries on this encrypted value
    ///
    /// Sometimes you just want to be able to store a safely encrypted number, without any ability
    /// to query it.  In that case, you can save some space by calling this method before
    /// serialisation.
    ///
    /// # Errors
    ///
    /// Can return an error if for some unfathomable reason the ciphertext cannot be made
    /// unqueryable, such as if an attempt is made to make an Unknown version ciphertext
    /// unqueryable.
    ///
    pub fn make_unqueryable(&mut self) -> Result<(), Error> {
        match self {
            I64::v1(i) => {
                i.make_unqueryable();
                Ok(())
            }
            I64::Unknown => Err(Error::UnknownVersionError()),
        }
    }
}

impl KithDatatype for I64 {
    fn key_id(&self) -> KeyId {
        match self {
            I64::v1(i) => i.key_id(),
            I64::Unknown => Default::default(),
        }
    }

    fn ciphertext_version(&self) -> u32 {
        match self {
            I64::v1(_) => 1,
            I64::Unknown => 0,
        }
    }
}
