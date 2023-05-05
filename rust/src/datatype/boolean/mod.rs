//! Store and query encrypted booleans
//!

mod v1;

use serde::{Deserialize, Serialize};

use self::v1::V1;
use crate::{datatype::kith::Datatype as KithDatatype, field::KeyId, Error, Field};

/// An encrypted queryable boolean
///
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[allow(missing_docs, clippy::missing_docs_in_private_items)] // I think we can figure it out from the name
#[non_exhaustive]
pub enum Boolean {
    #[allow(non_camel_case_types)]
    v1(Box<V1>),
    Unknown,
}

impl Boolean {
    /// Create a new encrypted, queryable boolean
    ///
    #[doc = include_str!("../encryption_contexts.md")]
    ///
    /// # Errors
    ///
    /// Can return an error if the process of encrypting the data fails.
    ///
    pub fn new(boolean: bool, context: &[u8], field: &Field) -> Result<Boolean, Error> {
        Ok(Boolean::v1(Box::new(V1::new(boolean, context, field)?)))
    }

    /// Create a new encrypted, queryable boolean with degraded security
    ///
    /// While the encrypted boolean value itself is securely encrypted, the ciphertexts produced by
    /// this function may contain components that allow an attacker to infer the value.
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
        boolean: bool,
        context: &[u8],
        field: &Field,
    ) -> Result<Boolean, Error> {
        Ok(Boolean::v1(Box::new(V1::new_with_unsafe_parts(
            boolean, context, field,
        )?)))
    }

    /// Get the plaintext boolean value from the encrypted ciphertext
    ///
    /// The `context` parameter must match the value of the `context` parameter passed to
    /// `Boolean::new()` when this ciphertext was created.
    ///
    /// # Errors
    ///
    /// Can return an error if the value could not be successfully decrypted, which may happen
    /// because the wrong field was used, or because the decryption context was incorrect.  See
    /// [`Boolean::new()`](Boolean::new) for more details about encryption and decryption contexts.
    ///
    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<bool, Error> {
        match self {
            Boolean::v1(t) => t.decrypt(context, field),
            Boolean::Unknown => Err(Error::UnknownVersionError()),
        }
    }

    /// Remove the ability to perform any queries on this boolean
    ///
    /// Sometimes you just want to be able to store a safely encrypted boolean, without any ability
    /// to query it.  In that case, you can save a bit of space by calling this method before
    /// serialisation.
    ///
    /// # Errors
    ///
    /// Can return an error if somehow a value of unknown version is used.
    ///
    pub fn make_unqueryable(&mut self) -> Result<(), Error> {
        match self {
            Boolean::v1(t) => {
                t.make_unqueryable();
                Ok(())
            }
            Boolean::Unknown => Err(Error::UnknownVersionError()),
        }
    }
}

impl KithDatatype for Boolean {
    fn key_id(&self) -> KeyId {
        match self {
            Boolean::v1(t) => t.key_id(),
            Boolean::Unknown => Default::default(),
        }
    }

    fn ciphertext_version(&self) -> u32 {
        match self {
            Boolean::v1(_) => 1,
            Boolean::Unknown => 0,
        }
    }
}
