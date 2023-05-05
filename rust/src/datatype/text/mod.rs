//! Store and query UTF-8 encoded text in an encrypted form
//!

mod v1;

use serde::{Deserialize, Serialize};
use std::hash::Hash;

use self::v1::V1;
use crate::{
    datatype::kith::{Datatype as KithDatatype, Kith},
    datatype::ORE,
    field::KeyId,
    Error, Field,
};

/// Generic UTF-8 text
#[derive(Debug, Hash, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[allow(missing_docs, clippy::missing_docs_in_private_items)] // I think we can figure it out from the name
#[non_exhaustive]
pub enum Text {
    #[allow(non_camel_case_types)]
    v1(Box<V1>),
    Unknown,
}

impl Text {
    /// Create a new encrypted, queryable UTF-8 text
    ///
    #[doc = include_str!("../encryption_contexts.md")]
    ///
    /// # Errors
    ///
    /// Can return an error if the process of encrypting the data fails.
    ///
    pub fn new(text: &str, context: &[u8], field: &Field) -> Result<Text, Error> {
        Ok(Text::v1(Box::new(V1::new(text, context, field)?)))
    }

    /// Create a new encrypted, queryable UTF-8 text with degraded security
    ///
    /// While the text itself is securely encrypted, the ciphertexts produced by this function may
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
        text: &str,
        context: &[u8],
        field: &Field,
        ordering: Option<u8>,
    ) -> Result<Text, Error> {
        Ok(Text::v1(Box::new(V1::new_with_unsafe_parts(
            text, context, field, ordering,
        )?)))
    }

    /// Get the encrypted length of the text
    ///
    /// The "length" of a text is defined as the number of Unicode Scalar Values present in the
    /// text.  That will in most, but not *all* cases, correspond to the number of "characters" in
    /// the text, if your idea of "character" is actually "grapheme cluster".
    ///
    /// This method returns this length as an orderable encrypted ciphertext, so you can search for
    /// texts that have lengths within a certain range, and sort a collection of texts by their
    /// length (iff those ciphertexts were all encrypted with unsafe parts).
    ///
    /// If the text has been made unqueryable, this method will return `None`.
    ///
    #[must_use]
    pub fn length(&self) -> Option<ORE<8, 16>> {
        match self {
            Text::v1(t) => t.length().map(|l| ORE::from_ore_v1(l, t.key_id())),
            Text::Unknown => None,
        }
    }

    /// Generate a set of encrypted values suitable for comparing against text lengths
    ///
    /// Since every element of an Enquo ciphertext is encrypted with a unique key, you can't just
    /// compare a text's length against any old encrypted number you happen to have.  The number
    /// must be encrypted with the correct field, and for the correct element of the ciphertext.
    ///
    /// This function encrypts a length value for texts which were encrypted using the same field
    /// that is passed in.
    ///
    /// # Errors
    ///
    /// Can return an error if the encryption process fails.
    ///
    pub fn query_length(len: u32, field: &Field) -> Result<Kith<ORE<8, 16>>, Error> {
        let mut k = Kith::new();
        k.add_member(ORE::from_ore_v1(
            V1::ore_length(len, field, true)?,
            field.key_id()?,
        ));
        Ok(k)
    }

    /// Decrypt a text
    ///
    /// The `context` parameter must match the value of the `context` parameter passed to
    /// `Text::new()` when this ciphertext was created.
    ///
    /// # Errors
    ///
    /// Can return an error if the value could not be successfully decrypted, which may happen
    /// because the wrong field was used, or because the decryption context was incorrect.  See
    /// [`Text::new()`](Text::new) for more details about encryption and decryption contexts.
    ///
    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<String, Error> {
        match self {
            Text::v1(t) => t.decrypt(context, field),
            Text::Unknown => Err(Error::UnknownVersionError()),
        }
    }

    /// Remove the ability to perform any queries on this text
    ///
    /// Sometimes you just want to be able to store a safely encrypted text, without any ability to
    /// query it.  In that case, you can save a whole pile of space by calling this method, which
    /// strips all the query-related ciphertexts, leaving you with an AES-256-encrypted UTF-8
    /// text to call your very own.
    ///
    /// # Errors
    ///
    /// Can return an error if somehow a value of unknown version is used.
    ///
    pub fn make_unqueryable(&mut self) -> Result<(), Error> {
        match self {
            Text::v1(t) => {
                t.make_unqueryable();
                Ok(())
            }
            Text::Unknown => Err(Error::UnknownVersionError()),
        }
    }
}

impl KithDatatype for Text {
    fn key_id(&self) -> KeyId {
        match self {
            Text::v1(t) => t.key_id(),
            Text::Unknown => Default::default(),
        }
    }

    fn ciphertext_version(&self) -> u32 {
        match self {
            Text::v1(_) => 1,
            Text::Unknown => 0,
        }
    }
}
