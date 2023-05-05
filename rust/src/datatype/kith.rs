//! Manage a collection of encrypted values that all represent the same plaintext
//!
//! There are times when it is important to be able to provide more than one representation of a
//! particular datum.  The canonical case is when encrypting the same value under multiple
//! different keys, so that a data set consisting of elements generated using these various keys,
//! can be efficiently queried for a given value.  Another use-case is to be able to query a data
//! set containing different *versions* of ciphertexts (say, during a period of upgrade) by
//! sending both `v1` and `v2` encryptions of a value.
//!
//! For these cases, it's useful to be able to ship all those variants of the same value in a
//! collection which is able to provide the appropriate ciphertext for comparison as-needed.
//!

use serde::{Deserialize, Serialize};

use crate::field::KeyId;

/// A collection of encrypted values that all represent the same plaintext
///
/// The `Kith` (as in "kith and kin") is a collection of encrypted representations of the same
/// plaintext value.  It is parameterised on a type of comparable ciphertext, `CT`, such as an
/// order-revealing ciphertext (`ORE`) or equality-revealing ciphertext (`ERE`).
///
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "CT: for<'a> Deserialize<'a>")]
pub struct Kith<CT>
where
    CT: std::fmt::Debug + Serialize + for<'a> Deserialize<'a>,
{
    /// The encrypted variants of the plaintext value that are available
    members: Vec<CT>,
}

impl<CT> Kith<CT>
where
    CT: Member + Clone,
{
    /// Create an empty `Kith`
    ///
    #[must_use]
    pub fn new() -> Self {
        Self { members: vec![] }
    }

    /// Create a `Kith` from a vector of existing ciphertexts
    ///
    pub fn new_from_vec(v: &[CT]) -> Self {
        Self {
            members: v.to_vec(),
        }
    }

    /// Add a new comparable ciphertext to the `Kith`.
    ///
    /// Panics if the capacity of the underlying vec of members would exceed `isize::MAX` bytes.
    ///
    pub fn add_member(&mut self, m: CT) {
        self.members.push(m);
    }

    /// Try and find a compatible ciphertext
    ///
    /// If no compatible ciphertext is found, then `None` is returned.
    ///
    pub fn compatible_member<DT>(&self, other: &DT) -> Option<CT>
    where
        DT: Datatype,
    {
        self.members
            .iter()
            .find(|m| m.is_compatible(other))
            .cloned()
    }
}

impl<CT> Default for Kith<CT>
where
    CT: Member + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

/// The functionality required of a comparable ciphertext type in order to be able to be be
/// included in a `Kith`.
///
#[doc(hidden)]
pub trait Member: Datatype + std::fmt::Debug + Serialize + for<'a> Deserialize<'a> {
    /// Determine whether this element of the value set can be meaningfully compared with the value
    /// represented by `other`.
    fn is_compatible<DT: Datatype>(&self, other: &DT) -> bool {
        self.key_id() == other.key_id() && self.ciphertext_version() == other.ciphertext_version()
    }
}

/// The functionality required on a data type to be able to compare it against the ciphertexts in a
/// `Kith`.
#[doc(hidden)]
pub trait Datatype {
    /// Return the ID of the key that created this data type
    ///
    fn key_id(&self) -> KeyId;

    /// Return a numeric indicator of the version of this data type
    fn ciphertext_version(&self) -> u32;
}
