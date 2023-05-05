//! The source of all Enquo-related goodness
//!
use std::sync::Arc;

use crate::{Error, Field, KeyProvider};

/// The "root" of an Enquo deployment is the key from which all other keys are derived, and from
/// which the fields which encrypt data in particular ways are derived.  Most of the magic is done
/// elsewhere, this is just the tree in which all the fairies live.
///
#[derive(Debug)]
pub struct Root {
    /// That which generates keys derived directly from the root, such as the field keys
    key_provider: Arc<dyn KeyProvider>,
}

impl Root {
    /// Create a new Enquo root.
    ///
    /// As the keys that secure all the encryption can come from many different places, the actual
    /// work of generating keys is delegated to a generic provider-of-keys.
    ///
    /// # Errors
    ///
    /// This function can't fail at the moment, but it is expected that in the future creating a
    /// `Root` will become more complicated, at which point something may be able to fail.
    ///
    pub fn new(key_provider: Arc<dyn KeyProvider>) -> Result<Root, Error> {
        Ok(Root { key_provider })
    }

    /// Generates a new key derived from the root key, based on `id`, and writes it into
    /// `derived_key`.
    ///
    /// # Errors
    ///
    /// Can return an error if the key provider is unable to complete the operation successfully,
    /// say due to a cryptographic error or a problem with the secure key store.
    ///
    pub(crate) fn derive_key(&self, derived_key: &mut [u8], id: &[u8]) -> Result<(), Error> {
        self.key_provider.derive_key(derived_key, id)
    }

    /// Create a new field for the given collection and name.
    ///
    /// A field is simply an abstraction for "a bunch of data that should all be comparable
    /// together".  For an RDBMS, for example, that would likely be a column, where `collection` is
    /// the table name and `name` is the column name.  Most other data storage systems have similar
    /// abstractions.  There's also nothing stopping you from encoding more information in either
    /// `collection` or `name` as you need to; as long as all the data you want to be able to query
    /// together shares the same `collection` and `name`, you'll be fine.
    ///
    /// # Errors
    ///
    /// Can return an error if generating the key for the field failed for some reason, such as a
    /// cryptographic failure or a problem communicating with the secure key store.
    ///
    pub fn field(&self, collection: &[u8], name: &[u8]) -> Result<Field, Error> {
        Field::new(self, collection, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_provider::Static;
    use std::sync::Arc;

    #[test]
    fn generates_a_field() {
        let k = Static::new(&[0; 32]).unwrap();
        let root = Root::new(Arc::new(k)).unwrap();
        root.field(b"users", b"full_name").unwrap();
    }
}
