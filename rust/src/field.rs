//! Build It and They Will Come
//!

use crate::{key_provider::Static, Error, KeyProvider, Root};

/// The type of the ID for a field key
///
/// The size of the ID space has been chosen to be large enough to make it practically impossible
/// for a collision to ever occur in real-world use.
///
pub(crate) type KeyId = [u8; 8];

/// The source of all encryption shenanigans.
///
/// Gets passed around like a doobie whenever we want to encrypt a data value.
///
#[derive(Debug)]
pub struct Field {
    /// The key from which all the component keys of the field's encryption are derived
    ///
    field_key: Static,
}

impl Field {
    /// Create a new Field
    ///
    /// Use `Root.field()` instead.
    ///
    /// # Errors
    ///
    /// Can return an error if the root can't derive the field key.
    ///
    pub(crate) fn new(root: &Root, collection: &[u8], name: &[u8]) -> Result<Field, Error> {
        Ok(Field {
            field_key: Self::field_key_provider(root, collection, name)?,
        })
    }

    /// Derive a specific subkey for some element of this field's cryptographic data.
    ///
    /// # Errors
    ///
    /// Can return an error if the key provider can't successfully derive the subkey, say because
    /// of a cryptographic error.
    ///
    pub(crate) fn subkey(&self, subkey: &mut [u8], identifier: &[u8]) -> Result<(), Error> {
        self.field_key.derive_key(subkey, identifier)
    }

    /// The ID of the key currently being used by this field
    ///
    /// Not part of the key itself, obviously, but a way to determine with a reasonable degree of
    /// confidence if the key used to encrypt a given data value is the same as the key in use on
    /// this field.
    ///
    /// # Errors
    ///
    /// Can return an error if the cryptographic operation involved in calculating the key ID fails
    /// for some reason.
    ///
    pub fn key_id(&self) -> Result<KeyId, Error> {
        let mut id: KeyId = Default::default();
        self.field_key.derive_key(&mut id, b"Field.key_id")?;
        Ok(id)
    }

    /// Create the provider for the key for this field
    ///
    /// As key providers do all the hard work of actually deriving new keys from a "base" key, a
    /// field needs a key provider to do that, which -- as field keys are local, can just be our
    /// bog-basic `Static` provider.
    ///
    /// # Errors
    ///
    /// Can crap out if the root can't derive the field key.
    ///
    fn field_key_provider(root: &Root, collection: &[u8], name: &[u8]) -> Result<Static, Error> {
        // Saturating math is fine because it's only a capacity calculation
        let mut id = Vec::<u8>::with_capacity(
            collection
                .len()
                .saturating_add(name.len())
                .saturating_add(1),
        );

        id.extend(collection);
        id.push(0);
        id.extend(name);

        let mut field_key: [u8; 32] = Default::default();
        root.derive_key(&mut field_key, &id)?;

        Static::new(&field_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_provider::Static;
    use hex_literal::hex;
    use std::sync::Arc;

    #[test]
    fn has_a_key_id() {
        let rk = Arc::new(Static::new(b"this is a suuuuper long test key").unwrap());
        let f = Root::new(rk)
            .unwrap()
            .field(b"users", b"full_name")
            .unwrap();

        assert_eq!(hex!["494d15e1 4ab748dd"], f.key_id().unwrap());
    }

    #[test]
    fn different_fields_have_different_key_ids() {
        let rk = Arc::new(Static::new(b"this is a suuuuper long test key").unwrap());
        let root = Root::new(rk).unwrap();
        let f1 = root.field(b"users", b"full_name").unwrap();
        let f2 = root.field(b"users", b"date_of_birth").unwrap();

        assert_ne!(f1.key_id().unwrap(), f2.key_id().unwrap());
    }

    #[test]
    fn generates_subkey() {
        let rk = Arc::new(Static::new(b"this is a suuuuper long test key").unwrap());
        let f = Root::new(rk)
            .unwrap()
            .field(b"users", b"full_name")
            .unwrap();

        let mut smol_sk: [u8; 4] = Default::default();
        f.subkey(&mut smol_sk, b"bob").unwrap();

        assert_eq!(hex!["f2c1753f"], smol_sk);

        let mut sk: [u8; 16] = Default::default();
        f.subkey(&mut sk, b"bob").unwrap();

        assert_eq!(hex!["f2c1753f 31c6cffe 6c387563 84ada729"], sk);

        let mut sk: [u8; 32] = Default::default();
        f.subkey(&mut sk, b"bob").unwrap();

        assert_eq!(
            hex!["f2c1753f 31c6cffe 6c387563 84ada729 480d6f9f 9dd228ae 5ccd833b b8eee70f"],
            sk
        );
    }
}
