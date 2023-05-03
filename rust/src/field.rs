use crate::{key_provider::Static, Error, KeyProvider, Root};

pub struct Field {
    field_key: Static,
}

impl Field {
    pub fn new(root: &Root, collection: &[u8], name: &[u8]) -> Result<Field, Error> {
        Ok(Field {
            field_key: Self::field_key_provider(root, collection, name)?,
        })
    }

    pub fn subkey(&self, subkey: &mut [u8], identifier: &[u8]) -> Result<(), Error> {
        self.field_key.derive_key(subkey, identifier)
    }

    pub fn key_id(&self) -> Result<Vec<u8>, Error> {
        let mut id: [u8; 4] = Default::default();
        self.field_key.derive_key(&mut id, b"Field.key_id")?;
        Ok(id.to_vec())
    }

    fn field_key_provider(root: &Root, collection: &[u8], name: &[u8]) -> Result<Static, Error> {
        let mut id = Vec::<u8>::with_capacity(collection.len() + name.len() + 1);

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

        assert_eq!(hex!["494d15e1"].to_vec(), f.key_id().unwrap());
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
