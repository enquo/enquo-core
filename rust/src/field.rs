use crate::{key_provider::Static, Error, KeyProvider, Root};

pub struct Field {
    field_key: Static,
}

impl Field {
    pub fn new(root: &Root, collection: &[u8], name: &[u8]) -> Result<Field, Error> {
        let field_key = Self::field_key(root, collection, name)?;

        Ok(Field {
            field_key: Static::new(&field_key),
        })
    }

    pub fn subkey(&self, identifier: &[u8]) -> Result<Vec<u8>, Error> {
        self.field_key.derive_key(identifier)
    }

    pub fn key_id(&self) -> Result<Vec<u8>, Error> {
        Ok(self.field_key.derive_key(b"Field.key_id")?[0..4].to_vec())
    }

    fn field_key(root: &Root, collection: &[u8], name: &[u8]) -> Result<Vec<u8>, Error> {
        let mut id = Vec::<u8>::with_capacity(collection.len() + name.len() + 1);
        id.extend(collection);
        id.push(0);
        id.extend(name);
        root.derive_key(&id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_provider::Static;
    use hex_literal::hex;

    #[test]
    fn derives_field_key_correctly() {
        let rk = Static::new(b"testkey");
        let f = Root::new(&rk)
            .unwrap()
            .field(b"users", b"full_name")
            .unwrap();

        assert_eq!(
            hex!["382beeb4093bc280 163017113af33e12 ca5d55b84e42e1b9 758d66ddcbd9b9d8"].to_vec(),
            f.field_key.key()
        );
    }
}
