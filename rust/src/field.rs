use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{
    r#type::{TypeError, I64},
    Root,
};

pub struct Field {
    key: Vec<u8>,
}

impl Field {
    pub fn new(root: &Root, collection: &[u8], name: &[u8]) -> Field {
        let key = Self::field_key(&root.key, collection, name);

        Field { key }
    }

    pub fn subkey(&self, identifier: &[u8]) -> Vec<u8> {
        Self::derive_key(&self.key, identifier)
    }

    pub fn key_id(&self) -> Vec<u8> {
        self.subkey(b"Field.key_id")[0..4].to_vec()
    }

    fn field_key(root_key: &[u8], collection: &[u8], name: &[u8]) -> Vec<u8> {
        let mut key_id = Vec::<u8>::with_capacity(collection.len() + name.len() + 1);
        key_id.extend(collection);
        key_id.push(0);
        key_id.extend(name);
        Self::derive_key(root_key, &key_id)
    }

    fn derive_key(base_key: &[u8], identifier: &[u8]) -> Vec<u8> {
        let mut keygen = Hmac::<Sha256>::new_from_slice(base_key).unwrap();
        keygen.update(identifier);

        keygen.finalize().into_bytes().to_vec()
    }

    pub fn i64(&self, i: i64, context: &[u8]) -> Result<I64, TypeError> {
        I64::new(i, context, self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn derives_field_key_correctly() {
        let f = Field::new(
            &Root {
                key: b"testkey".to_vec(),
            },
            b"users",
            b"full_name",
        );

        assert_eq!(
            hex!["382beeb4093bc280 163017113af33e12 ca5d55b84e42e1b9 758d66ddcbd9b9d8"].to_vec(),
            f.key
        );
    }
}
