use crate::{EncryptedValue, ORE64v1};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub struct Field {
    key: Vec<u8>,
}

// AKA "2**63"
const I64_OFFSET: i128 = 9_223_372_036_854_775_808;

impl Field {
    pub fn new(root_key: &Vec<u8>, collection: String, name: String) -> Field {
        let key = Self::field_key(root_key, collection, name);

        Field{key}
    }

    pub fn subkey(&self, identifier: &[u8]) -> Vec<u8> {
        Self::derive_key(&self.key, identifier)
    }

    fn field_key(root_key: &[u8], collection: String, name: String) -> Vec<u8> {
        let mut key_id = Vec::<u8>::with_capacity(collection.len() + name.len() + 1);
        key_id.extend(collection.bytes());
        key_id.push(0);
        key_id.extend(name.bytes());
        Self::derive_key(&root_key, &key_id)
    }

    fn derive_key(base_key: &[u8], identifier: &[u8]) -> Vec<u8> {
        let mut keygen = Hmac::<Sha256>::new_from_slice(base_key).unwrap();
        keygen.update(identifier);

        keygen.finalize().into_bytes().to_vec()
    }

    pub fn encrypt_i64(&self, i: i64, ctx: &[u8]) -> EncryptedValue {
        let u = (i as i128) + I64_OFFSET;
        EncryptedValue::ORE64v1(ORE64v1::new(u.try_into().unwrap(), ctx, &self))
    }

    pub fn decrypt_i64(&self, value: EncryptedValue, ctx: &[u8]) -> Result<i64, String> {
        match value {
            EncryptedValue::ORE64v1(ore) => {
                let u = ore.decrypt(ctx, &self)?;
                Ok(((u as i128) - I64_OFFSET).try_into().unwrap())
            },
            _ => {
                Err(format!("Unsupported EncryptedValue variant {:?}", value))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Crypto;

    #[test]
    fn encrypts_an_i64_as_an_ore_v1() {
        let crypto = Crypto::new(vec![0, 0, 0, 0]).unwrap();
        let field = crypto.field("users".to_string(), "full_name".to_string());

        let value = field.encrypt_i64(42, b"test");

        assert!(matches!(value, EncryptedValue::ORE64v1(_)));
    }

    #[test]
    fn correctly_encodes_an_i64_for_ore_comparison() {
        let crypto = Crypto::new(vec![0, 0, 0, 0]).unwrap();
        let field = crypto.field("users".to_string(), "full_name".to_string());

        assert!(field.encrypt_i64(42, b"test") == field.encrypt_i64(42, b"test"));
        assert!(field.encrypt_i64(0, b"test") == field.encrypt_i64(0, b"test"));
        assert!(field.encrypt_i64(-42, b"test") == field.encrypt_i64(-42, b"test"));
        assert!(field.encrypt_i64(4200000000000000000, b"test") == field.encrypt_i64(4200000000000000000, b"test"));
        assert!(field.encrypt_i64(-4200000000000000000, b"test") == field.encrypt_i64(-4200000000000000000, b"test"));

        assert!(field.encrypt_i64(42, b"test") < field.encrypt_i64(420, b"test"));
        assert!(field.encrypt_i64(0, b"test") < field.encrypt_i64(42, b"test"));
        assert!(field.encrypt_i64(-42, b"test") < field.encrypt_i64(42, b"test"));
        assert!(field.encrypt_i64(-42, b"test") < field.encrypt_i64(0, b"test"));
        assert!(field.encrypt_i64(-4200000000000000000, b"test") < field.encrypt_i64(4200000000000000000, b"test"));
        assert!(field.encrypt_i64(-4200000000000000000, b"test") < field.encrypt_i64(0, b"test"));

        assert!(field.encrypt_i64(420, b"test") > field.encrypt_i64(42, b"test"));
        assert!(field.encrypt_i64(42, b"test") > field.encrypt_i64(-42, b"test"));
        assert!(field.encrypt_i64(42, b"test") > field.encrypt_i64(0, b"test"));
        assert!(field.encrypt_i64(0, b"test") > field.encrypt_i64(-42, b"test"));
        assert!(field.encrypt_i64(4200000000000000000, b"test") > field.encrypt_i64(-4200000000000000000, b"test"));
        assert!(field.encrypt_i64(4200000000000000000, b"test") > field.encrypt_i64(0, b"test"));
    }
}
