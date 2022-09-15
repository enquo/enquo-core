use thiserror::Error;
use crate::Field;

pub struct Crypto {
    key: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Could not create new Crypto instance: {0}")]
    NewError(String),
}

impl Crypto {
    pub fn new(key: Vec<u8>) -> Result<Crypto, CryptoError> {
        Ok(Crypto { key: key })
    }

    pub fn field(&self, collection: String, name: String) -> Field {
        Field::new(&self.key, collection, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_field() {
        let crypto = Crypto::new(vec![0, 0, 0, 0]).unwrap();
        crypto.field("users".to_string(), "full_name".to_string());
    }
}
