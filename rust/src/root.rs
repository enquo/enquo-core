use crate::{Error, Field};

pub struct Root {
    pub key: Vec<u8>,
}

impl Root {
    pub fn new(key: &[u8]) -> Result<Root, Error> {
        Ok(Root { key: key.to_vec() })
    }

    pub fn field(&self, collection: &[u8], name: &[u8]) -> Field {
        Field::new(self, collection, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_field() {
        let crypto = Root::new(&[0; 32]).unwrap();
        crypto.field(b"users", b"full_name");
    }
}
