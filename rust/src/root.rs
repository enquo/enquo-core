use crate::{Error, Field, KeyProvider};

pub struct Root<'a> {
    pub key_provider: &'a dyn KeyProvider,
}

impl Root<'_> {
    pub fn new(key_provider: &dyn KeyProvider) -> Result<Root, Error> {
        Ok(Root { key_provider })
    }

    pub fn derive_key(&self, id: &[u8]) -> Result<Vec<u8>, Error> {
        self.key_provider.derive_key(id)
    }

    pub fn field(&self, collection: &[u8], name: &[u8]) -> Result<Field, Error> {
        Field::new(self, collection, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_field() {
        let k: &[u8] = &[0; 32];
        let root = Root::new(&k).unwrap();
        root.field(b"users", b"full_name").unwrap();
    }
}
