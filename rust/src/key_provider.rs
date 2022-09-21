mod slice;

use crate::Error;

pub trait KeyProvider {
    fn derive_key(&self, id: &[u8]) -> Result<Vec<u8>, Error>;
}
