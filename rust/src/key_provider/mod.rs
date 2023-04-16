mod r#static;
pub use r#static::Static;

use crate::Error;

pub trait KeyProvider: Send + Sync {
    fn derive_key(&self, id: &[u8]) -> Result<Vec<u8>, Error>;
}
