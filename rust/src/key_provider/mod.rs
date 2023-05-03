mod r#static;
pub use r#static::Static;

use crate::Error;

pub trait KeyProvider: Send + Sync {
    fn derive_key(&self, subkey: &mut [u8], id: &[u8]) -> Result<(), Error>;
}
