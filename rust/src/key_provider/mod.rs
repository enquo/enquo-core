//! Where all the providers of keys live.
//!
mod r#static;
pub use r#static::Static;

use crate::Error;

/// What a key provider needs to be able to do.
///
/// Not much, really.
///
pub trait KeyProvider: Send + Sync + std::fmt::Debug {
    /// Deterministically generate cryptographic key material based on `id`
    ///
    /// Writes the key material into `subkey`.
    ///
    /// A key provider configured with the same "root" key (whether that be local key material, or
    /// a key stored in a secure environment and interacted with via some protocol) and given the
    /// same `id` should always generate the same `subkey`.
    ///
    /// The keys generated from a key provider may be used in situations requiring a security level
    /// of up to 256 bits.  Conduct yourself accordingly.
    ///
    /// # Errors
    ///
    /// Can return an error if the derivation process fails, say because of a cryptographic error
    /// or a failure to communicate with the secure key store.
    ///
    fn derive_key(&self, subkey: &mut [u8], id: &[u8]) -> Result<(), Error>;
}
