//! The `Enquo::RootKey` Ruby module
//!

use enquo_core::{key_provider, key_provider::KeyProvider};
use magnus::{class, encoding, exception, function, prelude::*, RModule};
use std::ops::Deref;
use std::sync::Arc;

use crate::{maybe_raise, string_to_bytes};

/// The key provided to the Root from which all other keys are derived
#[magnus::wrap(class = "Enquo::RootKey")]
pub(crate) struct RootKey(Arc<dyn KeyProvider>);

impl Deref for RootKey {
    type Target = Arc<dyn KeyProvider>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Creates a `RootKey::Static` instance from the key provided
fn new_static_root_key(k_str: magnus::RString) -> Result<RootKey, magnus::Error> {
    let encindex = k_str.enc_get();

    let k: &[u8] = &if encindex == encoding::Index::ascii8bit() {
        if k_str.len() == 32 {
            Ok(string_to_bytes(k_str))
        } else {
            Err(magnus::Error::new(
                exception::arg_error(),
                "binary key string must be exactly 32 bytes long".to_string(),
            ))
        }
    } else if encindex == encoding::Index::utf8() || encindex == encoding::Index::usascii() {
        if k_str.len() == 64 {
            Ok(hex::decode(string_to_bytes(k_str)).map_err(|e| {
                magnus::Error::new(
                    exception::arg_error(),
                    format!("hex key must only contain valid hex characters: {e}"),
                )
            })?)
        } else {
            Err(magnus::Error::new(
                exception::arg_error(),
                format!(
                    "hex key string must be exactly 64 characters long (got {} characters)",
                    k_str.len()
                ),
            ))
        }
    } else {
        Err(magnus::Error::new(
            exception::encoding_error(),
            "key string must be encoded as BINARY or UTF-8".to_string(),
        ))
    }?;

    let mut key: [u8; 32] = Default::default();
    key.copy_from_slice(k);

    Ok(RootKey(Arc::new(maybe_raise(
        key_provider::Static::new(&key),
        None,
    )?)))
}

/// Create the `Enquo::RootKey` class and wire in its methods
pub(crate) fn init(base: RModule) -> Result<(), magnus::Error> {
    let base_class = base.define_class("RootKey", class::object())?;

    {
        let class = base_class.define_class("Static", base_class)?;
        class.define_singleton_method("new", function!(new_static_root_key, 1))?;
    }

    Ok(())
}
