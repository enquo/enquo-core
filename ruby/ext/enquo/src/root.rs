//! The home of the `Enquo::Root` class
//!

use enquo_core::KeyProvider;
use magnus::{class, function, method, prelude::*, RModule};
use std::{ops::Deref, sync::Arc};

use crate::{field::Field, maybe_raise, root_key::RootKey};

/// Wrapper struct for the enquo_core struct of the same name
#[magnus::wrap(class = "Enquo::Root")]
struct Root(enquo_core::Root);

impl Deref for Root {
    type Target = enquo_core::Root;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Root {
    /// Create a new root from a root key
    fn new(k: &RootKey) -> Result<Self, magnus::Error> {
        Ok(Self(maybe_raise(
            enquo_core::Root::new(Arc::<dyn KeyProvider>::clone(&**k)),
            None,
        )?))
    }

    /// Spawn a new `Enquo::Field`
    #[allow(clippy::needless_pass_by_value)] // Magnus is not friends with &str args
    fn field(&self, relation: String, name: String) -> Result<Field, magnus::Error> {
        Ok(Field(maybe_raise(
            self.0.field(relation.as_bytes(), name.as_bytes()),
            None,
        )?))
    }
}

/// Wire up everything for `Enquo::Root`
pub(crate) fn init(base: RModule) -> Result<(), magnus::Error> {
    let class = base.define_class("Root", class::object())?;

    class.define_singleton_method("new", function!(Root::new, 1))?;
    class.define_method("field", method!(Root::field, 2))?;
    Ok(())
}
