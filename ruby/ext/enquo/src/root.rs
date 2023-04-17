use magnus::{class, function, method, prelude::*, RModule};
use std::ops::Deref;

use crate::{field::Field, maybe_raise, root_key::RootKey};

#[magnus::wrap(class = "Enquo::Root")]
struct Root(enquo_core::Root);

impl Deref for Root {
    type Target = enquo_core::Root;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Root {
    fn new(k: &RootKey) -> Result<Self, magnus::Error> {
        Ok(Self(maybe_raise(
            enquo_core::Root::new(k.deref().clone()),
            None,
        )?))
    }

    fn field(&self, relation: String, name: String) -> Result<Field, magnus::Error> {
        Ok(Field(maybe_raise(
            self.0.field(relation.as_bytes(), name.as_bytes()),
            None,
        )?))
    }
}

pub fn init(base: &RModule) -> Result<(), magnus::Error> {
    let class = base.define_class("Root", class::object())?;

    class.define_singleton_method("new", function!(Root::new, 1))?;
    class.define_method("field", method!(Root::field, 2))?;
    Ok(())
}
