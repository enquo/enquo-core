use serde::{Deserialize, Serialize};

use super::boolean_v1::BooleanV1;
use crate::{Error, Field};

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum Boolean {
    #[allow(non_camel_case_types)]
    v1(Box<BooleanV1>),
    Unknown,
}

impl Boolean {
    pub fn new(boolean: bool, context: &[u8], field: &Field) -> Result<Boolean, Error> {
        Ok(Boolean::v1(Box::new(BooleanV1::new(
            boolean, context, field,
        )?)))
    }

    pub fn new_with_unsafe_parts(
        boolean: bool,
        context: &[u8],
        field: &Field,
    ) -> Result<Boolean, Error> {
        Ok(Boolean::v1(Box::new(BooleanV1::new_with_unsafe_parts(
            boolean, context, field,
        )?)))
    }

    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<bool, Error> {
        match self {
            Boolean::v1(t) => t.decrypt(context, field),
            Boolean::Unknown => panic!("Can't decrypt Unknown version"),
        }
    }

    pub fn make_unqueryable(&mut self) {
        match self {
            Boolean::v1(t) => t.make_unqueryable(),
            Boolean::Unknown => panic!("Can't clear_left_ciphertexts from Unknown version"),
        }
    }
}
