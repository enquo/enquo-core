use serde::{Deserialize, Serialize};
use std::hash::Hash;

use super::text_v1::TextV1;
use crate::{Error, Field};

#[derive(Debug, Hash, Serialize, Deserialize, Eq, PartialEq)]
pub enum Text {
    #[allow(non_camel_case_types)]
    v1(Box<TextV1>),
    Unknown,
}

impl Text {
    pub fn new(text: &str, context: &[u8], field: &Field) -> Result<Text, Error> {
        Ok(Text::v1(Box::new(TextV1::new(text, context, field)?)))
    }

    pub fn new_with_unsafe_parts(text: &str, context: &[u8], field: &Field) -> Result<Text, Error> {
        Ok(Text::v1(Box::new(TextV1::new_with_unsafe_parts(
            text, context, field,
        )?)))
    }

    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<String, Error> {
        match self {
            Text::v1(t) => t.decrypt(context, field),
            Text::Unknown => panic!("Can't decrypt Unknown version"),
        }
    }

    pub fn make_unqueryable(&mut self) {
        match self {
            Text::v1(t) => t.make_unqueryable(),
            Text::Unknown => panic!("Can't clear_left_ciphertexts from Unknown version"),
        }
    }
}
