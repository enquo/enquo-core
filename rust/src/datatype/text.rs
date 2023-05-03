use serde::{Deserialize, Serialize};
use std::hash::Hash;

use super::text_v1::TextV1;
use crate::{Error, Field, ValueFrom, ValueSet, ORE};

#[derive(Debug, Hash, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
pub enum Text {
    #[allow(non_camel_case_types)]
    v1(Box<TextV1>),
    Unknown,
}

impl Text {
    pub fn new(text: &str, context: &[u8], field: &Field) -> Result<Text, Error> {
        Ok(Text::v1(Box::new(TextV1::new(text, context, field)?)))
    }

    pub fn new_with_unsafe_parts(
        text: &str,
        context: &[u8],
        field: &Field,
        ordering: Option<u8>,
    ) -> Result<Text, Error> {
        Ok(Text::v1(Box::new(TextV1::new_with_unsafe_parts(
            text, context, field, ordering,
        )?)))
    }

    pub fn length(&self) -> Option<ORE<8, 16>> {
        match self {
            Text::v1(t) => t.length.as_ref().map(|l| ValueFrom::from(&t.key_id, l)),
            Text::Unknown => None,
        }
    }

    pub fn query_length(len: u32, field: &Field) -> Result<ValueSet<ORE<8, 16>>, Error> {
        vec![ValueFrom::from(
            &field.key_id()?,
            &TextV1::ore_length(len, field, true)?,
        )]
        .try_into()
    }

    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<String, Error> {
        match self {
            Text::v1(t) => t.decrypt(context, field),
            Text::Unknown => Err(Error::UnknownVersionError()),
        }
    }

    pub fn make_unqueryable(&mut self) -> Result<(), Error> {
        match self {
            Text::v1(t) => t.make_unqueryable(),
            Text::Unknown => Err(Error::UnknownVersionError()),
        }
    }
}
