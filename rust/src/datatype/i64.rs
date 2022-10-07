use serde::{Deserialize, Serialize};

use super::i64v1::I64v1;
use crate::{Error, Field};

#[derive(Debug, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
pub enum I64 {
    #[allow(non_camel_case_types)]
    v1(I64v1),
    Unknown,
}

impl I64 {
    pub fn new(i: i64, context: &[u8], field: &Field) -> Result<I64, Error> {
        Ok(I64::v1(I64v1::new(i, context, field)?))
    }

    pub fn new_with_unsafe_parts(i: i64, context: &[u8], field: &Field) -> Result<I64, Error> {
        Ok(I64::v1(I64v1::new_with_unsafe_parts(i, context, field)?))
    }

    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<i64, Error> {
        match self {
            I64::v1(i) => i.decrypt(context, field),
            I64::Unknown => panic!("Can't decrypt Unknown version"),
        }
    }

    pub fn make_unqueryable(&mut self) {
        match self {
            I64::v1(i) => i.make_unqueryable(),
            I64::Unknown => panic!("Can't make Unknown version unqueryable"),
        }
    }
}
