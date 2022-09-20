use serde::{Deserialize, Serialize};

use super::i64v1::I64v1;
use super::TypeError;
use crate::Field;

#[derive(Debug, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
pub enum I64 {
    #[allow(non_camel_case_types)]
    v1(I64v1),
}

impl I64 {
    pub fn new(i: i64, context: &[u8], field: &Field) -> Result<I64, TypeError> {
        Ok(I64::v1(I64v1::new(i, context, field)?))
    }

    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<i64, TypeError> {
        match self {
            I64::v1(i) => i.decrypt(context, field),
        }
    }
}
