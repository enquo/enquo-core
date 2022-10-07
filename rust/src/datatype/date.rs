use serde::{Deserialize, Serialize};

use super::date_v1::DateV1;
use crate::{Error, Field};

#[derive(Debug, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
pub enum Date {
    #[allow(non_camel_case_types)]
    v1(Box<DateV1>),
    Unknown,
}

impl Date {
    pub fn new(date: (i16, u8, u8), context: &[u8], field: &Field) -> Result<Date, Error> {
        Ok(Date::v1(Box::new(DateV1::new(date, context, field)?)))
    }

    pub fn new_with_unsafe_parts(
        date: (i16, u8, u8),
        context: &[u8],
        field: &Field,
    ) -> Result<Date, Error> {
        Ok(Date::v1(Box::new(DateV1::new_with_unsafe_parts(
            date, context, field,
        )?)))
    }

    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<(i16, u8, u8), Error> {
        match self {
            Date::v1(d) => d.decrypt(context, field),
            Date::Unknown => panic!("Can't decrypt Unknown version"),
        }
    }

    pub fn make_unqueryable(&mut self) {
        match self {
            Date::v1(d) => d.make_unqueryable(),
            Date::Unknown => panic!("Can't make Unknown version unqueryable"),
        }
    }
}
