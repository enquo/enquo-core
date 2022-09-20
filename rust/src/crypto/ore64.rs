use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

use super::ore64v1::ORE64v1;
use crate::{Error, Field};

#[derive(Debug, Serialize, Deserialize)]
pub enum ORE64 {
    #[allow(non_camel_case_types)]
    v1(ORE64v1),
}

impl ORE64 {
    pub fn new(u: u64, context: &[u8], field: &Field) -> Result<ORE64, Error> {
        Ok(ORE64::v1(ORE64v1::new(u, context, field)?))
    }

    pub fn cmp(&self, other: &Self) -> Ordering {
        match self {
            ORE64::v1(vs) => match other {
                ORE64::v1(vo) => vs.cmp(vo),
            },
        }
    }
}
