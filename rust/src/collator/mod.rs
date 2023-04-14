#[cfg_attr(feature = "icu", path = "icu.rs")]
#[cfg_attr(not(feature = "icu"), path = "lexicographic.rs")]
mod c;

pub(crate) use c::*;
