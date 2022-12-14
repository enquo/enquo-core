mod crypto;
mod datatype;
mod error;
mod field;
pub mod key_provider;
mod root;

pub use crate::{datatype::*, error::Error, field::Field, key_provider::KeyProvider, root::Root};

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
