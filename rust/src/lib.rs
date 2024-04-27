//! # Queryable Encryption for Everyone
//!
//! This is the Rust library that provides the core functionality required for the entireity of
//! [the Enquo project](https://enquo.org).  The primary types you'll want to use are:
//!
//! * [`Root`], which is the holder of the root key (from which all other encryption keys are
//!   derived), and can create [`Field`]s that are what does the actual encryption;
//!
//! * [`Field`], which represents a collection of values that should be queryable as a group (such as
//!   a column of data in an RDBMS table); and
//!
//! * The various datatypes, which live under [`datatype`], and which represent common forms of
//!   data that you may wish to encrypt and query.
//!

pub mod datatype;
pub mod key_provider;

mod collator;
mod crypto;
mod error;
mod field;
mod root;
mod util;

#[doc(inline)]
pub use crate::{error::Error, field::Field, key_provider::KeyProvider, root::Root};

#[doc(hidden)]
pub use crate::crypto::{AES256v1, EREv1, OREv1};

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
#[cfg(test)]
// Only used in doctests
use rand as _;
