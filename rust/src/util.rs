//! Snippets that are used in various places that we don't have a more sensible home for
//!

use crate::Error;

/// Simple wrapper to detect overflowing arithmetic and return an error
pub(crate) fn check_overflow<T>(v: (T, bool), e: &str) -> Result<T, Error> {
    match v {
        (u, false) => Ok(u),
        (_, true) => Err(Error::OverflowError(e.to_string())),
    }
}
