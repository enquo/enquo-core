//! Collation support
//!
//! Figuring out how strings *should* be sorted is a fiddly job.  That's why we've locked it all
//! away in here.
//!

#[cfg(feature = "icu")]
use {rust_icu_sys::UColAttributeValue, rust_icu_ucol::UCollator, rust_icu_ustring::UChar};

use crate::Error;

/// Create a "sort key" for a given string, using ICU
///
/// A sort key is a value that transmogrifies the usual numeric values of characters in such a way
/// that, when you sort the sort keys using ordinary numeric lowest-to-highest, the corresponding
/// texts are sorted "correctly".
///
/// The problem is that "correctly" varies by language, geography, and even context (German
/// dictionaries are sorted differently to German telephone books, for example).  Luckily, ICU
/// ("Internationalization Components for Unicode") provide mechanisms for figuring all that out.
/// Unluckily, linking ICU into a Rust binary that is to be used by many people is a shitshow
/// (ICU bumps its soname like there's a prize for the highest version number).
///
/// All this is to say that, by default, there's a built-in collator that just returns ASCII
/// values for the ordering code, but that can be swapped out by building with the `icu` feature,
/// which instead causes this function to come into existence.
///
#[cfg(feature = "icu")]
pub(crate) fn generate_sort_key(text: &str, collation: &str) -> Result<Vec<u8>, Error> {
    let mut collator = UCollator::try_from(collation)
        .map_err(|e| Error::CollationError(format!("could not create collator: {e}")))?;
    collator.set_strength(UColAttributeValue::UCOL_DEFAULT);
    let uc_text = UChar::try_from(text)
        .map_err(|e| Error::CollationError(format!("invalid text string: {e}")))?;

    Ok(collator.get_sort_key(&uc_text))
}

/// The default sort key generator
///
/// If you don't want to go through the rigors of building with ICU, you can use this collator,
/// which sucks to a great degree, but provides at least a stable sort order.
///
#[cfg(not(feature = "icu"))]
#[allow(clippy::unnecessary_wraps)] // The ICU version of this function can crap out
pub(crate) fn generate_sort_key(text: &str, _collation: &str) -> Result<Vec<u8>, Error> {
    Ok(text.as_bytes().to_vec())
}
