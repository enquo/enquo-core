use rust_icu_sys::UColAttributeValue;
use rust_icu_ucol::UCollator;
use rust_icu_ustring::UChar;

use crate::Error;

pub fn generate_sort_key(text: &str) -> Result<Vec<u8>, Error> {
    let mut collator = UCollator::try_from("en")
        .map_err(|e| Error::CollationError(format!("could not create collator: {e}")))?;
    collator.set_strength(UColAttributeValue::UCOL_DEFAULT);
    let uc_text = UChar::try_from(text)
        .map_err(|e| Error::CollationError(format!("invalid text string: {e}")))?;

    Ok(collator.get_sort_key(&uc_text))
}
