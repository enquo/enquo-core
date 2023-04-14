use crate::Error;

pub fn generate_sort_key(text: &str) -> Result<Vec<u8>, Error> {
    Ok(text.as_bytes().to_vec())
}
