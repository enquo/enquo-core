use ciborium::cbor;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use unicode_normalization::UnicodeNormalization;

use crate::{
    collator,
    crypto::{AES256v1, EREv1, OREv1},
    key_provider::{KeyProvider, Static},
    Error, Field,
};

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
pub struct TextV1 {
    #[serde(rename = "a")]
    pub aes_ciphertext: AES256v1,
    #[serde(rename = "e")]
    pub equality_ciphertext: Option<EREv1<16, 16, u64>>,
    #[serde(rename = "h")]
    pub hash_code: Option<u32>,
    #[serde(rename = "o")]
    pub order_code: Option<Vec<OREv1<1, 256, u8>>>,
    #[serde(rename = "l")]
    pub length: Option<OREv1<8, 16, u32>>,
    #[serde(rename = "k", with = "serde_bytes")]
    pub key_id: Vec<u8>,
}

const TEXT_V1_EQUALITY_HASH_KEY_IDENTIFIER: &[u8] = b"TextV1.equality_hash_key";
const TEXT_V1_EQUALITY_HASH_CIPHERTEXT_KEY_IDENTIFIER: &[u8] =
    b"TextV1.equality_hash_key_ciphertext";
const TEXT_V1_HASH_CODE_KEY_IDENTIFIER: &[u8] = b"TextV1.hash_code_key";
const TEXT_V1_ORDER_CODE_KEY_IDENTIFIER: &[u8] = b"TextV1.order_code_key";
const TEXT_V1_LENGTH_KEY_IDENTIFIER: &[u8] = b"TextV1.length_key";

impl TextV1 {
    pub fn new(text: &str, context: &[u8], field: &Field) -> Result<TextV1, Error> {
        Self::encrypt(text, context, field, false, None)
    }

    pub fn new_with_unsafe_parts(
        text: &str,
        context: &[u8],
        field: &Field,
        ordering: Option<u8>,
    ) -> Result<TextV1, Error> {
        Self::encrypt(text, context, field, true, ordering)
    }

    fn encrypt(
        text: &str,
        context: &[u8],
        field: &Field,
        allow_unsafe: bool,
        ordering: Option<u8>,
    ) -> Result<TextV1, Error> {
        let v = cbor!(text).map_err(|e| {
            Error::EncodingError(format!("failed to convert string to ciborium value: {e}"))
        })?;

        let mut msg: Vec<u8> = Default::default();
        ciborium::ser::into_writer(&v, &mut msg)
            .map_err(|e| Error::EncodingError(format!("failed to encode string value: {e}")))?;

        let aes = AES256v1::new(&msg, context, field)?;

        let normalised = text.nfc().collect::<String>();

        let eq_hash = Self::eq_hash(&normalised, field)?;
        let eq = Self::ere_eq_hash(eq_hash, field, allow_unsafe)?;

        let hc = if allow_unsafe {
            Some(Self::hash_code(&normalised, field)?)
        } else {
            None
        };

        let pt_len = <usize as TryInto<u32>>::try_into(text.chars().count()).map_err(|_| {
            Error::EncodingError("string length exceeds maximum allowed value".to_string())
        })?;
        let ore_len = Self::ore_length(pt_len, field, allow_unsafe)?;

        let order_code = Self::order_code(&normalised, ordering, field)?;

        Ok(TextV1 {
            aes_ciphertext: aes,
            equality_ciphertext: Some(eq),
            hash_code: hc,
            order_code,
            length: Some(ore_len),
            key_id: field.key_id()?,
        })
    }

    pub fn decrypt(&self, context: &[u8], field: &Field) -> Result<String, Error> {
        let pt = self.aes_ciphertext.decrypt(context, field)?;

        let s_text = ciborium::de::from_reader::<'_, String, &[u8]>(&*pt)
            .map_err(|e| Error::DecodingError(format!("could not decode decrypted value: {e}")))?;

        Ok(s_text)
    }

    pub fn make_unqueryable(&mut self) -> Result<(), Error> {
        self.equality_ciphertext = None;
        self.hash_code = None;
        self.length = None;
        Ok(())
    }

    fn eq_hash(text: &str, field: &Field) -> Result<u64, Error> {
        let k = field.subkey(TEXT_V1_EQUALITY_HASH_KEY_IDENTIFIER)?;
        let hasher = Static::new(&k);

        Ok(u64::from_be_bytes(
            hasher.derive_key(text.as_bytes())?[0..8]
                .try_into()
                .map_err(|_| {
                    Error::EncodingError(
                        "Failed to convert derived key into integer array".to_string(),
                    )
                })?,
        ))
    }

    fn ere_eq_hash(
        hc: u64,
        field: &Field,
        allow_unsafe: bool,
    ) -> Result<EREv1<16, 16, u64>, Error> {
        if allow_unsafe {
            Ok(EREv1::<16, 16, u64>::new_with_left(
                hc,
                TEXT_V1_EQUALITY_HASH_CIPHERTEXT_KEY_IDENTIFIER,
                field,
            )?)
        } else {
            Ok(EREv1::<16, 16, u64>::new(
                hc,
                TEXT_V1_EQUALITY_HASH_CIPHERTEXT_KEY_IDENTIFIER,
                field,
            )?)
        }
    }

    pub fn ore_length(
        len: u32,
        field: &Field,
        allow_unsafe: bool,
    ) -> Result<OREv1<8, 16, u32>, Error> {
        if allow_unsafe {
            Ok(OREv1::<8, 16, u32>::new_with_left(
                len,
                TEXT_V1_LENGTH_KEY_IDENTIFIER,
                field,
            )?)
        } else {
            Ok(OREv1::<8, 16, u32>::new(
                len,
                TEXT_V1_LENGTH_KEY_IDENTIFIER,
                field,
            )?)
        }
    }

    fn hash_code(text: &str, field: &Field) -> Result<u32, Error> {
        let k = field.subkey(TEXT_V1_HASH_CODE_KEY_IDENTIFIER)?;
        let hasher = Static::new(&k);

        Ok(u32::from_be_bytes(
            hasher.derive_key(text.as_bytes())?[0..4]
                .try_into()
                .map_err(|_| {
                    Error::EncodingError(
                        "Failed to convert derived key into integer array".to_string(),
                    )
                })?,
        ))
    }

    fn order_code(
        text: &str,
        ordering: Option<u8>,
        field: &Field,
    ) -> Result<Option<Vec<OREv1<1, 256, u8>>>, Error> {
        match ordering {
            None => Ok(None),
            Some(len) => {
                let sort_key = collator::generate_sort_key(text)?;

                let mut order_vec: Vec<OREv1<1, 256, u8>> = vec![];

                for i in 0..len {
                    let sort_key_component = sort_key.get(i as usize).unwrap_or(&0);
                    let v = OREv1::<1, 256, u8>::new_with_left(
                        *sort_key_component,
                        TEXT_V1_ORDER_CODE_KEY_IDENTIFIER,
                        field,
                    )?;
                    order_vec.push(v);
                }
                Ok(Some(order_vec))
            }
        }
    }
}

impl Hash for TextV1 {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash_code
            .expect("cannot hash a Text value without a hash code")
            .hash(state);
    }
}

impl Ord for TextV1 {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.key_id != other.key_id {
            panic!("Cannot compare ciphertexts from different keys");
        }

        let lhs = self
            .order_code
            .as_ref()
            .expect("Cannot compare without an ordering code on the left-hand side");
        let rhs = other
            .order_code
            .as_ref()
            .expect("Cannot compare without an ordering code on the right-hand side");

        lhs.cmp(rhs)
    }
}

impl PartialOrd for TextV1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for TextV1 {
    fn eq(&self, other: &Self) -> bool {
        if self.key_id != other.key_id {
            panic!("Cannot compare ciphertexts from different keys");
        }

        // While we'd ordinarily defer to cmp == Ordering::Equal in a PartialEq
        // implementation, in this case the order code is "less accurate"
        // than the equality ciphertext, and -- so far, at least -- you
        // can only get an orderable text value if you've also got an equality
        // ciphertext, so there's no chance of *having* to degrade.
        self.equality_ciphertext
            .as_ref()
            .expect("Cannot compare text values without LHS equality_ciphertext")
            == other
                .equality_ciphertext
                .as_ref()
                .expect("Cannot compare text values without RHS equality_ciphertext")
    }
}

impl Eq for TextV1 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::OREv1, key_provider::Static, Root};

    fn field() -> Field {
        Root::new(&Static::new(b"testkey"))
            .unwrap()
            .field(b"foo", b"bar")
            .unwrap()
    }

    #[test]
    fn value_round_trips() {
        let value = TextV1::new("Hello, Enquo!", b"context", &field()).unwrap();

        assert_eq!(
            "Hello, Enquo!",
            value.decrypt(b"context", &field()).unwrap()
        );
    }

    #[test]
    fn incorrect_context_fails() {
        let value = TextV1::new("Hello, Enquo!", b"somecontext", &field()).unwrap();

        let err = value.decrypt(b"othercontext", &field()).err();
        assert!(matches!(err, Some(Error::DecryptionError(_))));
    }

    #[test]
    fn ciphertexts_compare_correctly() {
        let text1 =
            TextV1::new_with_unsafe_parts("Hello, Enquo!", b"somecontext", &field(), None).unwrap();
        let text2 = TextV1::new("Hello, Enquo!", b"somecontext", &field()).unwrap();
        let text3 = TextV1::new("Goodbye, Enquo!", b"somecontext", &field()).unwrap();

        assert_eq!(text1, text2);
        assert_ne!(text1, text3);
    }

    #[test]
    fn hash_codes_compare_correctly() {
        let text1 = TextV1::new_with_unsafe_parts("Hello, Enquo!", b"", &field(), None).unwrap();
        let text2 = TextV1::new_with_unsafe_parts("Hello, Enquo!", b"", &field(), None).unwrap();
        let text3 = TextV1::new_with_unsafe_parts("Goodbye, Enquo!", b"", &field(), None).unwrap();

        assert_eq!(text1.hash_code.unwrap(), text2.hash_code.unwrap());
        assert_ne!(text1.hash_code.unwrap(), text3.hash_code.unwrap());
    }

    #[test]
    fn base_ascii_orderable_strings_compare_correctly() {
        let one = TextV1::new_with_unsafe_parts("one", b"1", &field(), Some(8)).unwrap();
        let two = TextV1::new_with_unsafe_parts("two", b"2", &field(), Some(8)).unwrap();
        let three = TextV1::new_with_unsafe_parts("three", b"3", &field(), Some(8)).unwrap();

        assert!(one == one);
        assert!(two == two);
        assert!(three == three);
        assert!(one < two);
        assert!(two > three);
        assert!(one < three);
    }

    #[cfg(feature = "icu")]
    mod icu_collation {
        use super::*;

        #[test]
        fn accented_orderable_strings_compare_correctly() {
            let first = TextV1::new_with_unsafe_parts(
                &String::from_utf8(b"R\xCC\x83amone".to_vec()).unwrap(),
                b"",
                &field(),
                Some(8),
            )
            .unwrap();
            let second = TextV1::new_with_unsafe_parts("Roman", b"", &field(), Some(8)).unwrap();

            assert!(first < second);
        }
    }

    #[cfg(not(feature = "icu"))]
    mod lexicographic_collation {
        use super::*;

        #[test]
        fn accented_orderable_strings_compare_weirdly() {
            let first = TextV1::new_with_unsafe_parts("Roman", b"", &field(), Some(8)).unwrap();
            let second = TextV1::new_with_unsafe_parts(
                &String::from_utf8(b"R\xCC\x83amone".to_vec()).unwrap(),
                b"",
                &field(),
                Some(8),
            )
            .unwrap();

            assert!(first < second);
        }
    }

    #[test]
    fn minimum_serialised_ciphertext_size() {
        let value = TextV1::new("", b"somecontext", &field()).unwrap();
        let serde_value = cbor!(value).unwrap();

        let mut s: Vec<u8> = vec![];
        ciborium::ser::into_writer(&serde_value, &mut s).unwrap();
        assert!(s.len() >= 158 || s.len() <= 160, "s.len() == {}", s.len());
    }

    #[test]
    fn minimum_unqueryable_serialised_ciphertext_size() {
        let mut value = TextV1::new("", b"somecontext", &field()).unwrap();
        value.make_unqueryable().unwrap();

        let serde_value = cbor!(value).unwrap();

        let mut s: Vec<u8> = vec![];
        ciborium::ser::into_writer(&serde_value, &mut s).unwrap();
        assert!(s.len() == 48, "s.len() == {}", s.len());
    }

    #[test]
    fn ciphertext_survives_serialisation() {
        let value = TextV1::new("ohai!", b"somecontext", &field()).unwrap();
        let serde_value = cbor!(value).unwrap();

        let mut s: Vec<u8> = vec![];
        ciborium::ser::into_writer(&serde_value, &mut s).unwrap();

        let v2: TextV1 = ciborium::de::from_reader(&s[..]).unwrap();

        assert_eq!("ohai!", v2.decrypt(b"somecontext", &field()).unwrap());
    }

    #[test]
    fn default_encryption_is_safe() {
        let value = TextV1::new("Hello, Enquo!", b"somecontext", &field()).unwrap();

        assert!(matches!(value.equality_ciphertext.unwrap().left, None));
        assert!(matches!(value.hash_code, None));
    }

    #[test]
    fn encrypted_values_are_not_normalised() {
        let value = TextV1::new(
            &String::from_utf8(b"La Nin\xCC\x83a".to_vec()).unwrap(),
            b"somecontext",
            &field(),
        )
        .unwrap();

        assert_eq!(
            b"La Nin\xCC\x83a",
            &value.decrypt(b"somecontext", &field()).unwrap().as_bytes()
        );
    }

    #[test]
    fn equality_ciphertexts_use_normalised_text() {
        let non_normalised = TextV1::new_with_unsafe_parts(
            &String::from_utf8(b"La Nin\xCC\x83a".to_vec()).unwrap(),
            b"somecontext",
            &field(),
            None,
        )
        .unwrap();
        let normalised = TextV1::new(
            &String::from_utf8(b"La Ni\xC3\xB1a".to_vec()).unwrap(),
            b"somecontext",
            &field(),
        )
        .unwrap();

        assert_eq!(non_normalised, normalised);
    }

    #[test]
    fn hash_codes_use_normalised_text() {
        let non_normalised = TextV1::new_with_unsafe_parts(
            &String::from_utf8(b"La Nin\xCC\x83a".to_vec()).unwrap(),
            b"somecontext",
            &field(),
            None,
        )
        .unwrap();
        let normalised = TextV1::new_with_unsafe_parts(
            &String::from_utf8(b"La Ni\xC3\xB1a".to_vec()).unwrap(),
            b"somecontext",
            &field(),
            None,
        )
        .unwrap();

        assert_eq!(
            non_normalised.hash_code.unwrap(),
            normalised.hash_code.unwrap()
        );
    }

    #[test]
    fn ascii_length() {
        let t = TextV1::new("ohai!", b"somecontext", &field()).unwrap();
        let len =
            OREv1::<8, 16, u32>::new_with_left(5, TEXT_V1_LENGTH_KEY_IDENTIFIER, &field()).unwrap();

        assert_eq!(t.length.unwrap(), len);
    }

    #[test]
    fn normalised_utf8_length() {
        let t = TextV1::new(
            &String::from_utf8(b"Jos\xC3\xA9".to_vec()).unwrap(),
            b"somecontext",
            &field(),
        )
        .unwrap();
        let len =
            OREv1::<8, 16, u32>::new_with_left(4, TEXT_V1_LENGTH_KEY_IDENTIFIER, &field()).unwrap();

        assert_eq!(t.length.unwrap(), len);
    }

    #[test]
    fn denormalised_utf8_length() {
        let t = TextV1::new(
            &String::from_utf8(b"Jose\xCC\x81".to_vec()).unwrap(),
            b"somecontext",
            &field(),
        )
        .unwrap();
        let len =
            OREv1::<8, 16, u32>::new_with_left(5, TEXT_V1_LENGTH_KEY_IDENTIFIER, &field()).unwrap();

        assert_eq!(t.length.unwrap(), len);
    }
}
