//! Version 1 of the Text datatype
//!

use ciborium::cbor;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use unicode_normalization::UnicodeNormalization;

use crate::{
    collator,
    crypto::{AES256v1, EREv1, OREv1},
    field::KeyId,
    key_provider::{KeyProvider, Static},
    Error, Field,
};

/// Version 1 of a Text value
///
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[doc(hidden)]
pub struct V1 {
    /// The actual encrypted value
    ///
    /// This is the bit that gets decrypted when someone wants to actually read the plaintext again
    ///
    #[serde(rename = "a")]
    aes_ciphertext: AES256v1,
    /// How we can tell, with a reasonable degree of certainty, whether or not two encrypted texts
    /// are equal
    #[serde(rename = "e")]
    equality_ciphertext: Option<EREv1<16, 16>>,
    /// A truncated hash to help with indexing in large datasets
    #[serde(rename = "h")]
    hash_code: Option<u16>,
    /// A way to allow texts to be sorted without seeing the plaintext
    #[serde(rename = "o")]
    order_code: Option<Vec<OREv1<1, 256>>>,
    /// The length of the text, in Unicode Scalar Values, and -- of course -- encrypted
    #[serde(rename = "l")]
    len: Option<OREv1<8, 16>>,
    /// A serialisation-friendly form of the field key ID
    #[serde(rename = "k", with = "serde_bytes")]
    kid: Vec<u8>,
}

/// Identifier for the subkey used to calculate the plaintext value of the equality hash
const TEXT_V1_EQUALITY_HASH_KEY_IDENTIFIER: &[u8] = b"TextV1.equality_hash_key";
/// Identifier for the subkey used to encrypt the equality hash
const TEXT_V1_EQUALITY_HASH_CIPHERTEXT_KEY_IDENTIFIER: &[u8] =
    b"TextV1.equality_hash_key_ciphertext";
/// Identifier for the subkey used to calculate the plaintext hash code
const TEXT_V1_HASH_CODE_KEY_IDENTIFIER: &[u8] = b"TextV1.hash_code_key";
/// Identifier for the subkey used to encrypt the ordering code
const TEXT_V1_ORDER_CODE_KEY_IDENTIFIER: &[u8] = b"TextV1.order_code_key";
/// Identifier for the subkey used to encrypt the text's length
const TEXT_V1_LENGTH_KEY_IDENTIFIER: &[u8] = b"TextV1.length_key";

impl V1 {
    /// Make a new V1 ciphertext
    ///
    pub(crate) fn new(text: &str, context: &[u8], field: &Field) -> Result<V1, Error> {
        Self::encrypt(text, context, field, false, None)
    }

    /// Make a new V1 ciphertext with degraded security
    ///
    pub(crate) fn new_with_unsafe_parts(
        text: &str,
        context: &[u8],
        field: &Field,
        ordering: Option<u8>,
    ) -> Result<V1, Error> {
        Self::encrypt(text, context, field, true, ordering)
    }

    /// Do the hard yards of actually creating the ciphertexts that make up the v1 `Text` value,
    /// and glueing them all together into the struct
    ///
    fn encrypt(
        text: &str,
        context: &[u8],
        field: &Field,
        allow_unsafe: bool,
        ordering: Option<u8>,
    ) -> Result<V1, Error> {
        let v = cbor!(text).map_err(|e| {
            Error::EncodingError(format!("failed to convert string to ciborium value: {e}"))
        })?;

        let mut msg: Vec<u8> = Vec::default();
        ciborium::ser::into_writer(&v, &mut msg)
            .map_err(|e| Error::EncodingError(format!("failed to encode string value: {e}")))?;

        let aes = AES256v1::new(&msg, context, field)?;

        let normalised = text.nfc().collect::<String>();

        let eq_hash = Self::eq_hash(&normalised, field)?;
        let eq = Self::ere_eq_hash(eq_hash, field, allow_unsafe)?;

        #[allow(clippy::if_then_some_else_none)]
        // Can't really use bool::then on a fallible function call
        let hc = if allow_unsafe {
            Some(Self::hash_code(&normalised, field)?)
        } else {
            None
        };

        let pt_len = <usize as TryInto<u32>>::try_into(text.chars().count()).map_err(|e| {
            Error::EncodingError(format!("string length exceeds maximum allowed value ({e})"))
        })?;
        let ore_len = Self::ore_length(pt_len, field, allow_unsafe)?;

        let order_code = Self::order_code(&normalised, ordering, field)?;

        Ok(V1 {
            aes_ciphertext: aes,
            equality_ciphertext: Some(eq),
            hash_code: hc,
            order_code,
            len: Some(ore_len),
            kid: field.key_id()?.into(),
        })
    }

    /// Decrypt the text and return it
    ///
    pub(crate) fn decrypt(&self, context: &[u8], field: &Field) -> Result<String, Error> {
        let pt = self.aes_ciphertext.decrypt(context, field)?;

        let s_text = ciborium::de::from_reader::<String, &[u8]>(&*pt)
            .map_err(|e| Error::DecodingError(format!("could not decode decrypted value: {e}")))?;

        Ok(s_text)
    }

    /// Strip all the mass of data that allows the text to be queried, leaving just the encrypted
    /// value that can be read
    ///
    pub(crate) fn make_unqueryable(&mut self) {
        self.equality_ciphertext = None;
        self.hash_code = None;
        self.len = None;
    }

    /// Return the field key ID that was used to create this `Text` value
    ///
    pub(crate) fn key_id(&self) -> KeyId {
        let mut key_id: KeyId = Default::default();
        key_id.copy_from_slice(&self.kid);
        key_id
    }

    /// Return the ciphertext representing the length of this `Text` value
    ///
    pub(crate) fn length(&self) -> Option<OREv1<8, 16>> {
        self.len.clone()
    }

    /// Calculate the plaintext value of the equality hash
    ///
    /// This is a 64-bit value that, to a reasonable probability, uniquely identifies the text that
    /// has been encrypted.  It is generated using a unique subkey so that if the same text were to
    /// be encrypted in different fields, the equality hash value would be different, making it all
    /// the harder for an attacker to try and figure out what texts are.
    ///
    fn eq_hash(text: &str, field: &Field) -> Result<u64, Error> {
        let mut hasher_key: [u8; 32] = Default::default();
        field.subkey(&mut hasher_key, TEXT_V1_EQUALITY_HASH_KEY_IDENTIFIER)?;

        let hasher = Static::new(&hasher_key)?;
        let mut hash: [u8; 8] = Default::default();
        hasher.derive_key(&mut hash, text.as_bytes())?;

        Ok(u64::from_be_bytes(hash))
    }

    /// Encrypt the equality hash into an equality-revealing ciphertext
    ///
    fn ere_eq_hash(hc: u64, field: &Field, allow_unsafe: bool) -> Result<EREv1<16, 16>, Error> {
        if allow_unsafe {
            Ok(EREv1::<16, 16>::new_with_left(
                hc,
                TEXT_V1_EQUALITY_HASH_CIPHERTEXT_KEY_IDENTIFIER,
                field,
            )?)
        } else {
            Ok(EREv1::<16, 16>::new(
                hc,
                TEXT_V1_EQUALITY_HASH_CIPHERTEXT_KEY_IDENTIFIER,
                field,
            )?)
        }
    }

    /// Encrypt a given number as though it were a Text value's `length`
    ///
    /// Used so that queries can have something to compare a whole bunch of `Text`'s lengths to.
    /// See also the [`Text::ore_length()`](crate::datatype::text::ore_length) docs.
    ///
    pub(crate) fn ore_length(
        len: u32,
        field: &Field,
        allow_unsafe: bool,
    ) -> Result<OREv1<8, 16>, Error> {
        if allow_unsafe {
            Ok(OREv1::<8, 16>::new_with_left(
                len,
                TEXT_V1_LENGTH_KEY_IDENTIFIER,
                field,
            )?)
        } else {
            Ok(OREv1::<8, 16>::new(
                len,
                TEXT_V1_LENGTH_KEY_IDENTIFIER,
                field,
            )?)
        }
    }

    /// Generate a (purposely very lossy) hash code
    ///
    /// This is a plaintext number that gets included in a degraded-security `Text` that can be
    /// used to provide some measure of distinction between values, without *totally* giving away
    /// that two encrypted texts are the same.  It's really only useful in large datasets, to give
    /// indexing a chance to pare the dataset down to a reasonable subset for sequential scanning.
    ///
    fn hash_code(text: &str, field: &Field) -> Result<u16, Error> {
        let mut hasher_key: [u8; 32] = Default::default();
        field.subkey(&mut hasher_key, TEXT_V1_HASH_CODE_KEY_IDENTIFIER)?;

        let hasher = Static::new(&hasher_key)?;
        let mut hash: [u8; 2] = Default::default();
        hasher.derive_key(&mut hash, text.as_bytes())?;

        Ok(u16::from_be_bytes(hash))
    }

    /// Generate the encrypted 'ordering code' for the given ciphertext
    ///
    /// An ordering code is a value that transmogrifies the usual numeric values of characters in
    /// such a way that, when you sort the ordering codes, the corresponding texts are sorted
    /// "correctly".  This job is performed by a "collator".
    ///
    /// The problem is that "correctly" varies by language, geography, and even context (German
    /// dictionaries are sorted differently to German telephone books, for example).  Luckily, ICU
    /// (Internationalization Components for Unicode) provide mechanisms for figuring all that out.
    /// Unluckily, linking ICU into a Rust binary that is to be used by many people is a shitshow
    /// (ICU bumps its soname like there's a prize for the highest version number).
    ///
    /// All this is to say that, by default, there's a built-in collator that just returns ASCII
    /// values for the ordering code, but that can be swapped out by building with the `icu` feature.
    ///
    fn order_code(
        text: &str,
        ordering: Option<u8>,
        field: &Field,
    ) -> Result<Option<Vec<OREv1<1, 256>>>, Error> {
        match ordering {
            None => Ok(None),
            Some(len) => {
                let sort_key = collator::generate_sort_key(text, "en")?;

                let mut order_vec: Vec<OREv1<1, 256>> = vec![];

                for i in 0..len {
                    let sort_key_component = sort_key.get(i as usize).unwrap_or(&0);
                    let v = OREv1::<1, 256>::new_with_left(
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

impl Hash for V1 {
    #[allow(clippy::expect_used)] // No way to signal error in impl Hash
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash_code
            .expect("cannot hash a Text value without a hash code")
            .hash(state);
    }
}

impl Ord for V1 {
    #[allow(clippy::panic, clippy::expect_used)] // No way to signal error from impl Ord
    fn cmp(&self, other: &Self) -> Ordering {
        assert!(
            self.kid == other.kid,
            "Cannot compare ciphertexts from different keys"
        );

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

impl PartialOrd for V1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for V1 {
    #[allow(clippy::panic, clippy::expect_used)] // No way to signal error from impl Eq
    fn eq(&self, other: &Self) -> bool {
        assert!(
            self.kid == other.kid,
            "Cannot compare ciphertexts from different keys"
        );

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

impl Eq for V1 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::OREv1, key_provider::Static, Root};
    use std::sync::Arc;

    fn field() -> Field {
        Root::new(Arc::new(
            Static::new(b"this is a suuuuper long test key").unwrap(),
        ))
        .unwrap()
        .field(b"foo", b"bar")
        .unwrap()
    }

    #[test]
    fn value_round_trips() {
        let value = V1::new("Hello, Enquo!", b"context", &field()).unwrap();

        assert_eq!(
            "Hello, Enquo!",
            value.decrypt(b"context", &field()).unwrap()
        );
    }

    #[test]
    fn incorrect_context_fails() {
        let value = V1::new("Hello, Enquo!", b"somecontext", &field()).unwrap();

        let err = value.decrypt(b"othercontext", &field()).err();
        assert!(matches!(err, Some(Error::DecryptionError(_))));
    }

    #[test]
    fn ciphertexts_compare_correctly() {
        let text1 =
            V1::new_with_unsafe_parts("Hello, Enquo!", b"somecontext", &field(), None).unwrap();
        let text2 = V1::new("Hello, Enquo!", b"somecontext", &field()).unwrap();
        let text3 = V1::new("Goodbye, Enquo!", b"somecontext", &field()).unwrap();

        assert_eq!(text1, text2);
        assert_ne!(text1, text3);
    }

    #[test]
    fn hash_codes_compare_correctly() {
        let text1 = V1::new_with_unsafe_parts("Hello, Enquo!", b"", &field(), None).unwrap();
        let text2 = V1::new_with_unsafe_parts("Hello, Enquo!", b"", &field(), None).unwrap();
        let text3 = V1::new_with_unsafe_parts("Goodbye, Enquo!", b"", &field(), None).unwrap();

        assert_eq!(text1.hash_code.unwrap(), text2.hash_code.unwrap());
        assert_ne!(text1.hash_code.unwrap(), text3.hash_code.unwrap());
    }

    #[test]
    fn base_ascii_orderable_strings_compare_correctly() {
        let one = V1::new_with_unsafe_parts("one", b"1", &field(), Some(8)).unwrap();
        let two = V1::new_with_unsafe_parts("two", b"2", &field(), Some(8)).unwrap();
        let three = V1::new_with_unsafe_parts("three", b"3", &field(), Some(8)).unwrap();

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
            let first = V1::new_with_unsafe_parts(
                &String::from_utf8(b"R\xCC\x83amone".to_vec()).unwrap(),
                b"",
                &field(),
                Some(8),
            )
            .unwrap();
            let second = V1::new_with_unsafe_parts("Roman", b"", &field(), Some(8)).unwrap();

            assert!(first < second);
        }
    }

    #[cfg(not(feature = "icu"))]
    mod lexicographic_collation {
        use super::*;

        #[test]
        fn accented_orderable_strings_compare_weirdly() {
            let first = V1::new_with_unsafe_parts("Roman", b"", &field(), Some(8)).unwrap();
            let second = V1::new_with_unsafe_parts(
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
        let value = V1::new("", b"somecontext", &field()).unwrap();
        let serde_value = cbor!(value).unwrap();

        let mut s: Vec<u8> = vec![];
        ciborium::ser::into_writer(&serde_value, &mut s).unwrap();
        assert!(s.len() >= 158 || s.len() <= 160, "s.len() == {}", s.len());
    }

    #[test]
    fn minimum_unqueryable_serialised_ciphertext_size() {
        let mut value = V1::new("", b"somecontext", &field()).unwrap();
        value.make_unqueryable();

        let serde_value = cbor!(value).unwrap();

        let mut s: Vec<u8> = vec![];
        ciborium::ser::into_writer(&serde_value, &mut s).unwrap();
        assert!(s.len() == 52, "s.len() == {}", s.len());
    }

    #[test]
    fn ciphertext_survives_serialisation() {
        let value = V1::new("ohai!", b"somecontext", &field()).unwrap();
        let serde_value = cbor!(value).unwrap();

        let mut s: Vec<u8> = vec![];
        ciborium::ser::into_writer(&serde_value, &mut s).unwrap();

        let v2: V1 = ciborium::de::from_reader(&s[..]).unwrap();

        assert_eq!("ohai!", v2.decrypt(b"somecontext", &field()).unwrap());
    }

    #[test]
    fn default_encryption_is_safe() {
        let value = V1::new("Hello, Enquo!", b"somecontext", &field()).unwrap();

        assert!(!value.equality_ciphertext.unwrap().has_left());
        assert!(matches!(value.hash_code, None));
    }

    #[test]
    fn encrypted_values_are_not_normalised() {
        let value = V1::new(
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
        let non_normalised = V1::new_with_unsafe_parts(
            &String::from_utf8(b"La Nin\xCC\x83a".to_vec()).unwrap(),
            b"somecontext",
            &field(),
            None,
        )
        .unwrap();
        let normalised = V1::new(
            &String::from_utf8(b"La Ni\xC3\xB1a".to_vec()).unwrap(),
            b"somecontext",
            &field(),
        )
        .unwrap();

        assert_eq!(non_normalised, normalised);
    }

    #[test]
    fn hash_codes_use_normalised_text() {
        let non_normalised = V1::new_with_unsafe_parts(
            &String::from_utf8(b"La Nin\xCC\x83a".to_vec()).unwrap(),
            b"somecontext",
            &field(),
            None,
        )
        .unwrap();
        let normalised = V1::new_with_unsafe_parts(
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
        let t = V1::new("ohai!", b"somecontext", &field()).unwrap();
        let len =
            OREv1::<8, 16>::new_with_left(5u8, TEXT_V1_LENGTH_KEY_IDENTIFIER, &field()).unwrap();

        assert_eq!(t.len.unwrap(), len);
    }

    #[test]
    fn normalised_utf8_length() {
        let t = V1::new(
            &String::from_utf8(b"Jos\xC3\xA9".to_vec()).unwrap(),
            b"somecontext",
            &field(),
        )
        .unwrap();
        let len =
            OREv1::<8, 16>::new_with_left(4u8, TEXT_V1_LENGTH_KEY_IDENTIFIER, &field()).unwrap();

        assert_eq!(t.len.unwrap(), len);
    }

    #[test]
    fn denormalised_utf8_length() {
        let t = V1::new(
            &String::from_utf8(b"Jose\xCC\x81".to_vec()).unwrap(),
            b"somecontext",
            &field(),
        )
        .unwrap();
        let len =
            OREv1::<8, 16>::new_with_left(5u8, TEXT_V1_LENGTH_KEY_IDENTIFIER, &field()).unwrap();

        assert_eq!(t.len.unwrap(), len);
    }
}
