use cretrit::PlainText;
use serde::{Deserialize, Serialize};

use crate::crypto::EREv1;
use crate::{Error, Field};

#[derive(Debug, Serialize, Deserialize)]
enum Ciphertext<const N: usize, const W: u16> {
    #[allow(non_camel_case_types)]
    v1(EREv1<N, W>),
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ERE<const N: usize, const W: u16> {
    #[serde(rename = "o")]
    ore_ciphertext: Ciphertext<N, W>,

    #[serde(rename = "k", with = "serde_bytes")]
    key_id: Vec<u8>,
}

impl<const N: usize, const W: u16> ERE<N, W> {
    pub fn new<T>(i: T, context: &[u8], field: &Field) -> Result<ERE<N, W>, Error>
    where
        PlainText<N, W>: TryFrom<T>,
        <PlainText<N, W> as TryFrom<T>>::Error: std::fmt::Display,
    {
        Ok(ERE::<N, W> {
            ore_ciphertext: Ciphertext::v1(EREv1::<N, W>::new(i, context, field)?),
            key_id: field.key_id()?,
        })
    }

    pub fn new_with_unsafe_parts<T>(i: T, context: &[u8], field: &Field) -> Result<ERE<N, W>, Error>
    where
        PlainText<N, W>: TryFrom<T>,
        <PlainText<N, W> as TryFrom<T>>::Error: std::fmt::Display,
    {
        Ok(ERE::<N, W> {
            ore_ciphertext: Ciphertext::v1(EREv1::<N, W>::new_with_left(i, context, field)?),
            key_id: field.key_id()?,
        })
    }
}

impl<const N: usize, const W: u16> PartialEq for ERE<N, W> {
    fn eq(&self, other: &Self) -> bool {
        match &self.ore_ciphertext {
            Ciphertext::v1(s) => match &other.ore_ciphertext {
                Ciphertext::v1(o) => s == o,
                _ => panic!("Cannot compare a v1 ERE ciphertext with any other type of ciphertext"),
            },
            Ciphertext::Unknown => {
                panic!("Cannot compare against an Unknown version ERE ciphertext")
            }
        }
    }
}

impl<const N: usize, const W: u16> Eq for ERE<N, W> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{key_provider::Static, Field, Root};
    use std::sync::Arc;

    fn field() -> Field {
        Root::new(Arc::new(
            Static::new(b"this is a suuuuper long test key").unwrap(),
        ))
        .unwrap()
        .field(b"foo", b"bar")
        .unwrap()
    }

    quickcheck! {
        fn comparison_u32(a: u32, b: u32) -> bool {
            let ca = ERE::<8, 16>::new_with_unsafe_parts(a, b"test", &field()).unwrap();
            let cb = ERE::<8, 16>::new_with_unsafe_parts(b, b"test", &field()).unwrap();

            (ca == cb) == (a == b)
        }

        fn comparison_u32_first_missing_left(a: u32, b: u32) -> bool {
            let ca = ERE::<8, 16>::new(a, b"test", &field()).unwrap();
            let cb = ERE::<8, 16>::new_with_unsafe_parts(b, b"test", &field()).unwrap();

            (ca == cb) == (a == b)
        }

        fn comparison_u32_second_missing_left(a: u32, b: u32) -> bool {
            let ca = ERE::<8, 16>::new_with_unsafe_parts(a, b"test", &field()).unwrap();
            let cb = ERE::<8, 16>::new(b, b"test", &field()).unwrap();

            (ca == cb) == (a == b)
        }
    }

    #[test]
    #[should_panic]
    fn need_one_left_ciphertext() {
        let ca = ERE::<8, 16>::new(8u8, b"test", &field()).unwrap();
        let cb = ERE::<8, 16>::new(16u8, b"test", &field()).unwrap();

        let _ = ca == cb;
    }
}
