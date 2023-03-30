use cretrit::PlainText;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use crate::crypto::EREv1;
use crate::{Error, Field};

#[derive(Debug, Serialize, Deserialize)]
enum Ciphertext<const N: usize, const W: u16, T> {
    #[allow(non_camel_case_types)]
    v1(EREv1<N, W, T>),
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ERE<const N: usize, const W: u16, T> {
    #[serde(rename = "o")]
    ore_ciphertext: Ciphertext<N, W, T>,

    #[serde(rename = "k", with = "serde_bytes")]
    key_id: Vec<u8>,

    #[serde(skip)]
    oooh: PhantomData<T>,
}

impl<const N: usize, const W: u16, T> ERE<N, W, T>
where
    PlainText<N, W>: From<T>,
{
    pub fn new(i: T, context: &[u8], field: &Field) -> Result<ERE<N, W, T>, Error> {
        Ok(ERE::<N, W, T> {
            ore_ciphertext: Ciphertext::v1(EREv1::<N, W, T>::new(i, context, field)?),
            key_id: field.key_id()?,
            oooh: PhantomData,
        })
    }

    pub fn new_with_unsafe_parts(
        i: T,
        context: &[u8],
        field: &Field,
    ) -> Result<ERE<N, W, T>, Error> {
        Ok(ERE::<N, W, T> {
            ore_ciphertext: Ciphertext::v1(EREv1::<N, W, T>::new_with_left(i, context, field)?),
            key_id: field.key_id()?,
            oooh: PhantomData,
        })
    }
}

impl<const N: usize, const W: u16, T> PartialEq for ERE<N, W, T>
where
    PlainText<N, W>: From<T>,
{
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

impl<const N: usize, const W: u16, T> Eq for ERE<N, W, T> where PlainText<N, W>: From<T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{key_provider::Static, Field, Root};

    fn field() -> Field {
        Root::new(&Static::new(b"testkey"))
            .unwrap()
            .field(b"foo", b"bar")
            .unwrap()
    }

    quickcheck! {
        fn comparison_u32(a: u32, b: u32) -> bool {
            let ca = ERE::<8, 16, u32>::new_with_unsafe_parts(a, b"test", &field()).unwrap();
            let cb = ERE::<8, 16, u32>::new_with_unsafe_parts(b, b"test", &field()).unwrap();

            (ca == cb) == (a == b)
        }

        fn comparison_u32_first_missing_left(a: u32, b: u32) -> bool {
            let ca = ERE::<8, 16, u32>::new(a, b"test", &field()).unwrap();
            let cb = ERE::<8, 16, u32>::new_with_unsafe_parts(b, b"test", &field()).unwrap();

            (ca == cb) == (a == b)
        }

        fn comparison_u32_second_missing_left(a: u32, b: u32) -> bool {
            let ca = ERE::<8, 16, u32>::new_with_unsafe_parts(a, b"test", &field()).unwrap();
            let cb = ERE::<8, 16, u32>::new(b, b"test", &field()).unwrap();

            (ca == cb) == (a == b)
        }
    }

    #[test]
    #[should_panic]
    fn need_one_left_ciphertext() {
        let ca = ERE::<8, 16, u32>::new(8, b"test", &field()).unwrap();
        let cb = ERE::<8, 16, u32>::new(16, b"test", &field()).unwrap();

        let _ = ca == cb;
    }
}
