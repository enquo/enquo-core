use cretrit::PlainText;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

use crate::crypto::OREv1;
use crate::{Error, Field, SetValue, ValueFrom};

#[derive(Debug, Serialize, Deserialize)]
enum Ciphertext<const N: usize, const W: u16> {
    #[allow(non_camel_case_types)]
    v1(OREv1<N, W>),
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ORE<const N: usize, const W: u16> {
    #[serde(rename = "o")]
    ore_ciphertext: Ciphertext<N, W>,

    #[serde(rename = "k", with = "serde_bytes")]
    key_id: Vec<u8>,
}

impl<const N: usize, const W: u16> ORE<N, W> {
    pub fn new<T>(i: T, context: &[u8], field: &Field) -> Result<ORE<N, W>, Error>
    where
        PlainText<N, W>: TryFrom<T>,
        <PlainText<N, W> as TryFrom<T>>::Error: std::fmt::Display,
        T: Clone,
    {
        Ok(ORE::<N, W> {
            ore_ciphertext: Ciphertext::v1(OREv1::<N, W>::new(i, context, field)?),
            key_id: field.key_id()?,
        })
    }

    pub fn new_with_unsafe_parts<T>(i: T, context: &[u8], field: &Field) -> Result<ORE<N, W>, Error>
    where
        PlainText<N, W>: TryFrom<T>,
        <PlainText<N, W> as TryFrom<T>>::Error: std::fmt::Display,
        T: Clone,
    {
        Ok(ORE::<N, W> {
            ore_ciphertext: Ciphertext::v1(OREv1::<N, W>::new_with_left(i, context, field)?),
            key_id: field.key_id()?,
        })
    }
}

impl<const N: usize, const W: u16> SetValue for ORE<N, W> {
    fn is_compatible(&self, other: &Self) -> bool {
        match &self.ore_ciphertext {
            Ciphertext::v1(_) => match &other.ore_ciphertext {
                Ciphertext::v1(_) => self.key_id == other.key_id,
                _ => false,
            },
            _ => false,
        }
    }
}

impl<const N: usize, const W: u16> ValueFrom<&OREv1<N, W>> for ORE<N, W> {
    fn from(k: &[u8], o: &OREv1<N, W>) -> ORE<N, W> {
        ORE::<N, W> {
            ore_ciphertext: Ciphertext::v1((*o).clone()),
            key_id: k.into(),
        }
    }
}

impl<const N: usize, const W: u16> Ord for ORE<N, W> {
    fn cmp(&self, other: &Self) -> Ordering {
        match &self.ore_ciphertext {
            Ciphertext::v1(s) => match &other.ore_ciphertext {
                Ciphertext::v1(o) => s.cmp(o),
                _ => panic!("Cannot compare a v1 ORE ciphertext with any other type of ciphertext"),
            },
            Ciphertext::Unknown => {
                panic!("Cannot compare against an Unknown version ORE ciphertext")
            }
        }
    }
}

impl<const N: usize, const W: u16> PartialOrd for ORE<N, W> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize, const W: u16> PartialEq for ORE<N, W> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl<const N: usize, const W: u16> Eq for ORE<N, W> {}

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
            let ca = ORE::<8, 16>::new_with_unsafe_parts(a, b"test", &field()).unwrap();
            let cb = ORE::<8, 16>::new_with_unsafe_parts(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_u32_first_missing_left(a: u32, b: u32) -> bool {
            let ca = ORE::<8, 16>::new(a, b"test", &field()).unwrap();
            let cb = ORE::<8, 16>::new_with_unsafe_parts(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_u32_second_missing_left(a: u32, b: u32) -> bool {
            let ca = ORE::<8, 16>::new_with_unsafe_parts(a, b"test", &field()).unwrap();
            let cb = ORE::<8, 16>::new(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }
    }

    #[test]
    #[should_panic]
    fn need_one_left_ciphertext() {
        let ca = ORE::<8, 16>::new(8u8, b"test", &field()).unwrap();
        let cb = ORE::<8, 16>::new(16u8, b"test", &field()).unwrap();

        let _ = ca == cb;
    }
}
