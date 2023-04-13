use cretrit::PlainText;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::marker::PhantomData;

use crate::crypto::OREv1;
use crate::{Error, Field, SetValue, ValueFrom};

#[derive(Debug, Serialize, Deserialize)]
enum Ciphertext<const N: usize, const W: u16, T>
where
    T: Clone,
{
    #[allow(non_camel_case_types)]
    v1(OREv1<N, W, T>),
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ORE<const N: usize, const W: u16, T>
where
    T: Clone,
{
    #[serde(rename = "o")]
    ore_ciphertext: Ciphertext<N, W, T>,

    #[serde(rename = "k", with = "serde_bytes")]
    key_id: Vec<u8>,

    #[serde(skip)]
    oooh: PhantomData<T>,
}

impl<const N: usize, const W: u16, T> ORE<N, W, T>
where
    PlainText<N, W>: From<T>,
    T: Clone,
{
    pub fn new(i: T, context: &[u8], field: &Field) -> Result<ORE<N, W, T>, Error> {
        Ok(ORE::<N, W, T> {
            ore_ciphertext: Ciphertext::v1(OREv1::<N, W, T>::new(i, context, field)?),
            key_id: field.key_id()?,
            oooh: PhantomData,
        })
    }

    pub fn new_with_unsafe_parts(
        i: T,
        context: &[u8],
        field: &Field,
    ) -> Result<ORE<N, W, T>, Error> {
        Ok(ORE::<N, W, T> {
            ore_ciphertext: Ciphertext::v1(OREv1::<N, W, T>::new_with_left(i, context, field)?),
            key_id: field.key_id()?,
            oooh: PhantomData,
        })
    }
}

impl<const N: usize, const W: u16, T> SetValue for ORE<N, W, T>
where
    T: Clone,
{
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

impl<const N: usize, const W: u16, T> ValueFrom<&OREv1<N, W, T>> for ORE<N, W, T>
where
    T: Clone,
{
    fn from(k: &[u8], o: &OREv1<N, W, T>) -> ORE<N, W, T> {
        ORE::<N, W, T> {
            ore_ciphertext: Ciphertext::v1((*o).clone()),
            key_id: k.into(),
            oooh: PhantomData,
        }
    }
}

impl<const N: usize, const W: u16, T> Ord for ORE<N, W, T>
where
    PlainText<N, W>: From<T>,
    T: Clone,
{
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

impl<const N: usize, const W: u16, T> PartialOrd for ORE<N, W, T>
where
    PlainText<N, W>: From<T>,
    T: Clone,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize, const W: u16, T> PartialEq for ORE<N, W, T>
where
    PlainText<N, W>: From<T>,
    T: Clone,
{
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl<const N: usize, const W: u16, T> Eq for ORE<N, W, T>
where
    PlainText<N, W>: From<T>,
    T: Clone,
{
}

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
            let ca = ORE::<8, 16, u32>::new_with_unsafe_parts(a, b"test", &field()).unwrap();
            let cb = ORE::<8, 16, u32>::new_with_unsafe_parts(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_u32_first_missing_left(a: u32, b: u32) -> bool {
            let ca = ORE::<8, 16, u32>::new(a, b"test", &field()).unwrap();
            let cb = ORE::<8, 16, u32>::new_with_unsafe_parts(b, b"test", &field()).unwrap();

            match ca.cmp(&cb) {
                Ordering::Equal => a == b,
                Ordering::Less => a < b,
                Ordering::Greater => a > b,
            }
        }

        fn comparison_u32_second_missing_left(a: u32, b: u32) -> bool {
            let ca = ORE::<8, 16, u32>::new_with_unsafe_parts(a, b"test", &field()).unwrap();
            let cb = ORE::<8, 16, u32>::new(b, b"test", &field()).unwrap();

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
        let ca = ORE::<8, 16, u32>::new(8, b"test", &field()).unwrap();
        let cb = ORE::<8, 16, u32>::new(16, b"test", &field()).unwrap();

        let _ = ca == cb;
    }
}
