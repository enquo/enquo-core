use serde::{Deserialize, Serialize};

pub trait SetValue {
    fn is_compatible(&self, other: &Self) -> bool;
}

pub trait ValueFrom<T> {
    fn from(kid: &[u8], src: T) -> Self;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "T: for<'a> Deserialize<'a>")]
pub struct ValueSet<T>(Vec<T>)
where
    T: Serialize + for<'a> Deserialize<'a> + Eq;

impl<T> ValueSet<T>
where
    T: SetValue + Serialize + for<'a> Deserialize<'a> + Eq,
{
    pub fn compatible_value(&self, other: &T) -> Option<&T> {
        self.0.iter().find(|v| v.is_compatible(other))
    }
}

impl<T> From<Vec<T>> for ValueSet<T>
where
    T: SetValue + Serialize + for<'a> Deserialize<'a> + Eq,
{
    fn from(v: Vec<T>) -> ValueSet<T> {
        ValueSet::<T>(v)
    }
}
