use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
/// A JSON object or array, yikes
pub struct ObjectOrArray<T: Serialize + for<'a> Deserialize<'a>> {
    #[serde(with = "either::serde_untagged")]
    inner: either::Either<T, Vec<T>>,
}

impl<T: Serialize + for<'a> Deserialize<'a>> ObjectOrArray<T> {
    /// When an array, is it empty
    pub fn is_empty(&self) -> bool {
        match &self.inner {
            either::Left(_) => false,
            either::Right(v) => v.is_empty(),
        }
    }
}

impl<T: Serialize + for<'a> Deserialize<'a>> From<T> for ObjectOrArray<T> {
    fn from(value: T) -> Self {
        Self {
            inner: either::Left(value),
        }
    }
}

impl<T: Serialize + for<'a> Deserialize<'a>> From<Vec<T>> for ObjectOrArray<T> {
    fn from(values: Vec<T>) -> Self {
        Self {
            inner: either::Right(values),
        }
    }
}

#[cfg(test)]
impl<T: Serialize + for<'a> Deserialize<'a>> Default for ObjectOrArray<T> {
    fn default() -> Self {
        vec![].try_into().unwrap()
    }
}
