use serde::{Deserialize, Serialize};
use url::Url;

#[cfg_attr(test, derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Id(Option<Url>);

impl From<Option<Url>> for Id {
    fn from(u: Option<Url>) -> Self {
        Self(u)
    }
}

impl From<Url> for Id {
    fn from(u: Url) -> Self {
        Some(u).into()
    }
}

#[cfg(test)]
impl From<&str> for Id {
    fn from(u: &str) -> Self {
        Some(Url::parse(u).unwrap()).into()
    }
}
