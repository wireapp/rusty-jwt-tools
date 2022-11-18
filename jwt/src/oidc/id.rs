use crate::prelude::*;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use url::Url;

#[cfg_attr(test, derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
/// see https://www.w3.org/TR/json-ld11/#node-identifiers
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

impl FromStr for Id {
    type Err = RustyJwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Some(Url::parse(s)?).into())
    }
}

#[cfg(test)]
impl From<&str> for Id {
    fn from(s: &str) -> Self {
        s.parse().unwrap()
    }
}
