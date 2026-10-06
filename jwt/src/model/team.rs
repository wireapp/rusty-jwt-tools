use crate::prelude::{RustyJwtError, RustyJwtResult};

/// Represents a Wire team.
///
/// There is a `AT MOST ONE` mapping between a user and a team but a user does not necessarily
/// belong to a team.
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    derive_more::From,
    derive_more::Into,
    derive_more::Deref,
)]
#[serde(transparent)]
pub struct Team(pub Option<String>);

impl From<String> for Team {
    fn from(s: String) -> Self {
        Some(s).into()
    }
}

impl From<&str> for Team {
    fn from(s: &str) -> Self {
        Some(s.to_string()).into()
    }
}

impl TryFrom<&[u8]> for Team {
    type Error = RustyJwtError;

    fn try_from(value: &[u8]) -> RustyJwtResult<Self> {
        Ok(core::str::from_utf8(value)?.into())
    }
}

#[cfg(test)]
impl Default for Team {
    fn default() -> Self {
        Self(Some("wire".to_string()))
    }
}
