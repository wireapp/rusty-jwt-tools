use crate::prelude::{RustyJwtError, RustyJwtResult};

/// Represents a Wire team.
///
/// There is a `AT MOST ONE` mapping between a user and a team but a user does not necessarily
/// belong to a team.
#[derive(
    Debug, Clone, serde::Serialize, serde::Deserialize, derive_more::From, derive_more::Into, derive_more::Deref,
)]
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

impl Eq for Team {}

#[cfg(test)]
impl Default for Team {
    fn default() -> Self {
        Self(Some("wire".to_string()))
    }
}

/// We want this to be lenient and backward compatible during the migration period
impl PartialEq for Team {
    fn eq(&self, server_team: &Self) -> bool {
        match (&self.0, &server_team.0) {
            // TODO: forbid this before releasing
            (None, Some(_)) | (Some(_), None) => true, // this probably means that client & server are operating on different versions.
            (Some(a), Some(b)) => a.eq(b),
            (None, None) => true,
        }
    }
}
