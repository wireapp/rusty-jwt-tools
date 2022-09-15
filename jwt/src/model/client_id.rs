use std::str::FromStr;

use crate::prelude::*;

/// Unique user handle
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct QualifiedClientId<'a> {
    /// user ID UUID-4 in ASCII string representation
    pub user: &'a str,
    /// the client number assigned by the backend
    pub client: u16,
    /// the backend domain of the client
    pub domain: &'a str,
}

impl<'a> TryFrom<&'a str> for QualifiedClientId<'a> {
    type Error = RustyJwtError;

    fn try_from(client_id: &'a str) -> RustyJwtResult<Self> {
        let rest = client_id
            .strip_prefix(Self::URI_PREFIX)
            .ok_or(RustyJwtError::InvalidClientId)?;
        let (user, rest) = rest.split_once('/').ok_or(RustyJwtError::InvalidClientId)?;
        let (client, domain) = rest.split_once('@').ok_or(RustyJwtError::InvalidClientId)?;
        let client = u16::from_str(client)?;
        Ok(Self { user, client, domain })
    }
}

impl<'a> TryFrom<&'a [u8]> for QualifiedClientId<'a> {
    type Error = RustyJwtError;

    fn try_from(client_id: &'a [u8]) -> RustyJwtResult<Self> {
        core::str::from_utf8(client_id)?.try_into()
    }
}

impl<'a> QualifiedClientId<'a> {
    const URI_PREFIX: &'static str = "URI:wireapp:";

    /// Constructor
    pub fn new(user: &'a str, client: u16, domain: &'a str) -> Self {
        Self { user, client, domain }
    }

    /// Constructor
    pub fn try_from_raw_parts(user: &'a [u8], client: u16, domain: &'a [u8]) -> RustyJwtResult<Self> {
        let user = core::str::from_utf8(user)?;
        let domain = core::str::from_utf8(domain)?;
        Ok(Self { user, client, domain })
    }

    /// Into JWT 'sub' claim
    pub fn to_subject(&self) -> String {
        format!("{}{}/{}@{}", Self::URI_PREFIX, self.user, self.client, self.domain)
    }
}

#[cfg(test)]
impl Default for QualifiedClientId<'_> {
    fn default() -> Self {
        QualifiedClientId::new("SvPfLlwBQi-6oddVRrkqpw", 1223, "example.com")
    }
}

#[cfg(test)]
impl QualifiedClientId<'_> {
    pub fn alice() -> Self {
        Self::new("alice", 1, "wire.com")
    }

    pub fn bob() -> Self {
        Self::new("bob", 2, "wire.com")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_subject_should_succeed() {
        let alice = QualifiedClientId::alice();
        let sub = alice.to_subject();
        assert_eq!(&sub, "URI:wireapp:alice/1@wire.com")
    }

    #[test]
    fn parse_should_succeed() {
        let alice = QualifiedClientId::alice();
        let sub = alice.to_subject();
        let parsed = QualifiedClientId::try_from(sub.as_str()).unwrap();
        assert_eq!(alice, parsed)
    }
}
