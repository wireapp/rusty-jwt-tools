use crate::prelude::*;

/// Unique user handle
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QualifiedClientId<'a> {
    /// user ID UUID-4 in ASCII string representation
    pub user: &'a str,
    /// the client number assigned by the backend
    pub client: u16,
    /// the backend domain of the client
    pub domain: &'a str,
}

impl<'a> QualifiedClientId<'a> {
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
    pub fn subject(&self) -> String {
        format!("{}/{}@{}", self.user, hex::encode(self.client.to_string()), self.domain)
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
