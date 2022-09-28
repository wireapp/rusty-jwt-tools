use std::str::FromStr;

use uuid::Uuid;

use crate::prelude::*;

/// Unique user handle
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct QualifiedClientId<'a> {
    /// base64url encoded UUIDv4 unique user identifier
    pub user: Uuid,
    /// the client number assigned by the backend in hex
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
        let user = Self::parse_user(user)?;
        let (client, domain) = rest.split_once('@').ok_or(RustyJwtError::InvalidClientId)?;
        let client = u16::from_str_radix(client, 16)?;
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
    #[cfg(test)]
    pub const DEFAULT_RAW_USER: &'static str = "SvPfLlwBQi-6oddVRrkqpw";

    const URI_PREFIX: &'static str = "URI:wireapp:";

    /// Constructor
    pub fn try_new(user: &'a str, client: u16, domain: &'a str) -> RustyJwtResult<Self> {
        let user = Self::parse_user(user)?;
        Ok(Self { user, client, domain })
    }

    /// Constructor
    pub fn try_from_raw_parts(user: &'a [u8], client: u16, domain: &'a [u8]) -> RustyJwtResult<Self> {
        let user = Self::parse_user(user)?;
        let domain = core::str::from_utf8(domain)?;
        Ok(Self { user, client, domain })
    }

    /// Into JWT 'sub' claim
    pub fn to_subject(&self) -> String {
        let client = hex::encode(self.client.to_be_bytes());
        format!("{}{}/{client}@{}", Self::URI_PREFIX, self.user, self.domain)
    }

    fn parse_user(user: impl AsRef<[u8]>) -> RustyJwtResult<Uuid> {
        let user = base64::decode_config(user, base64::URL_SAFE_NO_PAD)?;
        Ok(Uuid::from_bytes(user.as_slice().try_into()?))
    }
}

#[cfg(test)]
impl Default for QualifiedClientId<'_> {
    fn default() -> Self {
        QualifiedClientId::try_new(Self::DEFAULT_RAW_USER, 1223, "example.com").unwrap()
    }
}

#[cfg(test)]
impl QualifiedClientId<'_> {
    pub fn alice() -> Self {
        Self::try_new("S6PwC0nFR5GEPRaGE-cq-w", 1234, "wire.com").unwrap()
    }

    pub fn bob() -> Self {
        Self::try_new("RJsHxf38Q06MbvZBk46ADg", 5678, "wire.com").unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_should_expect_base64url_uuid_user() {
        let client = 6699;
        let domain = "wire.com";
        let client_id = QualifiedClientId::try_new(QualifiedClientId::DEFAULT_RAW_USER, client, domain).unwrap();
        assert_eq!(
            client_id,
            QualifiedClientId {
                user: uuid::uuid!("4af3df2e-5c01-422f-baa1-d75546b92aa7"),
                client,
                domain,
            }
        )
    }

    #[test]
    fn to_subject_should_succeed() {
        let user = QualifiedClientId::DEFAULT_RAW_USER;
        let domain = "wire.com";
        let client_id = QualifiedClientId::try_new(user, 6699, domain).unwrap();
        let uuid_user = "4af3df2e-5c01-422f-baa1-d75546b92aa7";
        assert_eq!(
            &client_id.to_subject(),
            &format!("URI:wireapp:{uuid_user}/1a2b@{domain}")
        );
    }

    #[test]
    fn parse_subject_should_succeed() {
        let user = QualifiedClientId::DEFAULT_RAW_USER;
        let domain = "wire.com";
        let subject = format!("URI:wireapp:{user}/1a2b@{domain}");
        let parsed = QualifiedClientId::try_from(subject.as_str()).unwrap();
        assert_eq!(
            parsed,
            QualifiedClientId {
                user: uuid::uuid!("4af3df2e-5c01-422f-baa1-d75546b92aa7"),
                client: 6699,
                domain,
            }
        );
    }

    #[test]
    fn parse_subject_should_fail_when_invalid_hex_client() {
        let user = QualifiedClientId::DEFAULT_RAW_USER;
        let invalid_client = "1g2g";
        let subject = format!("URI:wireapp:{user}/{invalid_client}@wire.com");
        assert!(matches!(
            QualifiedClientId::try_from(subject.as_str()).unwrap_err(),
            RustyJwtError::ParseIntError(_)
        ))
    }

    #[test]
    fn parse_subject_should_fail_when_invalid_uuid_user() {
        let invalid_user = format!("{}abcd", QualifiedClientId::DEFAULT_RAW_USER);
        let subject = format!("URI:wireapp:{invalid_user}/1a2b@wire.com");
        assert!(matches!(
            QualifiedClientId::try_from(subject.as_str()).unwrap_err(),
            RustyJwtError::Base64DecodeError(_)
        ))
    }
}
