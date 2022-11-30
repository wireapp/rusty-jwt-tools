use uuid::Uuid;

use crate::prelude::*;

/// Unique user handle
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct QualifiedClientId<'a> {
    /// base64url encoded UUIDv4 unique user identifier
    pub user: Uuid,
    /// the client number assigned by the backend in hex
    pub client: u64,
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
        let client = u64::from_str_radix(client, 16).map_err(|_| RustyJwtError::InvalidClientId)?;
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
    pub const DEFAULT_USER: Uuid = uuid::uuid!("4af3df2e-5c01-422f-baa1-d75546b92aa7");

    const URI_PREFIX: &'static str = "im:wireapp:";

    /// Constructor
    pub fn try_new(user: impl AsRef<str>, client: u64, domain: &'a str) -> RustyJwtResult<Self> {
        let user = uuid::Uuid::try_from(user.as_ref()).map_err(|_| RustyJwtError::InvalidClientId)?;
        Ok(Self { user, client, domain })
    }

    /// Constructor
    pub fn try_from_raw_parts(user: &'a [u8], client: u64, domain: &'a [u8]) -> RustyJwtResult<Self> {
        let user = Uuid::from_slice(user)?;
        let domain = core::str::from_utf8(domain)?;
        Ok(Self { user, client, domain })
    }

    /// Into JWT 'sub' claim
    pub fn to_subject(&self) -> String {
        let user = base64::encode_config(self.user.as_simple().to_string(), base64::URL_SAFE_NO_PAD);
        format!("{}{user}/{:x}@{}", Self::URI_PREFIX, self.client, self.domain)
    }

    fn parse_user(user: impl AsRef<[u8]>) -> RustyJwtResult<Uuid> {
        let user = base64::decode_config(user, base64::URL_SAFE_NO_PAD).map_err(|_| RustyJwtError::InvalidClientId)?;
        Ok(Uuid::try_parse_ascii(&user)?)
    }
}

#[cfg(test)]
impl<'a> serde::Serialize for QualifiedClientId<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_subject())
    }
}

#[cfg(test)]
impl<'a, 'de> serde::Deserialize<'de> for QualifiedClientId<'a> {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        todo!()
    }
}

#[cfg(test)]
impl Default for QualifiedClientId<'_> {
    fn default() -> Self {
        QualifiedClientId::try_new(Self::DEFAULT_USER.to_string(), 1223, "example.com").unwrap()
    }
}

#[cfg(test)]
impl QualifiedClientId<'_> {
    pub fn alice() -> Self {
        Self::try_new("e1299f1d-180e-4339-b7c7-2715e1e6897f", 1234, "wire.com").unwrap()
    }

    pub fn bob() -> Self {
        Self::try_new("6ea667de-236b-4fed-8acd-778974ca615c", 5678, "wire.com").unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr as _;

    mod constructor {
        use super::*;

        #[test]
        fn constructor_should_build() {
            let client = 6699;
            let domain = "wire.com";
            let user = uuid::uuid!("4af3df2e-5c01-422f-baa1-d75546b92aa7").to_string();
            let client_id = QualifiedClientId::try_new(&user, client, domain).unwrap();
            assert_eq!(
                client_id,
                QualifiedClientId {
                    user: Uuid::from_str(&user).unwrap(),
                    client,
                    domain
                }
            )
        }

        #[test]
        fn constructor_should_fail_when_user_not_uuid() {
            let client_id = QualifiedClientId::try_new("abcd", 6699, "wire.com");
            assert!(matches!(client_id.unwrap_err(), RustyJwtError::InvalidClientId))
        }
    }

    mod to_subject {
        use super::*;

        #[test]
        fn to_subject_should_succeed() {
            let user = "4af3df2e-5c01-422f-baa1-d75546b92aa7";
            let domain = "wire.com";
            let client_id = QualifiedClientId::try_new(user, u64::MAX, domain).unwrap();
            let base64_user = "NGFmM2RmMmU1YzAxNDIyZmJhYTFkNzU1NDZiOTJhYTc";
            let hex_client = "ffffffffffffffff";
            assert_eq!(
                &client_id.to_subject(),
                &format!("im:wireapp:{base64_user}/{hex_client}@{domain}")
            );
        }
    }

    mod parse {
        use super::*;

        #[test]
        fn parse_subject_should_succeed() {
            let user = "NGFmM2RmMmU1YzAxNDIyZmJhYTFkNzU1NDZiOTJhYTc";
            let client = "1a2b";
            let domain = "wire.com";
            let subject = format!("im:wireapp:{user}/{client}@{domain}");
            let parsed = QualifiedClientId::try_from(subject.as_str()).unwrap();
            assert_eq!(
                parsed,
                QualifiedClientId {
                    user: Uuid::from_str(&QualifiedClientId::DEFAULT_USER.to_string()).unwrap(),
                    client: 6699,
                    domain,
                }
            );
        }

        #[test]
        fn parse_subject_should_fail_when_invalid_uuid_user() {
            let invalid_user = format!("{}abcd", "NGFmM2RmMmU1YzAxNDIyZmJhYTFkNzU1NDZiOTJhYTc");
            let client = "1a2b";
            let subject = format!("im:wireapp:{invalid_user}/{client}@wire.com");
            let parsed = QualifiedClientId::try_from(subject.as_str());
            assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
        }

        #[test]
        fn parse_subject_should_fail_when_invalid_hex_client() {
            let user = "NGFmM2RmMmU1YzAxNDIyZmJhYTFkNzU1NDZiOTJhYTc";
            let invalid_client = "1g2g";
            let subject = format!("im:wireapp:{user}/{invalid_client}@wire.com");
            let parsed = QualifiedClientId::try_from(subject.as_str());
            assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
        }

        #[test]
        fn parse_subject_should_fail_when_client_too_large() {
            let user = "NGFmM2RmMmU1YzAxNDIyZmJhYTFkNzU1NDZiOTJhYTc";
            let invalid_client = u128::MAX;
            let subject = format!("im:wireapp:{user}/{:x}@wire.com", invalid_client);
            let parsed = QualifiedClientId::try_from(subject.as_str());
            assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
        }
    }
}
