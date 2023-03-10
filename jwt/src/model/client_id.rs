use base64::Engine;
use uuid::Uuid;

use crate::prelude::*;

/// Unique user handle
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ClientId {
    /// base64url encoded UUIDv4 unique user identifier
    pub user: Uuid,
    /// the client number assigned by the backend in hex
    pub client: u64,
    /// the backend domain of the client
    pub domain: String,
}

impl ClientId {
    #[cfg(test)]
    pub const DEFAULT_USER: Uuid = uuid::uuid!("4af3df2e-5c01-422f-baa1-d75546b92aa7");

    /// URI prefix for all subject URIs
    pub const URI_PREFIX: &'static str = "im:wireapp=";

    /// Between user-id & client-id when converted to an URI
    pub const URI_DELIMITER: &'static str = "/";

    /// Between user-id & client-id when parsed from Wire clients
    pub const CLIENT_DELIMITER: &'static str = ":";

    /// Constructor
    pub fn try_new(user: impl AsRef<str>, client: u64, domain: &str) -> RustyJwtResult<Self> {
        let user = uuid::Uuid::try_from(user.as_ref()).map_err(|_| RustyJwtError::InvalidClientId)?;
        Ok(Self {
            user,
            client,
            domain: domain.to_string(),
        })
    }

    /// Constructor
    pub fn try_from_raw_parts(user: &[u8], client: u64, domain: &[u8]) -> RustyJwtResult<Self> {
        let user = Uuid::from_slice(user)?;
        let domain = core::str::from_utf8(domain)?.to_string();
        Ok(Self { user, client, domain })
    }

    /// Parse from an URI e.g. `im:wireapp={userId}/{clientId}@{domain}`
    pub fn try_from_uri(client_id: &str) -> RustyJwtResult<Self> {
        let client_id = client_id
            .strip_prefix(Self::URI_PREFIX)
            .ok_or(RustyJwtError::InvalidClientId)?;
        Self::parse_client_id(client_id, Self::URI_DELIMITER)
    }

    /// Constructor for clientId usually used by Wire client application. Does not have the prefix
    /// and uses ':' instead of '/' as delimiter
    /// e.g. `im:wireapp={userId}:{clientId}@{domain}`
    pub fn try_from_qualified(client_id: &str) -> RustyJwtResult<Self> {
        Self::parse_client_id(client_id, Self::CLIENT_DELIMITER)
    }

    fn parse_client_id(client_id: &str, delimiter: &'static str) -> RustyJwtResult<Self> {
        let (user, rest) = client_id.split_once(delimiter).ok_or(RustyJwtError::InvalidClientId)?;
        let user = Self::parse_user(user)?;
        let (client, domain) = rest.split_once('@').ok_or(RustyJwtError::InvalidClientId)?;
        let client = u64::from_str_radix(client, 16).map_err(|_| RustyJwtError::InvalidClientId)?;
        Ok(Self {
            user,
            client,
            domain: domain.to_string(),
        })
    }

    /// Into JWT 'sub' claim
    pub fn to_uri(&self) -> String {
        let user = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(self.user.as_simple().to_string());
        format!(
            "{}{user}{}{:x}@{}",
            Self::URI_PREFIX,
            Self::URI_DELIMITER,
            self.client,
            self.domain
        )
    }

    fn parse_user(user: impl AsRef<[u8]>) -> RustyJwtResult<Uuid> {
        let user = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(user)
            .map_err(|_| RustyJwtError::InvalidClientId)?;
        Ok(Uuid::try_parse_ascii(&user)?)
    }
}

#[cfg(test)]
impl serde::Serialize for ClientId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_uri())
    }
}

#[cfg(test)]
impl<'de> serde::Deserialize<'de> for ClientId {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        todo!()
    }
}

#[cfg(test)]
impl Default for ClientId {
    fn default() -> Self {
        ClientId::try_new(Self::DEFAULT_USER.to_string(), 1223, "example.com").unwrap()
    }
}

#[cfg(test)]
impl ClientId {
    pub fn alice() -> Self {
        Self::try_new("e1299f1d-180e-4339-b7c7-2715e1e6897f", 1234, "wire.com").unwrap()
    }

    pub fn bob() -> Self {
        Self::try_new("6ea667de-236b-4fed-8acd-778974ca615c", 5678, "wire.com").unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;

    mod constructor {
        use super::*;

        #[test]
        fn constructor_should_build() {
            let client = 6699;
            let domain = "wire.com".to_string();
            let user = uuid::uuid!("4af3df2e-5c01-422f-baa1-d75546b92aa7").to_string();
            let client_id = ClientId::try_new(&user, client, &domain).unwrap();
            assert_eq!(
                client_id,
                ClientId {
                    user: Uuid::from_str(&user).unwrap(),
                    client,
                    domain
                }
            )
        }

        #[test]
        fn constructor_should_fail_when_user_not_uuid() {
            let client_id = ClientId::try_new("abcd", 6699, "wire.com");
            assert!(matches!(client_id.unwrap_err(), RustyJwtError::InvalidClientId))
        }
    }

    mod to_uri {
        use super::*;

        #[test]
        fn to_uri_should_succeed() {
            let user = "4af3df2e-5c01-422f-baa1-d75546b92aa7";
            let domain = "wire.com";
            let client_id = ClientId::try_new(user, u64::MAX, domain).unwrap();
            let base64_user = "NGFmM2RmMmU1YzAxNDIyZmJhYTFkNzU1NDZiOTJhYTc";
            let hex_client = "ffffffffffffffff";
            assert_eq!(
                &client_id.to_uri(),
                &format!(
                    "{}{base64_user}{}{hex_client}@{domain}",
                    ClientId::URI_PREFIX,
                    ClientId::URI_DELIMITER
                )
            );
        }
    }

    mod parse {
        use super::*;

        const USER_ID: &str = "NGFmM2RmMmU1YzAxNDIyZmJhYTFkNzU1NDZiOTJhYTc";
        const CLIENT_ID: &str = "1a2b";
        const DOMAIN: &str = "wire.com";

        mod uri {
            use super::*;

            #[test]
            fn should_succeed() {
                let subject = format!("{}{USER_ID}/{CLIENT_ID}@{DOMAIN}", ClientId::URI_PREFIX);
                let parsed = ClientId::try_from_uri(&subject).unwrap();
                assert_eq!(
                    parsed,
                    ClientId {
                        user: Uuid::from_str(&ClientId::DEFAULT_USER.to_string()).unwrap(),
                        client: 6699,
                        domain: DOMAIN.to_string(),
                    }
                );
            }

            #[test]
            fn should_fail_when_invalid_uuid_user() {
                let invalid_user = format!("{}abcd", USER_ID);
                let subject = format!("{}{invalid_user}/{CLIENT_ID}@{DOMAIN}", ClientId::URI_PREFIX);
                let parsed = ClientId::try_from_uri(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }

            #[test]
            fn should_fail_when_invalid_uri_prefix() {
                let subject = format!("im:not:wireapp={USER_ID}/{CLIENT_ID}@{DOMAIN}");
                let parsed = ClientId::try_from_uri(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }

            #[test]
            fn should_fail_when_invalid_delimiter() {
                let delimiter = "@";
                let subject = format!("{}{USER_ID}{delimiter}{CLIENT_ID}@{DOMAIN}", ClientId::URI_PREFIX);
                let parsed = ClientId::try_from_uri(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }

            #[test]
            fn should_fail_when_using_client_delimiter() {
                let delimiter = ClientId::CLIENT_DELIMITER;
                let subject = format!("{}{USER_ID}{delimiter}{CLIENT_ID}@{DOMAIN}", ClientId::URI_PREFIX);
                let parsed = ClientId::try_from_uri(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }

            #[test]
            fn should_fail_when_invalid_hex_client() {
                let invalid_client = "1g2g";
                let subject = format!("{}{USER_ID}/{invalid_client}@{DOMAIN}", ClientId::URI_PREFIX);
                let parsed = ClientId::try_from_uri(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }

            #[test]
            fn should_fail_when_client_too_large() {
                let invalid_client = u128::MAX;
                let subject = format!("{}{USER_ID}/{invalid_client:x}@{DOMAIN}", ClientId::URI_PREFIX);
                let parsed = ClientId::try_from_uri(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }
        }

        mod client {
            use super::*;

            #[test]
            fn should_succeed() {
                let subject = format!("{USER_ID}:{CLIENT_ID}@{DOMAIN}");
                let parsed = ClientId::try_from_qualified(&subject).unwrap();
                assert_eq!(
                    parsed,
                    ClientId {
                        user: Uuid::from_str(&ClientId::DEFAULT_USER.to_string()).unwrap(),
                        client: 6699,
                        domain: DOMAIN.to_string(),
                    }
                );
            }

            #[test]
            fn should_fail_when_invalid_uuid_user() {
                let invalid_user = format!("{}abcd", USER_ID);
                let subject = format!("{invalid_user}:{CLIENT_ID}@{DOMAIN}");
                let parsed = ClientId::try_from_qualified(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }

            #[test]
            fn should_fail_when_uri_prefix() {
                let subject = format!("{}{USER_ID}:{CLIENT_ID}@{DOMAIN}", ClientId::URI_PREFIX);
                let parsed = ClientId::try_from_qualified(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }

            #[test]
            fn should_fail_when_invalid_delimiter() {
                let delimiter = "@";
                let subject = format!("{USER_ID}{delimiter}{CLIENT_ID}@{DOMAIN}");
                let parsed = ClientId::try_from_qualified(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }

            #[test]
            fn should_fail_when_using_uri_delimiter() {
                let delimiter = ClientId::URI_DELIMITER;
                let subject = format!("{USER_ID}{delimiter}{CLIENT_ID}@{DOMAIN}");
                let parsed = ClientId::try_from_qualified(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }

            #[test]
            fn should_fail_when_invalid_hex_client() {
                let invalid_client = "1g2g";
                let subject = format!("{USER_ID}:{invalid_client}@{DOMAIN}");
                let parsed = ClientId::try_from_qualified(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }

            #[test]
            fn should_fail_when_client_too_large() {
                let invalid_client = u128::MAX;
                let subject = format!("{USER_ID}:{invalid_client:x}@{DOMAIN}");
                let parsed = ClientId::try_from_qualified(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }
        }
    }
}
