use crate::model::DEFAULT_URL;
use base64::Engine;
use const_format::concatcp;
use percent_encoding::percent_decode_str;
use url::Url;
use uuid::Uuid;

use crate::prelude::*;

/// Unique user handle
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ClientId {
    /// base64url encoded UUIDv4 unique user identifier
    pub user_id: Uuid,
    /// the device id assigned by the backend in hex
    pub device_id: u64,
    /// the backend domain of the client
    pub domain: String,
}

impl ClientId {
    #[cfg(test)]
    pub const DEFAULT_USER: Uuid = uuid::uuid!("4af3df2e-5c01-422f-baa1-d75546b92aa7");

    /// URI scheme for all subject URIs
    pub const URI_RAW_SCHEME: &'static str = "wireapp";

    /// URI scheme for all subject URIs
    pub const URI_SCHEME: &'static str = concatcp!(ClientId::URI_RAW_SCHEME, "://");

    /// user-id & device-id separator
    pub const DELIMITER: &'static str = ":";

    /// user-id & device-id separator when ClientId is represented as a URI
    pub const URI_DELIMITER: &'static str = "!";

    /// Constructor
    pub fn try_new(user_id: impl AsRef<str>, device_id: u64, domain: &str) -> RustyJwtResult<Self> {
        let user_id = uuid::Uuid::try_from(user_id.as_ref()).map_err(|_| RustyJwtError::InvalidClientId)?;
        Ok(Self {
            user_id,
            device_id,
            domain: domain.to_string(),
        })
    }

    /// Constructor
    pub fn try_from_raw_parts(user_id: &[u8], device_id: u64, domain: &[u8]) -> RustyJwtResult<Self> {
        let user_id = Uuid::from_slice(user_id)?;
        let domain = core::str::from_utf8(domain)?.to_string();
        Ok(Self {
            user_id,
            device_id,
            domain,
        })
    }

    /// Parse from an URI e.g. `wireapp://{userId}%21{clientId}@{domain}` where '%21' is '!' percent encoded
    pub fn try_from_uri(client_id: &str) -> RustyJwtResult<Self> {
        let uri = client_id.parse::<Url>()?;
        if uri.scheme() != Self::URI_RAW_SCHEME {
            return Err(RustyJwtError::InvalidIdentifierScheme(uri.scheme().to_string()));
        }

        let username = percent_decode_str(uri.username()).decode_utf8()?;
        let (user_id, device_id) = username.split_once('!').ok_or(RustyJwtError::InvalidClientId)?;

        let user_id = Self::parse_user_id(user_id)?;
        let device_id = Self::parse_device_id(device_id)?;
        let domain = uri.host_str().ok_or(RustyJwtError::InvalidClientId)?.to_string();
        Ok(Self {
            user_id,
            device_id,
            domain: domain.to_string(),
        })
    }

    /// Constructor for clientId usually used by Wire client application. It is not a URI (does not have a scheme)
    /// e.g. `wireapp://{userId}!{clientId}@{domain}`
    pub fn try_from_qualified(client_id: &str) -> RustyJwtResult<Self> {
        let (user_id, rest) = client_id
            .split_once(Self::DELIMITER)
            .ok_or(RustyJwtError::InvalidClientId)?;
        let user_id = Self::parse_user_id(user_id)?;
        let (device_id, domain) = rest.split_once('@').ok_or(RustyJwtError::InvalidClientId)?;
        let device_id = Self::parse_device_id(device_id)?;
        Ok(Self {
            user_id,
            device_id,
            domain: domain.to_string(),
        })
    }

    /// Into JWT 'sub' claim
    pub fn to_uri(&self) -> String {
        // sadly this is the only way to have a Url builder :/
        let mut uri = DEFAULT_URL.clone();
        let user_id = self.base64_encoded_user_id();
        let device_id = self.hex_encoded_device_id();
        let client_id = format!("{user_id}{}{device_id}", ClientId::URI_DELIMITER);
        uri.set_username(&client_id).unwrap();
        uri.set_host(Some(&self.domain)).unwrap();
        uri.to_string()
    }

    /// Without URI scheme
    pub fn to_qualified(&self) -> String {
        let user_id = self.base64_encoded_user_id();
        let delimiter = Self::DELIMITER;
        let device_id = self.hex_encoded_device_id();
        let host = &self.domain;
        format!("{user_id}{delimiter}{device_id}@{host}")
    }

    fn base64_encoded_user_id(&self) -> String {
        let user_id = self.user_id.as_bytes().as_slice();
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(user_id)
    }

    fn hex_encoded_device_id(&self) -> String {
        format!("{:x}", self.device_id)
    }

    fn parse_user_id(user_id: &str) -> RustyJwtResult<Uuid> {
        let user_id = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(user_id)
            .map_err(|_| RustyJwtError::InvalidClientId)?;
        Ok(Uuid::from_slice(&user_id)?)
    }

    fn parse_device_id(device_id: &str) -> RustyJwtResult<u64> {
        u64::from_str_radix(device_id, 16).map_err(|_| RustyJwtError::InvalidClientId)
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
pub mod tests {
    use std::str::FromStr as _;

    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test]
    fn should_roundtrip() {
        let user_id = Uuid::new_v4().to_string();
        let device_id = u64::MAX;
        let domain = "wire.com";
        let client_id = ClientId::try_new(user_id, device_id, domain).unwrap();
        assert_eq!(client_id, ClientId::try_from_uri(&client_id.to_uri()).unwrap());
        assert_eq!(
            client_id,
            ClientId::try_from_qualified(&client_id.to_qualified()).unwrap()
        );
    }

    mod constructor {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        fn constructor_should_build() {
            let client = 6699;
            let domain = "wire.com".to_string();
            let user = uuid::uuid!("4af3df2e-5c01-422f-baa1-d75546b92aa7").to_string();
            let client_id = ClientId::try_new(&user, client, &domain).unwrap();
            assert_eq!(
                client_id,
                ClientId {
                    user_id: Uuid::from_str(&user).unwrap(),
                    device_id: client,
                    domain
                }
            )
        }

        #[test]
        #[wasm_bindgen_test]
        fn constructor_should_fail_when_user_not_uuid() {
            let client_id = ClientId::try_new("abcd", 6699, "wire.com");
            assert!(matches!(client_id.unwrap_err(), RustyJwtError::InvalidClientId))
        }
    }

    mod to_uri {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        fn to_uri_should_succeed() {
            let user = "4af3df2e-5c01-422f-baa1-d75546b92aa7";
            let domain = "wire.com";
            let client_id = ClientId::try_new(user, u64::MAX, domain).unwrap();
            let base64_user = "SvPfLlwBQi-6oddVRrkqpw";
            let hex_client = "ffffffffffffffff";
            assert_eq!(
                client_id.to_uri(),
                format!("wireapp://{base64_user}!{hex_client}@{domain}",)
            );
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_be_a_valid_uri() {
            let domain = "wire.com";
            let user = Uuid::new_v4().to_string();
            let client_id = ClientId::try_new(user, u64::MAX, domain).unwrap();
            assert!(Url::parse(&client_id.to_uri()).is_ok());
        }

        #[test]
        #[wasm_bindgen_test]
        fn uri_should_have_the_expected_host() {
            let user = Uuid::new_v4().to_string();
            let domain = "wire.com";
            let client_id = ClientId::try_new(user, u64::MAX, domain).unwrap();
            let uri = Url::parse(&client_id.to_uri()).unwrap();
            assert_eq!(uri.host_str().unwrap(), domain);
        }
    }

    mod parse {
        use super::*;

        const USER_ID: &str = "SvPfLlwBQi-6oddVRrkqpw";
        const CLIENT_ID: &str = "1a2b";
        const DOMAIN: &str = "wire.com";

        mod uri {
            use super::*;

            #[test]
            #[wasm_bindgen_test]
            fn should_succeed() {
                let subject = format!("wireapp://{USER_ID}!{CLIENT_ID}@{DOMAIN}");
                let parsed = ClientId::try_from_uri(&subject).unwrap();
                let expected_client_id = ClientId {
                    user_id: Uuid::from_str(&ClientId::DEFAULT_USER.to_string()).unwrap(),
                    device_id: 6699,
                    domain: DOMAIN.to_string(),
                };
                assert_eq!(parsed, expected_client_id);

                // should percent decode the URI username before parsing the ClientId
                let subject = format!("wireapp://{USER_ID}%21{CLIENT_ID}@{DOMAIN}");
                let parsed = ClientId::try_from_uri(&subject).unwrap();

                assert_eq!(parsed, expected_client_id);
            }

            #[test]
            #[wasm_bindgen_test]
            fn should_fail_when_invalid_uuid_user() {
                let invalid_user = format!("{}abcd", USER_ID);
                let subject = format!("{}{invalid_user}:{CLIENT_ID}@{DOMAIN}", ClientId::URI_SCHEME);
                let parsed = ClientId::try_from_uri(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }

            #[test]
            #[wasm_bindgen_test]
            fn should_fail_when_invalid_scheme() {
                let subject = format!("http://{USER_ID}:{CLIENT_ID}@{DOMAIN}");
                let parsed = ClientId::try_from_uri(&subject);
                assert!(
                    matches!(parsed.unwrap_err(), RustyJwtError::InvalidIdentifierScheme(scheme) if scheme == "http")
                );
            }

            #[test]
            #[wasm_bindgen_test]
            fn should_fail_when_invalid_delimiter() {
                let delimiter = "@";
                let subject = format!("{}{USER_ID}{delimiter}{CLIENT_ID}@{DOMAIN}", ClientId::URI_SCHEME);
                let parsed = ClientId::try_from_uri(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }

            #[test]
            #[wasm_bindgen_test]
            fn should_fail_when_invalid_hex_client() {
                let invalid_device_id = "1g2g";
                let subject = format!("{}{USER_ID}:{invalid_device_id}@{DOMAIN}", ClientId::URI_SCHEME);
                let parsed = ClientId::try_from_uri(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }

            #[test]
            #[wasm_bindgen_test]
            fn should_fail_when_client_too_large() {
                let invalid_client = u128::MAX;
                let subject = format!("{}{USER_ID}:{invalid_client:x}@{DOMAIN}", ClientId::URI_SCHEME);
                let parsed = ClientId::try_from_uri(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }
        }

        mod qualified {
            use super::*;

            #[test]
            #[wasm_bindgen_test]
            fn should_succeed() {
                let subject = format!("{USER_ID}:{CLIENT_ID}@{DOMAIN}");
                let parsed = ClientId::try_from_qualified(&subject).unwrap();
                assert_eq!(
                    parsed,
                    ClientId {
                        user_id: Uuid::from_str(&ClientId::DEFAULT_USER.to_string()).unwrap(),
                        device_id: 6699,
                        domain: DOMAIN.to_string(),
                    }
                );
            }

            #[test]
            #[wasm_bindgen_test]
            fn should_fail_when_invalid_uuid_user() {
                let invalid_user = format!("{}abcd", USER_ID);
                let subject = format!("{invalid_user}:{CLIENT_ID}@{DOMAIN}");
                let parsed = ClientId::try_from_qualified(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }

            #[test]
            #[wasm_bindgen_test]
            fn should_fail_when_uri_prefix() {
                let subject = format!("{}{USER_ID}:{CLIENT_ID}@{DOMAIN}", ClientId::URI_SCHEME);
                let parsed = ClientId::try_from_qualified(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }

            #[test]
            #[wasm_bindgen_test]
            fn should_fail_when_invalid_delimiter() {
                let delimiter = "@";
                let subject = format!("{USER_ID}{delimiter}{CLIENT_ID}@{DOMAIN}");
                let parsed = ClientId::try_from_qualified(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }

            #[test]
            #[wasm_bindgen_test]
            fn should_fail_when_invalid_hex_client() {
                let invalid_client = "1g2g";
                let subject = format!("{USER_ID}:{invalid_client}@{DOMAIN}");
                let parsed = ClientId::try_from_qualified(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }

            #[test]
            #[wasm_bindgen_test]
            fn should_fail_when_client_too_large() {
                let invalid_client = u128::MAX;
                let subject = format!("{USER_ID}:{invalid_client:x}@{DOMAIN}");
                let parsed = ClientId::try_from_qualified(&subject);
                assert!(matches!(parsed.unwrap_err(), RustyJwtError::InvalidClientId));
            }
        }
    }
}
