use crate::model::DEFAULT_URL;
use crate::prelude::{ClientId, RustyJwtError, RustyJwtResult};
use percent_encoding::percent_decode_str;
use std::str::FromStr;

/// A unique human-friendly identifier for a user e.g. `beltram_wire`
#[derive(Debug, Clone, Eq, PartialEq, derive_more::From, derive_more::Into, derive_more::Deref)]
pub struct Handle(String);

impl Handle {
    /// Present in front of the handle. It's '@' URL encoded
    pub const PREFIX: &'static str = "%40";

    /// Converts the handle into i.e. `{handle}` => `wireapp://%40{handle}@{domain}`
    pub fn try_to_qualified(&self, host: &str) -> RustyJwtResult<QualifiedHandle> {
        // sadly this is the only way to have a Url builder :/
        let mut uri = DEFAULT_URL.clone();

        uri.set_host(Some(host)).map_err(|_| RustyJwtError::InvalidHandle)?;
        let username = format!("@{}", self.0);
        uri.set_username(&username).map_err(|_| RustyJwtError::InvalidHandle)?;
        Ok(QualifiedHandle(uri.to_string()))
    }
}

impl TryFrom<QualifiedHandle> for Handle {
    type Error = RustyJwtError;

    fn try_from(qh: QualifiedHandle) -> RustyJwtResult<Self> {
        let trimmed = qh
            .trim_start_matches(ClientId::URI_SCHEME)
            .trim_start_matches(Self::PREFIX);
        let Some((handle, _)) = trimmed.rsplit_once('@') else {
            return Err(RustyJwtError::InvalidHandle);
        };
        Ok(handle.into())
    }
}

impl From<&str> for Handle {
    fn from(s: &str) -> Self {
        s.to_string().into()
    }
}

impl TryFrom<&[u8]> for Handle {
    type Error = RustyJwtError;

    fn try_from(value: &[u8]) -> RustyJwtResult<Self> {
        Ok(core::str::from_utf8(value)?.into())
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Default for Handle {
    fn default() -> Self {
        "beltram_wire".into()
    }
}

/// A handle represented as a URI e.g. `wireapp://%40beltram_wire@wire.com`
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize, derive_more::Deref)]
pub struct QualifiedHandle(String);

impl FromStr for QualifiedHandle {
    type Err = RustyJwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uri = url::Url::parse(s)?;

        let scheme = uri.scheme();
        if scheme != ClientId::URI_RAW_SCHEME {
            return Err(RustyJwtError::InvalidIdentifierScheme(scheme.to_string()));
        }

        let username = percent_decode_str(uri.username()).decode_utf8()?;
        if !username.starts_with('@') {
            return Err(RustyJwtError::InvalidHandle);
        }

        Ok(Self(s.to_string()))
    }
}

/// Should only be used in tests
impl std::fmt::Display for QualifiedHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Default for QualifiedHandle {
    fn default() -> Self {
        Handle::default().try_to_qualified("wire.com").unwrap()
    }
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test]
    fn should_build_qualified() {
        let (username, host) = ("beltram_wire", "wire.com");
        let handle = Handle::from(username);
        let qualified_handle = handle.try_to_qualified(host).unwrap();
        assert_eq!(&qualified_handle.0, "wireapp://%40beltram_wire@wire.com");

        // should be a valid URI
        let uri = url::Url::parse(&qualified_handle.0).unwrap();
        assert_eq!(uri.scheme(), "wireapp");
        assert_eq!(uri.host_str(), Some(host));
        assert_eq!(uri.username(), "%40beltram_wire");
    }

    mod parse {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        fn should_parse_qualified() {
            let qualified_handle = "wireapp://%40beltram_wire@wire.com".parse::<QualifiedHandle>().unwrap();
            let handle = Handle::try_from(qualified_handle).unwrap();
            assert_eq!(&handle.0, "beltram_wire");
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_invalid_scheme() {
            let qualified_handle = "http://%40beltram_wire@wire.com".parse::<QualifiedHandle>();
            assert!(matches!(
                qualified_handle.unwrap_err(),
                RustyJwtError::InvalidIdentifierScheme(scheme) if scheme == "http"
            ));
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_invalid_username() {
            let qualified_handle = "wireapp://beltram_wire@wire.com".parse::<QualifiedHandle>();
            assert!(matches!(qualified_handle.unwrap_err(), RustyJwtError::InvalidHandle));
        }
    }
}
