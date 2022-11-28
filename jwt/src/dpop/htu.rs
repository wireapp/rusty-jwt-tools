use serde::{Deserialize, Serialize};

use crate::prelude::*;

/// The HTTP request URI without query and fragment parts
///
/// Specified in [RFC 7230 Section 5.5: Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content][1]
///
/// [1]: https://tools.ietf.org/html/rfc7230#section-5.5
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Htu(url::Url);

#[cfg(test)]
impl Default for Htu {
    fn default() -> Self {
        "https://wire.example.com/client/token".try_into().unwrap()
    }
}

impl TryFrom<&[u8]> for Htu {
    type Error = RustyJwtError;

    fn try_from(u: &[u8]) -> RustyJwtResult<Self> {
        core::str::from_utf8(u)?.try_into()
    }
}

impl TryFrom<&str> for Htu {
    type Error = RustyJwtError;

    fn try_from(u: &str) -> RustyJwtResult<Self> {
        const QUERY_REASON: &str = "cannot contain query parameter";
        const FRAGMENT_REASON: &str = "cannot contain fragment parameter";

        let uri = url::Url::try_from(u)?;
        if uri.query().is_some() {
            return Err(RustyJwtError::InvalidHtu(uri, QUERY_REASON));
        }
        if uri.fragment().is_some() {
            return Err(RustyJwtError::InvalidHtu(uri, FRAGMENT_REASON));
        }
        Ok(Self(uri))
    }
}

impl ToString for Htu {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test]
    fn can_create_from_valid_uri() {
        let uri = "https://wire.com";
        assert!(Htu::try_from(uri).is_ok())
    }

    #[test]
    #[wasm_bindgen_test]
    fn can_create_from_bytes() {
        let uri = "https://wire.com".as_bytes();
        assert!(Htu::try_from(uri).is_ok())
    }

    #[test]
    #[wasm_bindgen_test]
    fn fail_creating_from_invalid_uri() {
        let uri = "https://wire com";
        assert!(Htu::try_from(uri).is_err())
    }

    #[test]
    #[wasm_bindgen_test]
    fn fail_creating_from_invalid_with_query() {
        let uri = "https://wire.com?a=b";
        assert!(
            matches!(Htu::try_from(uri).unwrap_err(), RustyJwtError::InvalidHtu(u, r) if u == url::Url::try_from(uri).unwrap() && r == "cannot contain query parameter")
        )
    }

    #[test]
    #[wasm_bindgen_test]
    fn fail_creating_from_invalid_with_fragment() {
        let uri = "https://wire.com#rocks";
        assert!(
            matches!(Htu::try_from(uri).unwrap_err(), RustyJwtError::InvalidHtu(u, r) if u == url::Url::try_from(uri).unwrap() && r == "cannot contain fragment parameter")
        )
    }
}
