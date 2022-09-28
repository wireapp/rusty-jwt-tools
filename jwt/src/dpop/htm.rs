use serde::{Deserialize, Serialize};

use crate::prelude::*;

/// HTTP methods allowed in a DPoP token. We only declare those in use by Wire
///
/// Specified in [RFC 7231 Section 4: Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content][1]
///
/// [1]: https://tools.ietf.org/html/rfc7231#section-4
#[derive(Debug, Copy, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(test, derive(Default))]
pub enum Htm {
    /// HTTP POST method
    #[cfg_attr(test, default)]
    Post,
    #[cfg(test)]
    Put,
}

impl TryFrom<&str> for Htm {
    type Error = RustyJwtError;

    fn try_from(value: &str) -> RustyJwtResult<Self> {
        Ok(match value {
            "POST" => Self::Post,
            _ => return Err(RustyJwtError::InvalidHtm(value.to_string())),
        })
    }
}

impl TryFrom<String> for Htm {
    type Error = RustyJwtError;

    fn try_from(value: String) -> RustyJwtResult<Self> {
        value.as_str().try_into()
    }
}

impl TryFrom<&[u8]> for Htm {
    type Error = RustyJwtError;

    fn try_from(value: &[u8]) -> RustyJwtResult<Self> {
        core::str::from_utf8(value)?.try_into()
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test]
    fn should_accept_post() {
        assert!(Htm::try_from(b"POST".as_slice()).is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn should_be_case_sensitive() {
        assert!(matches!(
            Htm::try_from(b"post".as_slice()).unwrap_err(),
            RustyJwtError::InvalidHtm(m) if &m == "post"
        ));
    }

    #[test]
    #[wasm_bindgen_test]
    fn should_fail_when_unsupported_method() {
        assert!(matches!(
            Htm::try_from(b"HEAD".as_slice()).unwrap_err(),
            RustyJwtError::InvalidHtm(m) if &m == "HEAD"
        ));
    }
}
