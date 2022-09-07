use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};

use crate::prelude::*;

/// Claims in a DPoP token
///
/// Specified in [OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)][1]
///
/// [1]: https://www.ietf.org/archive/id/draft-ietf-oauth-dpop-08.html
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(test, derive(Default))]
pub struct Dpop {
    /// The HTTP method of the request to which the JWT is attached
    #[serde(rename = "htm")]
    pub htm: Htm,
    /// The HTTP request URI
    #[serde(rename = "htu")]
    pub htu: Htu,
    /// ACME server nonce
    #[serde(rename = "chal")]
    pub challenge: AcmeChallenge,
}

/// HTTP methods allowed in a DPoP token. We only declare those in use by Wire
///
/// Specified in [RFC 7231 Section 4: Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content][1]
///
/// [1]: https://tools.ietf.org/html/rfc7231#section-4
#[derive(Debug, Copy, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(test, derive(Default))]
pub enum Htm {
    #[cfg_attr(test, default)]
    Post,
}

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
        "http://wire.com".try_into().unwrap()
    }
}

impl TryFrom<String> for Htu {
    type Error = RustyJwtError;

    fn try_from(u: String) -> RustyJwtResult<Self> {
        u.as_str().try_into()
    }
}

impl TryFrom<&str> for Htu {
    type Error = RustyJwtError;

    fn try_from(u: &str) -> RustyJwtResult<Self> {
        const QUERY_REASON: &str = "cannot contain query parameter";
        const FRAGMENT_REASON: &str = "cannot contain fragment parameter";

        let uri = url::Url::try_from(u)?;
        if uri.query().is_some() {
            return Err(RustyJwtError::HtuError(uri, QUERY_REASON));
        }
        if uri.fragment().is_some() {
            return Err(RustyJwtError::HtuError(uri, FRAGMENT_REASON));
        }
        Ok(Self(uri))
    }
}

impl Dpop {
    /// JWT header 'typ'
    pub const TYP: &'static str = "dpop+jwt";
    /// JWT claim 'exp' (expiration) in seconds (90 days by default)
    ///
    /// Specified in [RFC 7519 Section 4.1.4: JSON Web Token (JWT)][1]
    ///
    /// [1]: https://tools.ietf.org/html/rfc7519#section-4.1.4
    pub const EXP: u64 = 3600 * 24 * 90; // 90 days

    pub fn into_jwt_claims(self, nonce: BackendNonce, client_id: ClientId) -> JWTClaims<Dpop> {
        let exp = Duration::from_secs(Dpop::EXP);
        let mut claims = Claims::with_custom_claims(self, exp);
        claims = claims.with_jwt_id(Self::new_jti());
        claims = claims.with_nonce(nonce);
        claims = claims.with_subject(String::from(client_id));
        claims
    }

    fn new_jti() -> String {
        uuid::Uuid::new_v4().to_string()
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::test_utils::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod htu {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        fn can_create_from_valid_uri() {
            let uri = "https://wire.com";
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
                matches!(Htu::try_from(uri).unwrap_err(), RustyJwtError::HtuError(u, r) if u == url::Url::try_from(uri).unwrap() && r == "cannot contain query parameter")
            )
        }

        #[test]
        #[wasm_bindgen_test]
        fn fail_creating_from_invalid_with_fragment() {
            let uri = "https://wire.com#rocks";
            assert!(
                matches!(Htu::try_from(uri).unwrap_err(), RustyJwtError::HtuError(u, r) if u == url::Url::try_from(uri).unwrap() && r == "cannot contain fragment parameter")
            )
        }
    }
}
