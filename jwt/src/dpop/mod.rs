use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};

use crate::prelude::*;

use crate::jwt::new_jti;
pub use htm::Htm;
pub use htu::Htu;
pub use verify::VerifyDpop;
pub use verify::VerifyDpopTokenHeader;

pub mod generate;
mod htm;
mod htu;
mod verify;

/// Claims in a DPoP token
///
/// Specified in [OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)][1]
///
/// [1]: https://www.ietf.org/archive/id/draft-ietf-oauth-dpop-11.html
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
    /// Allows passing extra arbitrary data which will end up in DPoP token claims
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra_claims: Option<serde_json::Value>,
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

    /// Create JWT claims (a JSON object) from DPoP fields
    pub fn into_jwt_claims(self, nonce: BackendNonce, client_id: QualifiedClientId) -> JWTClaims<Self> {
        let exp = Duration::from_secs(Self::EXP);
        let mut claims = Claims::with_custom_claims(self, exp);
        claims.jwt_id = Some(new_jti());
        claims.nonce = Some(nonce.to_string());
        claims.subject = Some(client_id.to_subject());
        claims
    }
}
