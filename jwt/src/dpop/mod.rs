use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};

pub use htm::Htm;
pub use htu::Htu;
pub use verify::VerifyDpop;
pub use verify::VerifyDpopTokenHeader;

use crate::jwt::new_jti;
use crate::prelude::*;

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
    pub challenge: AcmeNonce,
    /// Allows passing extra arbitrary data which will end up in DPoP token claims
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra_claims: Option<serde_json::Value>,
}

impl Dpop {
    /// JWT header 'typ'
    pub const TYP: &'static str = "dpop+jwt";

    /// Create JWT claims (a JSON object) from DPoP fields
    pub fn into_jwt_claims(
        self,
        nonce: BackendNonce,
        client_id: ClientId,
        expiry: core::time::Duration,
    ) -> JWTClaims<Self> {
        let expiry = coarsetime::Duration::from_secs(expiry.as_secs());
        Claims::with_custom_claims(self, expiry)
            .with_jwt_id(new_jti())
            .with_nonce(nonce.to_string())
            .with_subject(client_id.to_subject())
    }
}
