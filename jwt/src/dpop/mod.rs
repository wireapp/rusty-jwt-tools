pub use htm::Htm;
pub use htu::Htu;
use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};
pub(crate) use verify::{VerifyDpop, VerifyDpopTokenHeader};

use crate::{jwt::new_jti, prelude::*};

mod generate;
mod htm;
mod htu;
mod verify;

/// Claims in a DPoP token
///
/// Specified in [OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)][1]
///
/// [1]: https://www.ietf.org/archive/id/draft-ietf-oauth-dpop-11.html
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
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
    /// Client's handle e.g. `beltram_wire`
    #[serde(rename = "handle")]
    pub handle: QualifiedHandle,
    /// Team the client belongs to e.g. `wire`
    #[serde(rename = "team")]
    pub team: Team,
    /// Display name (aka Official Name) of the client
    #[serde(rename = "name")]
    pub display_name: String,
    /// Allows passing extra arbitrary data which will end up in DPoP token claims
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra_claims: Option<serde_json::Value>,
}

impl Dpop {
    /// JWT header 'typ'
    pub const TYP: &'static str = "dpop+jwt";

    /// we want "nbf" & "iat" slightly in the past to prevent clock drifts or problems non-monotonic hosts
    pub(crate) const NOW_LEEWAY_SECONDS: u64 = 3600;

    /// Create JWT claims (a JSON object) from DPoP fields
    pub fn into_jwt_claims(
        self,
        nonce: BackendNonce,
        client_id: &ClientId,
        expiry: core::time::Duration,
        audience: url::Url,
    ) -> JWTClaims<Self> {
        let expiry = coarsetime::Duration::from_secs(expiry.as_secs());
        let now = coarsetime::Clock::now_since_epoch() - Duration::from_secs(Self::NOW_LEEWAY_SECONDS);
        let mut claims = Claims::with_custom_claims(self, expiry)
            .with_audience(audience)
            .invalid_before(now)
            .with_jwt_id(new_jti())
            .with_nonce(nonce.to_string())
            .with_subject(client_id.to_uri());
        claims.issued_at = Some(now);
        claims
    }
}

#[cfg(test)]
impl Default for Dpop {
    fn default() -> Self {
        Self {
            htm: Htm::default(),
            htu: Htu::default(),
            challenge: AcmeNonce::default(),
            handle: QualifiedHandle::default(),
            team: Team::default(),
            display_name: "John Doe".to_string(),
            extra_claims: None,
        }
    }
}
