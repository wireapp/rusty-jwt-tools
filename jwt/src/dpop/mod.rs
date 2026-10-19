use std::time::Duration;

pub use htm::Htm;
pub use htu::Htu;
use serde::{Deserialize, Serialize};
pub(crate) use verify::{VerifyDpop, VerifyDpopTokenHeader};

use crate::{jwt::JwtClaims, prelude::*};

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

    /// Create JWT claims (a JSON object) from DPoP fields
    pub fn into_jwt_claims(
        self,
        nonce: BackendNonce,
        client_id: &ClientId,
        expiry: Duration,
        audience: url::Url,
    ) -> JwtClaims<Self> {
        JwtClaims::new_for_client(self, client_id, nonce, audience, expiry)
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
