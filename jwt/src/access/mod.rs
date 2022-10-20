use jwt_simple::prelude::*;

use crate::jkt::JktConfirmation;
use crate::jwt::new_jti;
use crate::prelude::*;

pub mod generate;
mod verify;

/// Claims in an access token
///
/// Specified in [OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)][1]
///
/// [1]: https://www.ietf.org/archive/id/draft-ietf-oauth-dpop-11.html
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(test, derive(Default))]
pub struct Access {
    /// ACME server nonce
    #[serde(rename = "chal")]
    pub challenge: AcmeChallenge,
    /// Hash of the JWK, see [JktConfirmation]
    #[serde(rename = "cnf")]
    pub cnf: JktConfirmation,
    /// Allows passing extra arbitrary data which will end up in access token claims
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra_claims: Option<serde_json::Value>,
}

impl Access {
    /// JWT claim 'exp' (expiration) in seconds (90 days by default)
    ///
    /// Specified in [RFC 7519 Section 4.1.4: JSON Web Token (JWT)][1]
    ///
    /// [1]: https://tools.ietf.org/html/rfc7519#section-4.1.4
    pub const EXP: u64 = 3600 * 24 * 90; // 90 days

    pub fn into_jwt_claims(self, client_id: QualifiedClientId, nonce: BackendNonce) -> JWTClaims<Self> {
        let exp = Duration::from_secs(Self::EXP);
        let mut claims = Claims::with_custom_claims(self, exp);
        claims.jwt_id = Some(new_jti());
        claims.subject = Some(client_id.to_subject());
        claims.nonce = Some(nonce.to_string());
        claims
    }
}
