//! Generic Jwt utilities

use jwt_simple::prelude::*;
use serde::de::DeserializeOwned;

use crate::jwk_thumbprint::JwkThumbprint;
use crate::prelude::*;

/// Global trait to verify a Jwt token
#[derive(Debug, Clone)]
pub struct Verify<'a> {
    /// client_id
    pub client_id: ClientId<'a>,
    /// nonce
    pub backend_nonce: Option<&'a BackendNonce>,
    /// leeway
    pub leeway: u16,
    /// cnf
    pub cnf: Option<&'a JwkThumbprint>,
}

impl From<&Verify<'_>> for VerificationOptions {
    fn from(v: &Verify<'_>) -> Self {
        Self {
            accept_future: false,
            required_key_id: None, // we don't verify 'jti', just enforce its presence
            required_subject: Some(v.client_id.to_subject()),
            required_nonce: v.backend_nonce.map(|n| n.to_string()),
            time_tolerance: Some(UnixTimeStamp::from_secs(v.leeway as u64)),
            ..Default::default()
        }
    }
}

/// Verifies JWT token standard headers
pub trait VerifyJwtHeader {
    /// Verifies a Jwt token header
    fn verify_jwt_header(&self) -> RustyJwtResult<JwsAlgorithm>;
}

impl VerifyJwtHeader for TokenMetadata {
    fn verify_jwt_header(&self) -> RustyJwtResult<JwsAlgorithm> {
        // fails when the algorithm is not supported
        let alg = JwsAlgorithm::try_from(self.algorithm())?;
        Ok(alg)
    }
}

/// Verifies a Jwt token
pub trait VerifyJwt {
    /// Verifies the JWT token given a JWK
    ///
    /// # Arguments
    /// * `key` - Public signature key
    /// * `client_id` - client identifier
    /// * `backend_nonce` - optional nonce generated by wire-server
    /// * `max_expiration` - token's 'exp' threshold
    /// * `leeway` - The maximum number of seconds of clock skew the implementation will allow
    fn verify_jwt<T>(
        &self,
        key: &AnyPublicKey,
        max_expiration: u64,
        cnf: Option<&JwkThumbprint>,
        verify: Verify,
    ) -> RustyJwtResult<JWTClaims<T>>
    where
        T: Serialize + DeserializeOwned;
}

impl VerifyJwt for &str {
    fn verify_jwt<T>(
        &self,
        key: &AnyPublicKey<'_>,
        max_expiration: u64,
        cnf: Option<&JwkThumbprint>,
        verify: Verify,
    ) -> RustyJwtResult<JWTClaims<T>>
    where
        T: Serialize + DeserializeOwned,
    {
        let verifications = Some(VerificationOptions::from(&verify));
        let claims = key.verify_token::<T>(self, verifications).map_err(jwt_error_mapping)?;

        claims.jwt_id.as_ref().ok_or(RustyJwtError::MissingTokenClaim("jti"))?;
        let exp = claims.expires_at.ok_or(RustyJwtError::MissingTokenClaim("exp"))?;
        claims.issued_at.ok_or(RustyJwtError::MissingTokenClaim("iat"))?;
        if exp > Duration::from_secs(max_expiration) {
            return Err(RustyJwtError::TokenLivesTooLong);
        }

        if let Some(cnf) = cnf {
            if Some(cnf) != verify.cnf {
                return Err(RustyJwtError::InvalidJwkThumbprint);
            }
        }

        Ok(claims)
    }
}

/// Tries mapping 'jwt-simple' errors
pub fn jwt_error_mapping(e: jwt_simple::Error) -> RustyJwtError {
    let reason = e.to_string();
    // since `jwt_simple` returns [anyhow::Error] which we can't pattern match against
    // we have to parse the reason to "guess" the root cause
    match reason.as_str() {
        // standard claims failing because of [VerificationOptions]
        "Required subject missing" => RustyJwtError::MissingTokenClaim("sub"),
        "Required nonce missing" => RustyJwtError::MissingTokenClaim("nonce"),
        "Required subject mismatch" => RustyJwtError::TokenSubMismatch,
        "Required nonce mismatch" => RustyJwtError::DpopNonceMismatch,
        "Clock drift detected" => RustyJwtError::InvalidDpopIat,
        "Token has expired" => RustyJwtError::TokenExpired,
        "Invalid JWK in DPoP token" => RustyJwtError::InvalidDpopJwk,
        // DPoP claims failing because of serde
        r if r.starts_with("missing field `chal`") => RustyJwtError::MissingTokenClaim("chal"),
        r if r.starts_with("missing field `htm`") => RustyJwtError::MissingTokenClaim("htm"),
        r if r.starts_with("missing field `htu`") => RustyJwtError::MissingTokenClaim("htu"),
        r if r.starts_with("missing field `cnf`") => RustyJwtError::MissingTokenClaim("cnf"),
        r if r.starts_with("missing field `proof`") => RustyJwtError::MissingTokenClaim("proof"),
        r if r.starts_with("missing field `api_version`") => RustyJwtError::MissingTokenClaim("api_version"),
        r if r.starts_with("missing field `client_id`") => RustyJwtError::MissingTokenClaim("client_id"),
        r if r.starts_with("missing field `scope`") => RustyJwtError::MissingTokenClaim("scope"),
        _ => RustyJwtError::InvalidToken(reason),
    }
}
