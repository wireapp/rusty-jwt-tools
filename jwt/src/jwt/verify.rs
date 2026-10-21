//! Generic Jwt utilities

use jsonwebtoken::{
    DecodingKey, Validation, decode,
    errors::{Error, ErrorKind},
};
use serde::{Serialize, de::DeserializeOwned};

use crate::{jwt::JwtClaims, prelude::*};

/// What the claims of a token must look like to pass [VerifyJwt::verify_jwt]
#[derive(Debug, Clone)]
pub struct ExpectedClaims<'a> {
    /// The client the token must belong to, i.e. the 'sub' claim must be its URI
    pub client_id: &'a ClientId,
    /// If set, the 'nonce' claim must be equal to it
    pub backend_nonce: Option<&'a BackendNonce>,
    /// The maximum number of seconds of clock skew allowed when checking 'exp', 'nbf' and 'iat'
    pub leeway: u16,
    /// If set, the 'iss' claim is required and must be equal to it
    pub issuer: Option<Htu>,
    /// Latest accepted 'exp' claim, in seconds since the UNIX epoch
    pub max_expiration: u64,
}

/// Verifies a Jwt token
pub trait VerifyJwt {
    /// Verifies the signature and the claims of the JWT token and returns its claims
    ///
    /// # Arguments
    /// * `alg` - Algorithm the token must be signed with
    /// * `key` - Public key to verify the signature with
    /// * `expected` - What the claims must look like, see [ExpectedClaims]
    fn verify_jwt<T>(
        &self,
        alg: JwsAlgorithm,
        key: &DecodingKey,
        expected: ExpectedClaims,
    ) -> RustyJwtResult<JwtClaims<T>>
    where
        T: Serialize + DeserializeOwned;
}

impl VerifyJwt for &str {
    fn verify_jwt<T>(
        &self,
        alg: JwsAlgorithm,
        key: &DecodingKey,
        expected: ExpectedClaims,
    ) -> RustyJwtResult<JwtClaims<T>>
    where
        T: Serialize + DeserializeOwned,
    {
        // Setup the validation
        let mut validation = Validation::new(alg.into());
        if let Some(issuer) = expected.issuer {
            validation.set_required_spec_claims(&["exp", "sub", "nbf", "iss"]);
            validation.set_issuer(&[issuer]);
        } else {
            validation.set_required_spec_claims(&["exp", "sub", "nbf"]);
        }
        validation.validate_aud = false;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = expected.leeway.into();
        validation.sub = Some(expected.client_id.to_uri());

        // Get the token claims, validating the above via jsonwebtoken
        let token = decode::<JwtClaims<T>>(self, key, &validation).map_err(jwt_error_mapping)?;
        let claims = token.claims;

        // custom validations
        claims.jwt_id.as_ref().ok_or(RustyJwtError::MissingTokenClaim("jti"))?;
        let issued_at = claims.issued_at.ok_or(RustyJwtError::MissingTokenClaim("iat"))?;
        let now = jsonwebtoken::get_current_timestamp();
        if issued_at > now + expected.leeway as u64 {
            return Err(RustyJwtError::TokenIssuedInFuture);
        }
        let exp = claims.expires_at.ok_or(RustyJwtError::MissingTokenClaim("exp"))?;
        if exp > expected.max_expiration {
            return Err(RustyJwtError::TokenLivesTooLong);
        }

        if let Some(backend_nonce) = expected.backend_nonce {
            let nonce = claims
                .nonce
                .as_deref()
                .ok_or(RustyJwtError::MissingTokenClaim("nonce"))?;

            if nonce != backend_nonce.as_str() {
                return Err(RustyJwtError::DpopNonceMismatch);
            }
        }

        Ok(claims)
    }
}

/// Claims which can be reported as [RustyJwtError::MissingTokenClaim]
const KNOWN_CLAIMS: &[&str] = &[
    // spec claims, reported by jsonwebtoken
    "exp",
    "nbf",
    "aud",
    "iss",
    "sub",
    // DPoP claims, reported by serde
    "chal",
    "htm",
    "htu",
    "cnf",
    "proof",
    "api_version",
    "client_id",
    "scope",
    "handle",
    "name",
];

/// Returns the `'static` name of a known claim
fn known_claim(name: &str) -> Option<&'static str> {
    KNOWN_CLAIMS.iter().copied().find(|&claim| claim == name)
}

/// Maps jsonwebtoken::errors::Error to RustyJwtError
pub fn jwt_error_mapping(e: Error) -> RustyJwtError {
    match e.into_kind() {
        ErrorKind::MissingRequiredClaim(claim) => known_claim(&claim)
            .map(RustyJwtError::MissingTokenClaim)
            .unwrap_or_else(|| RustyJwtError::InvalidToken(format!("missing required claim '{claim}'"))),

        ErrorKind::InvalidSubject => RustyJwtError::TokenSubMismatch,

        ErrorKind::ExpiredSignature => RustyJwtError::TokenExpired,

        ErrorKind::ImmatureSignature => RustyJwtError::TokenNotYetValid,

        ErrorKind::InvalidIssuer => RustyJwtError::TokenIssuerMismatch,

        // DPoP claims failing because of serde
        ErrorKind::Json(error) => {
            let msg = error.to_string();

            msg.strip_prefix("missing field `")
                .and_then(|rest| rest.split_once('`'))
                .and_then(|(field, _)| known_claim(field))
                .map(RustyJwtError::MissingTokenClaim)
                .unwrap_or(RustyJwtError::InvalidToken(msg))
        }
        other => RustyJwtError::InvalidToken(format!("{other:?}")),
    }
}
