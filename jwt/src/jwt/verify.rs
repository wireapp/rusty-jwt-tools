//! Generic Jwt utilities

use jsonwebtoken::{
    DecodingKey, Validation, decode,
    errors::{Error, ErrorKind},
};
use serde::{Serialize, de::DeserializeOwned};

use crate::{jwt::JwtClaims, prelude::*};

/// What the claims of a token must look like to pass [verify_jwt]
#[derive(Debug, Clone)]
pub(crate) struct ExpectedClaims<'a> {
    /// The client the token must belong to, i.e. the 'sub' claim must be its URI
    pub client_id: &'a ClientId,
    /// The 'nonce' claim must be equal to it
    pub backend_nonce: &'a BackendNonce,
    /// The maximum number of seconds of clock skew allowed when checking 'exp', 'nbf' and 'iat'
    pub leeway: u16,
    /// Latest accepted 'exp' claim, in seconds since the UNIX epoch
    pub max_expiration: u64,
}

/// Verifies the signature and the claims of a JWT token and returns its claims
///
/// # Arguments
/// * `token` - JWT token in compact serialization
/// * `alg` - Algorithm the token must be signed with
/// * `key` - Public key to verify the signature with
/// * `expected` - What the claims must look like, see [ExpectedClaims]
pub(crate) fn verify_jwt<T>(
    token: &str,
    alg: JwsAlgorithm,
    key: &DecodingKey,
    expected: ExpectedClaims,
) -> RustyJwtResult<JwtClaims<T>>
where
    T: Serialize + DeserializeOwned,
{
    // Setup the validation
    let mut validation = Validation::new(alg.into());
    validation.set_required_spec_claims(&["exp", "sub", "nbf"]);
    validation.validate_aud = false;
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = expected.leeway.into();
    validation.sub = Some(expected.client_id.to_uri());

    // Get the token claims, validating the above via jsonwebtoken
    let token = decode::<JwtClaims<T>>(token, key, &validation).map_err(jwt_error_mapping)?;
    let claims = token.claims;

    // custom validations
    claims
        .jwt_id
        .as_ref()
        .ok_or(RustyJwtError::MissingTokenClaim(Claim::Jti))?;
    let issued_at = claims.issued_at.ok_or(RustyJwtError::MissingTokenClaim(Claim::Iat))?;
    let now = jsonwebtoken::get_current_timestamp();
    if issued_at > now + expected.leeway as u64 {
        return Err(RustyJwtError::TokenIssuedInFuture);
    }
    let exp = claims.expires_at.ok_or(RustyJwtError::MissingTokenClaim(Claim::Exp))?;
    if exp > expected.max_expiration {
        return Err(RustyJwtError::TokenLivesTooLong);
    }

    let nonce = claims
        .nonce
        .as_deref()
        .ok_or(RustyJwtError::MissingTokenClaim(Claim::Nonce))?;
    if nonce != expected.backend_nonce.as_str() {
        return Err(RustyJwtError::DpopNonceMismatch);
    }

    Ok(claims)
}

/// Maps jsonwebtoken::errors::Error to RustyJwtError
fn jwt_error_mapping(e: Error) -> RustyJwtError {
    match e.into_kind() {
        ErrorKind::MissingRequiredClaim(claim) => Claim::from_name(&claim)
            .map(RustyJwtError::MissingTokenClaim)
            .unwrap_or_else(|| RustyJwtError::InvalidToken(format!("missing required claim '{claim}'"))),

        ErrorKind::InvalidSubject => RustyJwtError::TokenSubMismatch,

        ErrorKind::ExpiredSignature => RustyJwtError::TokenExpired,

        ErrorKind::ImmatureSignature => RustyJwtError::TokenNotYetValid,

        // DPoP claims failing because of serde
        ErrorKind::Json(error) => {
            let msg = error.to_string();

            msg.strip_prefix("missing field `")
                .and_then(|rest| rest.split_once('`'))
                .and_then(|(field, _)| Claim::from_name(field))
                .map(RustyJwtError::MissingTokenClaim)
                .unwrap_or(RustyJwtError::InvalidToken(msg))
        }
        other => RustyJwtError::InvalidToken(format!("{other:?}")),
    }
}
