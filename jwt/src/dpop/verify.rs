use jsonwebtoken::{
    DecodingKey, Header, Validation, decode, decode_header,
    errors::{Error, ErrorKind},
    jwk::{AlgorithmParameters, EllipticCurve, EllipticCurveKeyParameters, Jwk, OctetKeyPairParameters},
};

use crate::{jwt::JwtClaims, prelude::*};

/// What a DPoP proof must look like to pass [verify_dpop_proof]
#[derive(Debug, Clone)]
pub(crate) struct ExpectedDpop<'a> {
    /// The client the proof must belong to, i.e. the 'sub' claim must be its URI
    pub client_id: &'a ClientId,
    /// The 'nonce' claim must be equal to it
    pub backend_nonce: &'a BackendNonce,
    /// The maximum number of seconds of clock skew allowed when checking 'exp', 'nbf' and 'iat'
    pub leeway: u16,
    /// Largest acceptable 'exp' claim, in seconds since the UNIX epoch
    pub max_expiration: u64,
    /// The 'handle' claim must be equal to it
    pub handle: &'a QualifiedHandle,
    /// The 'name' claim must be equal to it
    pub display_name: &'a str,
    /// The 'team' claim must be equal to it
    pub team: &'a Team,
    /// The 'htm' claim must be equal to it
    pub htm: Htm,
    /// The 'htu' claim must be equal to it
    pub htu: &'a Htu,
}

/// Verifies the header, the signature and the claims of a DPoP proof
///
/// Returns the algorithm and the JWK of the proof's header, together with its claims.
pub(crate) fn verify_dpop_proof(
    proof: &str,
    expected: ExpectedDpop,
) -> RustyJwtResult<(JwsAlgorithm, Jwk, JwtClaims<Dpop>)> {
    let (alg, jwk) = verify_header(decode_header(proof)?)?;
    let pk = DecodingKey::from_jwk(&jwk).map_err(|e| RustyJwtError::InvalidToken(e.to_string()))?;
    let claims = verify_claims(proof, alg, &pk, &expected)?;

    if expected.htm != claims.custom.htm {
        return Err(RustyJwtError::DpopHtmMismatch);
    }
    if expected.htu != &claims.custom.htu {
        return Err(RustyJwtError::DpopHtuMismatch);
    }
    if expected.handle != &claims.custom.handle {
        return Err(RustyJwtError::DpopHandleMismatch);
    }
    if expected.team != &claims.custom.team {
        return Err(RustyJwtError::DpopTeamMismatch);
    }
    if expected.display_name != claims.custom.display_name {
        return Err(RustyJwtError::DpopDisplayNameMismatch);
    }
    Ok((alg, jwk, claims))
}

/// Verifies the DPoP specific header fields and returns the algorithm and the JWK
fn verify_header(header: Header) -> RustyJwtResult<(JwsAlgorithm, Jwk)> {
    let typ = header.typ.ok_or(RustyJwtError::MissingTokenHeader("typ"))?;
    if typ != Dpop::TYP {
        return Err(RustyJwtError::InvalidTokenTyp(Dpop::TYP));
    }
    let alg = JwsAlgorithm::try_from(header.alg)?;
    let jwk = header.jwk.ok_or(RustyJwtError::MissingTokenHeader("jwk"))?;
    if !jwk_matches_alg(&jwk, alg) {
        return Err(RustyJwtError::InvalidJwk);
    }
    Ok((alg, jwk))
}

/// Verifies the signature of a DPoP proof and its 'sub', 'exp', 'nbf', 'iat', 'jti' and 'nonce' claims
fn verify_claims(
    proof: &str,
    alg: JwsAlgorithm,
    key: &DecodingKey,
    expected: &ExpectedDpop,
) -> RustyJwtResult<JwtClaims<Dpop>> {
    let mut validation = Validation::new(alg.into());
    validation.set_required_spec_claims(&["exp", "sub", "nbf"]);
    validation.validate_aud = false;
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = expected.leeway.into();
    validation.sub = Some(expected.client_id.to_uri());

    // verifies the signature and the claims configured above
    let claims = decode::<JwtClaims<Dpop>>(proof, key, &validation)
        .map_err(jwt_error_mapping)?
        .claims;

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

/// Whether the JWK's key type and curve are the ones expected by `alg`
fn jwk_matches_alg(jwk: &Jwk, alg: JwsAlgorithm) -> bool {
    matches!(
        (alg, &jwk.algorithm),
        (
            JwsAlgorithm::ES256,
            AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                curve: EllipticCurve::P256,
                ..
            })
        ) | (
            JwsAlgorithm::ES384,
            AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                curve: EllipticCurve::P384,
                ..
            })
        ) | (
            JwsAlgorithm::ES512,
            AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                curve: EllipticCurve::P521,
                ..
            })
        ) | (
            JwsAlgorithm::EdDSA,
            AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                curve: EllipticCurve::Ed25519,
                ..
            })
        )
    )
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
