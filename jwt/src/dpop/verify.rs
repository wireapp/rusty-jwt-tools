use jsonwebtoken::{
    DecodingKey, Header,
    jwk::{AlgorithmParameters, EllipticCurve, EllipticCurveKeyParameters, Jwk, OctetKeyPairParameters},
};

use crate::{
    jwt::{JwtClaims, Verify, VerifyJwt},
    prelude::*,
};

/// Verifies DPoP token specific header
pub(crate) trait VerifyDpopTokenHeader {
    /// Verifies the header
    fn verify_dpop_header(self) -> RustyJwtResult<(JwsAlgorithm, Jwk)>;
}

impl VerifyDpopTokenHeader for Header {
    fn verify_dpop_header(self) -> RustyJwtResult<(JwsAlgorithm, Jwk)> {
        let typ = self.typ.ok_or(RustyJwtError::MissingDpopHeader("typ"))?;
        if typ != Dpop::TYP {
            return Err(RustyJwtError::InvalidDpopTyp);
        }
        let alg = JwsAlgorithm::try_from(self.alg)?;
        let jwk = self.jwk.ok_or(RustyJwtError::MissingDpopHeader("jwk"))?;
        if !jwk_matches_alg(&jwk, alg) {
            return Err(RustyJwtError::InvalidDpopJwk);
        }
        Ok((alg, jwk))
    }
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

/// Verifies DPoP token specific claims
pub(crate) trait VerifyDpop {
    /// Verifies the claims
    ///
    /// # Arguments
    /// * `htm` - method
    /// * `uri` - uri
    #[allow(clippy::too_many_arguments)]
    fn verify_client_dpop(
        &self,
        alg: JwsAlgorithm,
        jwk: &Jwk,
        client_id: &ClientId,
        handle: &QualifiedHandle,
        display_name: &str,
        team: &Team,
        backend_nonce: &BackendNonce,
        challenge: Option<&AcmeNonce>,
        htm: Option<Htm>,
        htu: &Htu,
        max_expiration: u64,
        leeway: u16,
    ) -> RustyJwtResult<JwtClaims<Dpop>>;
}

impl VerifyDpop for &str {
    fn verify_client_dpop(
        &self,
        alg: JwsAlgorithm,
        jwk: &Jwk,
        client_id: &ClientId,
        handle: &QualifiedHandle,
        display_name: &str,
        team: &Team,
        backend_nonce: &BackendNonce,
        challenge: Option<&AcmeNonce>,
        htm: Option<Htm>,
        htu: &Htu,
        max_expiration: u64,
        leeway: u16,
    ) -> RustyJwtResult<JwtClaims<Dpop>> {
        let pk = DecodingKey::from_jwk(jwk).map_err(|e| RustyJwtError::InvalidToken(e.to_string()))?;
        let verify = Verify {
            client_id,
            backend_nonce: Some(backend_nonce),
            leeway,
            issuer: None,
        };

        // also verifies the nonce
        let claims = (*self).verify_jwt::<Dpop>(alg, &pk, max_expiration, verify)?;

        if let Some(expected_htm) = htm
            && expected_htm != claims.custom.htm
        {
            return Err(RustyJwtError::DpopHtmMismatch);
        }
        if htu != &claims.custom.htu {
            return Err(RustyJwtError::DpopHtuMismatch);
        }
        if let Some(chal) = challenge
            && chal != &claims.custom.challenge
        {
            return Err(RustyJwtError::DpopChallengeMismatch);
        }
        if &claims.custom.handle != handle {
            return Err(RustyJwtError::DpopHandleMismatch);
        }
        if team != &claims.custom.team {
            return Err(RustyJwtError::DpopTeamMismatch);
        }
        if display_name != claims.custom.display_name {
            return Err(RustyJwtError::DpopDisplayNameMismatch);
        }
        Ok(claims)
    }
}
