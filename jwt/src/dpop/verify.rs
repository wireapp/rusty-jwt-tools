use jwt_simple::prelude::*;

use crate::jwt::{Verify, VerifyJwt, VerifyJwtHeader};
use crate::prelude::*;

/// Verifies DPoP token specific header
pub(crate) trait VerifyDpopTokenHeader {
    /// Verifies the header
    fn verify_dpop_header(&self) -> RustyJwtResult<(JwsAlgorithm, &Jwk)>;
}

impl VerifyDpopTokenHeader for TokenMetadata {
    fn verify_dpop_header(&self) -> RustyJwtResult<(JwsAlgorithm, &Jwk)> {
        let typ = self.signature_type().ok_or(RustyJwtError::MissingDpopHeader("typ"))?;
        if typ != Dpop::TYP {
            return Err(RustyJwtError::InvalidDpopTyp);
        }
        let alg = self.verify_jwt_header()?;
        let jwk = self.public_key().ok_or(RustyJwtError::MissingDpopHeader("jwk"))?;
        Ok((alg, jwk))
    }
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
    ) -> RustyJwtResult<JWTClaims<Dpop>>;
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
    ) -> RustyJwtResult<JWTClaims<Dpop>> {
        let pk = AnyPublicKey::from((alg, jwk));
        let verify = Verify {
            client_id,
            backend_nonce: Some(backend_nonce),
            leeway,
            issuer: None,
        };

        let claims = (*self).verify_jwt::<Dpop>(&pk, max_expiration, verify)?;
        if let Some(expected_htm) = htm {
            if expected_htm != claims.custom.htm {
                return Err(RustyJwtError::DpopHtmMismatch);
            }
        }
        if htu != &claims.custom.htu {
            return Err(RustyJwtError::DpopHtuMismatch);
        }
        if let Some(chal) = challenge {
            if chal != &claims.custom.challenge {
                return Err(RustyJwtError::DpopChallengeMismatch);
            }
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
