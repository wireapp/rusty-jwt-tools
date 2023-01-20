use jwt_simple::prelude::*;
use serde::de::DeserializeOwned;

use crate::jwk::TryFromJwk;
use crate::prelude::*;

/// Abstraction over a public cryptographic key to upcast it in order to ease and factorize its usage with `jwt_simple`
#[derive(Debug, Clone)]
pub struct AnyPublicKey<'a>(JwsAlgorithm, Option<&'a Jwk>, Option<&'a Pem>);

impl AnyPublicKey<'_> {
    fn try_into_pem(&self) -> RustyJwtResult<Pem> {
        if let Some(jwk) = self.1 {
            return Ok(match self.0 {
                JwsAlgorithm::P256 => ES256PublicKey::try_from_jwk(jwk)?.to_pem()?.into(),
                JwsAlgorithm::P384 => ES384PublicKey::try_from_jwk(jwk)?.to_pem()?.into(),
                JwsAlgorithm::Ed25519 => Ed25519PublicKey::try_from_jwk(jwk)?.to_pem().into(),
            });
        }
        self.2.cloned().ok_or(RustyJwtError::ImplementationError)
    }
}

impl<'a> From<(JwsAlgorithm, &'a Jwk)> for AnyPublicKey<'a> {
    fn from((alg, jwk): (JwsAlgorithm, &'a Jwk)) -> Self {
        Self(alg, Some(jwk), None)
    }
}

impl<'a> From<(JwsAlgorithm, &'a Pem)> for AnyPublicKey<'a> {
    fn from((alg, pk): (JwsAlgorithm, &'a Pem)) -> Self {
        Self(alg, None, Some(pk))
    }
}

impl PartialEq for AnyPublicKey<'_> {
    fn eq(&self, other: &Self) -> bool {
        if let Some((this, other)) = self.try_into_pem().ok().zip(other.try_into_pem().ok()) {
            return this.as_str().trim() == other.as_str().trim();
        }
        false
    }
}

impl AnyPublicKey<'_> {
    /// Depending on the key elements, delegates to the right key constructor and verify the supplied token
    pub fn verify_token<T>(
        &self,
        token: &str,
        options: Option<VerificationOptions>,
    ) -> Result<JWTClaims<T>, jwt_simple::Error>
    where
        T: Serialize + DeserializeOwned,
    {
        let Self(alg, jwk, pk) = self;
        if let Some(jwk) = jwk {
            match alg {
                JwsAlgorithm::P256 => ES256PublicKey::try_from_jwk(jwk)?.verify_token::<T>(token, options),
                JwsAlgorithm::P384 => ES384PublicKey::try_from_jwk(jwk)?.verify_token::<T>(token, options),
                JwsAlgorithm::Ed25519 => Ed25519PublicKey::try_from_jwk(jwk)?.verify_token::<T>(token, options),
            }
        } else if let Some(pk) = pk {
            match alg {
                JwsAlgorithm::P256 => ES256PublicKey::from_pem(pk)?.verify_token::<T>(token, options),
                JwsAlgorithm::P384 => ES384PublicKey::from_pem(pk)?.verify_token::<T>(token, options),
                JwsAlgorithm::Ed25519 => Ed25519PublicKey::from_pem(pk)?.verify_token::<T>(token, options),
            }
        } else {
            Err(jwt_simple::Error::msg("Implementation error"))
        }
    }
}
