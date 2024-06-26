//! Everything related to JWK

use base64::Engine;
use jwt_simple::prelude::*;

use crate::prelude::*;

mod ecdsa;
mod eddsa;
pub(crate) mod json;
#[cfg(feature = "rsa")]
mod rsa;

/// From json to JWK
pub trait TryIntoJwk {
    /// str -> JWK
    fn try_into_jwk(self) -> RustyJwtResult<Jwk>;
}

/// From JWK to json
pub trait TryFromJwk
where
    Self: Sized,
{
    /// JWK -> str
    fn try_from_jwk(jwk: &Jwk) -> RustyJwtResult<Self>;
}

/// JWK utilities
pub struct RustyJwk;

impl RustyJwk {
    #[inline]
    fn base64_url_encode(i: impl AsRef<[u8]>) -> String {
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(i)
    }

    #[inline]
    fn base64_url_decode(i: impl AsRef<[u8]>) -> RustyJwtResult<Vec<u8>> {
        Ok(base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(i)?)
    }
}

#[cfg(feature = "test-utils")]
/// Generates a json serialized JWK for testing purposes
pub fn generate_jwk(alg: JwsAlgorithm) -> Vec<u8> {
    let jwk = match alg {
        JwsAlgorithm::P256 => ES256KeyPair::generate().public_key().try_into_jwk().unwrap(),
        JwsAlgorithm::P384 => ES384KeyPair::generate().public_key().try_into_jwk().unwrap(),
        JwsAlgorithm::P521 => ES512KeyPair::generate().public_key().try_into_jwk().unwrap(),
        JwsAlgorithm::Ed25519 => Ed25519KeyPair::generate().public_key().try_into_jwk().unwrap(),
    };
    serde_json::to_vec(&jwk).unwrap()
}
