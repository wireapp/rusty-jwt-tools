use jwt_simple::prelude::*;

use crate::{jwk::RustyJwk, prelude::*};

impl RustyJwk {
    pub fn rand_jwk(alg: JwsAlgorithm) -> Jwk {
        use crate::jwk::TryIntoJwk as _;
        match alg {
            JwsAlgorithm::P256 => ES256KeyPair::generate().public_key().try_into_jwk().unwrap(),
            JwsAlgorithm::P384 => ES384KeyPair::generate().public_key().try_into_jwk().unwrap(),
            JwsAlgorithm::P521 => ES512KeyPair::generate().public_key().try_into_jwk().unwrap(),
            JwsAlgorithm::Ed25519 => Ed25519KeyPair::generate().public_key().try_into_jwk().unwrap(),
        }
    }
}
