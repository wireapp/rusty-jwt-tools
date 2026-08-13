use jwt_simple::prelude::*;

use crate::{jwk::RustyJwk, prelude::*};

impl RustyJwk {
    pub fn rand_jwk(alg: JwsAlgorithm) -> Jwk {
        use crate::jwk::TryIntoJwk as _;
        match alg {
            JwsAlgorithm::ES256 => ES256KeyPair::generate().public_key().try_into_jwk().unwrap(),
            JwsAlgorithm::ES384 => ES384KeyPair::generate().public_key().try_into_jwk().unwrap(),
            JwsAlgorithm::ES512 => ES512KeyPair::generate().public_key().try_into_jwk().unwrap(),
            JwsAlgorithm::EdDSA => Ed25519KeyPair::generate().public_key().try_into_jwk().unwrap(),
        }
    }
}
