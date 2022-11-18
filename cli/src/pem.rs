use jwt_simple::prelude::*;
use rusty_jwt_tools::prelude::*;

pub fn parse_pem(pem: String) -> (JwsAlgorithm, Pem) {
    let alg = if Ed25519KeyPair::from_pem(&pem).is_ok() {
        JwsAlgorithm::Ed25519
    } else if ES256KeyPair::from_pem(&pem).is_ok() {
        JwsAlgorithm::P256
    } else if ES384KeyPair::from_pem(&pem).is_ok() {
        JwsAlgorithm::P384
    } else {
        panic!("PEM key did not match any known format")
    };
    (alg, pem.into())
}
