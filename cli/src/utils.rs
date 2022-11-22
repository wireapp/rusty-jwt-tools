use jwt_simple::prelude::Jwk;
use rusty_jwt_tools::jkt::JktConfirmation;
use rusty_jwt_tools::prelude::*;

pub fn jwk_thumbprint(alg: JwsAlgorithm, jwk: &Jwk) -> (String, HashAlgorithm) {
    let hash_alg = into_hash_alg(alg);
    let jkt = JktConfirmation::generate(jwk, hash_alg).unwrap().jkt;
    (jkt, hash_alg)
}

fn into_hash_alg(alg: JwsAlgorithm) -> HashAlgorithm {
    match alg {
        JwsAlgorithm::Ed25519 | JwsAlgorithm::P256 => HashAlgorithm::SHA256,
        JwsAlgorithm::P384 => HashAlgorithm::SHA384,
    }
}
