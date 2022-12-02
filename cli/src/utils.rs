use jwt_simple::prelude::Jwk;
use rusty_jwt_tools::jwk_thumbprint::JwkThumbprint;
use rusty_jwt_tools::prelude::*;
use std::path::PathBuf;

pub fn jwk_thumbprint(alg: JwsAlgorithm, jwk: &Jwk) -> (String, HashAlgorithm) {
    let hash_alg = into_hash_alg(alg);
    let kid = JwkThumbprint::generate(jwk, hash_alg).unwrap().kid;
    (kid, hash_alg)
}

fn into_hash_alg(alg: JwsAlgorithm) -> HashAlgorithm {
    match alg {
        JwsAlgorithm::Ed25519 | JwsAlgorithm::P256 => HashAlgorithm::SHA256,
        JwsAlgorithm::P384 => HashAlgorithm::SHA384,
    }
}

pub fn read_stdin() -> String {
    use std::io::BufRead as _;

    let stdin = std::io::stdin();
    let mut result = vec![];
    for line in stdin.lock().lines() {
        let line = line.expect("Could not read line from standard in");
        result.push(line);
    }
    result.join("")
}

pub fn read_file(file: Option<&PathBuf>) -> Option<String> {
    file.map(|f| {
        if f.exists() {
            std::fs::read_to_string(f).unwrap()
        } else {
            panic!("File {:?} does not exist", f)
        }
    })
}
