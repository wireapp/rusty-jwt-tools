use jwt_simple::prelude::Jwk;
use rusty_jwt_tools::jwk_thumbprint::JwkThumbprint;
use rusty_jwt_tools::prelude::*;
use std::path::PathBuf;

pub fn jwk_thumbprint(alg: JwsAlgorithm, jwk: &Jwk) -> (String, HashAlgorithm) {
    let hash_alg = HashAlgorithm::from(alg);
    let kid = JwkThumbprint::generate(jwk, hash_alg).unwrap().kid;
    (kid, hash_alg)
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
            panic!("File {f:?} does not exist")
        }
    })
}
