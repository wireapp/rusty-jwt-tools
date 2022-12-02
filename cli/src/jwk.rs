use crate::{pem::parse_key_pair_pem, utils::*};
use clap::Parser;
use console::style;
use jwt_simple::prelude::*;
use rusty_jwt_tools::{jwk::TryIntoJwk, prelude::*};
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct ParseJwk {
    /// key in PEM format
    key: Option<PathBuf>,
}

impl ParseJwk {
    pub fn execute(self) -> anyhow::Result<()> {
        let key = read_file(self.key.as_ref())
            .unwrap_or_else(read_stdin)
            .trim()
            .to_string();
        let (alg, pem) = parse_key_pair_pem(key);

        let jwk = match alg {
            JwsAlgorithm::P256 => {
                let kp = ES256KeyPair::from_pem(pem.as_str()).expect("Invalid PEM");
                kp.public_key().try_into_jwk().unwrap()
            }
            JwsAlgorithm::P384 => {
                let kp = ES384KeyPair::from_pem(pem.as_str()).expect("Invalid PEM");
                kp.public_key().try_into_jwk().unwrap()
            }
            JwsAlgorithm::Ed25519 => {
                let kp = Ed25519KeyPair::from_pem(pem.as_str()).expect("Invalid PEM");
                kp.public_key().try_into_jwk().unwrap()
            }
        };
        let json_jwk = serde_json::to_string_pretty(&jwk).unwrap();
        println!("- JWK: \n{}", style(&json_jwk).cyan());

        let (jwk_thumbprint, hash_alg) = jwk_thumbprint(alg, &jwk);
        // JWK thumbprint of a private key is the same as its corresponding public key https://www.rfc-editor.org/rfc/rfc7638.html#section-3.2.1
        println!("- JWK thumbprint with {} : {}", hash_alg, style(&jwk_thumbprint).cyan());

        Ok(())
    }
}
