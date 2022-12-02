use crate::utils::*;
use clap::Parser;
use console::style;
use jwt_simple::prelude::*;
use rusty_jwt_tools::jwk_thumbprint::JwkThumbprint;
use rusty_jwt_tools::prelude::*;
use serde_json::Value;
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct ParseJwt {
    /// JSON claims
    jwt: Option<PathBuf>,
}

impl ParseJwt {
    pub fn execute(self) -> anyhow::Result<()> {
        let jwt = read_file(self.jwt.as_ref())
            .unwrap_or_else(read_stdin)
            .trim()
            .to_string();

        let metadata = Token::decode_metadata(&jwt).unwrap();

        // ------ Header ------

        println!("{}", style("\n--- Header ---").cyan());
        let alg: JwsAlgorithm = metadata.algorithm().try_into().expect("Unsupported algorithm");
        println!("- alg: {}", style(alg.to_string()).cyan());
        println!("- typ: {}", style(metadata.signature_type().unwrap()).cyan());

        let jwk = metadata.public_key().unwrap();
        let json_jwk = serde_json::to_string_pretty(jwk).unwrap();
        println!("- JWK: \n{}", style(&json_jwk).cyan());
        let (jwk_thumbprint, hash_alg) = jwk_thumbprint(alg, jwk);
        println!("- JWK thumbprint with {} : {}", hash_alg, style(&jwk_thumbprint).cyan());

        // ------ Verify ------

        println!("{}", style("\n--- Verify Claims ---").green());
        let key: AnyPublicKey = (alg, jwk).into();

        key.verify_token::<Value>(&jwt, None).unwrap();
        println!("- {}: ✅ ", style("signature").green());

        let verif = VerificationOptions {
            accept_future: true,
            ..Default::default()
        };
        key.verify_token::<Value>(&jwt, Some(verif)).unwrap();
        println!("- {}: ✅ ", style("expires").green());

        let verif = VerificationOptions {
            accept_future: false,
            ..Default::default()
        };
        let claims = key.verify_token::<Value>(&jwt, Some(verif)).unwrap();
        println!("- {}: ✅ ", style("issued at").green());

        // JWK thumbprint
        let cnf = claims.custom.get("cnf");
        let kid = cnf.and_then(|c| serde_json::from_value::<JwkThumbprint>(c.clone()).ok());
        if let Some(kid) = kid {
            let expected_kid = JwkThumbprint::generate(jwk, hash_alg).unwrap();
            if kid == expected_kid {
                println!("- {}: ✅ ", style("JWK thumbprint").green());
            } else {
                println!("- {}: ❌ ", style("JWK thumbprint").green());
            }
        }

        // ------ Claims ------

        println!("{}", style("\n--- Claims ---").magenta());
        let mut claims = key.verify_token::<Value>(&jwt, None).unwrap();

        let vp = claims.custom.as_object_mut().and_then(|o| o.remove("vp"));
        if let Some(mut vp) = vp {
            let vcs = vp.as_object_mut().and_then(|o| o.remove("verifiableCredential"));
            if let Some(mut vcs) = vcs {
                let vcs = vcs.as_array_mut().expect("Invalid Verifiable Credentials");
                for (i, vc) in vcs.iter_mut().enumerate() {
                    let vc = serde_json::to_string_pretty(vc).unwrap();
                    println!("- Verifiable Credential {}: \n{}", i + 1, style(&vc).magenta());
                }
            }
            let vp = serde_json::to_string_pretty(&vp).unwrap();
            println!("- Verifiable Presentation \n{}", style(&vp).magenta());
        }

        let json_claims = serde_json::to_string_pretty(&claims).unwrap();
        println!("- rest of claims \n{}", style(&json_claims).magenta());

        Ok(())
    }
}
