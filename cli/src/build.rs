use crate::pem::parse_pem;
use clap::Parser;
use jwt_simple::prelude::*;
use rusty_jwt_tools::prelude::*;
use serde_json::Value;
use std::{fs, path::PathBuf};

#[derive(Debug, Parser)]
pub struct BuildJwt {
    /// JSON claims
    claims: Option<PathBuf>,
    /// Signature key in PEM format
    #[arg(short = 'k', long)]
    key: PathBuf,
    /// Verifiable Presentation.
    #[arg(short = 'p', long)]
    vp: Option<PathBuf>,
    /// List of Verifiable Credentials
    #[arg(short = 'c', long)]
    vc: Vec<PathBuf>,
}

impl BuildJwt {
    pub fn execute(self) -> anyhow::Result<()> {
        let (alg, kp) = self.get_key();

        let mut header = JWTHeader::default();
        header.algorithm = alg.to_string();

        let mut json_claims = self.get_json_claims();

        if let Some(vp) = self.get_vp() {
            let vp = serde_json::to_value(vp).unwrap();
            json_claims.as_object_mut().unwrap().insert("vp".to_string(), vp);
        }

        let duration = Duration::from_days(90);
        let claims = Claims::with_custom_claims(json_claims, duration);

        let jwt = RustyJwtTools::generate_jwt(alg, header, claims, kp).unwrap();

        // println!("https://jwt.io/#id_token={jwt}\n");
        println!("{}", jwt);
        Ok(())
    }

    fn get_json_claims(&self) -> Value {
        let claims = if let Some(claims) = self.claims.as_ref() {
            if claims.exists() {
                fs::read_to_string(claims).unwrap()
            } else {
                panic!("Claims file does not exist")
            }
        } else {
            use std::io::BufRead as _;

            let stdin = std::io::stdin();
            let mut claims = vec![];
            for line in stdin.lock().lines() {
                let line = line.expect("Could not read line from standard in");
                claims.push(line);
            }
            claims.join("")
        };
        serde_json::from_str::<Value>(&claims).unwrap()
    }

    fn get_key(&self) -> (JwsAlgorithm, Pem) {
        let key = if self.key.exists() {
            fs::read_to_string(self.key.clone()).unwrap()
        } else {
            panic!("Key file does not exist")
        };
        parse_pem(key)
    }

    fn get_vp(&self) -> Option<RustyPresentation> {
        self.vp
            .as_ref()
            .map(|path| {
                if path.exists() {
                    fs::read_to_string(path).unwrap()
                } else {
                    panic!("Verifiable presentation file does not exist")
                }
            })
            .map(|p| serde_json::from_str::<RustyPresentation>(&p).expect("Invalid Verifiable Presentation"))
            .map(|mut p| {
                if !self.get_vc().is_empty() {
                    p.verifiable_credential = self.get_vc().into()
                }
                p
            })
    }

    fn get_vc(&self) -> Vec<RustyCredential> {
        if !self.vc.is_empty() {
            self.vc
                .iter()
                .map(|path| {
                    if path.exists() {
                        fs::read_to_string(path).unwrap()
                    } else {
                        panic!("Verifiable credential file does not exist")
                    }
                })
                .map(|c| serde_json::from_str(&c).expect("Invalid Verifiable Credential"))
                .collect()
        } else {
            vec![]
        }
    }
}
