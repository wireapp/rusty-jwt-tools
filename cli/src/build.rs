use crate::{pem::parse_key_pair_pem, utils::*};
use clap::Parser;
use jwt_simple::prelude::*;
use rusty_jwt_tools::prelude::*;
use serde_json::Value;
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct BuildJwt {
    /// path to file with json claims
    claims: Option<PathBuf>,
    /// path to file with signature key in PEM format
    #[arg(short = 'k', long)]
    key: PathBuf,
    /// path to file with Verifiable Presentation.
    #[arg(short = 'p', long)]
    vp: Option<PathBuf>,
    /// path to file with Verifiable Credentials. Appended to presentation
    #[arg(short = 'c', long)]
    vc: Vec<PathBuf>,
    /// expiration in days
    #[arg(short = 'e', long, default_value_t = 90)]
    expires: u64,
}

impl BuildJwt {
    pub fn execute(self) -> anyhow::Result<()> {
        let (alg, kp) = parse_key_pair_pem(read_file(Some(&self.key)).unwrap());

        let header = JWTHeader {
            algorithm: alg.to_string(),
            ..Default::default()
        };

        let mut json_claims = self.get_json_claims();

        if let Some(vp) = self.get_vp() {
            let vp = serde_json::to_value(vp).unwrap();
            json_claims.as_object_mut().unwrap().insert("vp".to_string(), vp);
        }

        let expires = Duration::from_days(self.expires);
        let claims = Claims::with_custom_claims(json_claims, expires);

        let jwt = RustyJwtTools::generate_jwt(alg, header, Some(claims), &kp, true).unwrap();

        println!("{}", jwt);
        Ok(())
    }

    fn get_json_claims(&self) -> Value {
        let claims = read_file(self.claims.as_ref()).unwrap_or_else(read_stdin);
        serde_json::from_str::<Value>(&claims).unwrap()
    }

    fn get_vp(&self) -> Option<RustyPresentation> {
        read_file(self.vp.as_ref())
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
                .map(|path| read_file(Some(path)).unwrap())
                .map(|c| serde_json::from_str(&c).expect("Invalid Verifiable Credential"))
                .collect()
        } else {
            vec![]
        }
    }
}
