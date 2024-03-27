use crate::{pem::*, utils::*};
use anyhow::anyhow;
use clap::Parser;
use jwt_simple::prelude::*;
use rusty_jwt_tools::prelude::*;
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct AccessGenerate {
    /// path to file with wire-server's signature public key in PEM format
    #[arg(short = 'k', long)]
    key: PathBuf,
    /// base64Url encoded challenge (nonce) generated by acme server
    ///
    /// e.g. 'okAJ33Ym/XS2qmmhhh7aWSbBlYy4Ttm1EysqW8I/9ng'
    #[arg(short = 'c', long)]
    challenge: String,
    /// base64Url encoded nonce generated by wire-server
    ///
    /// e.g. 'WE88EvOBzbqGerznM+2P/AadVf7374y0cH19sDSZA2A'
    #[arg(long)]
    nonce: String,
    /// wire-server uri this token will be fetched from
    ///
    /// e.g. 'https://wire.example.com/clients/token'
    #[arg(long)]
    htu: String,
    /// qualified wire client id
    ///
    /// e.g. 'wireapp://lJGYPz0ZRq2kvc_XpdaDlA!7b52de7af952ba14@wire.com'
    #[arg(short = 'i', long)]
    client_id: String,
    /// Wire handle
    ///
    /// e.g. 'beltram_wire'
    #[arg(long)]
    handle: String,
    /// Wire Display Name
    ///
    /// e.g. 'Beltram Maldant'
    #[arg(long)]
    display_name: String,
    /// Wire team the user belongs to
    ///
    /// e.g. 'wire'
    #[arg(short = 't', long)]
    team: Option<String>,
    /// client dpop & access token expiration in seconds
    ///
    /// e.g. '300' for 5 minutes
    #[arg(short = 'e', long)]
    expiry: u64,
    /// version of wire-server http API
    ///
    /// e.g. '5' (current default)
    #[arg(long, default_value = "5")]
    api_version: u32,
}

impl AccessGenerate {
    pub fn execute(self) -> anyhow::Result<()> {
        let (alg, backend_pk) = parse_key_pair_pem(read_file(Some(&self.key)).unwrap());

        let client_kp = match alg {
            JwsAlgorithm::P256 => ES256KeyPair::generate().to_pem().unwrap().into(),
            JwsAlgorithm::P384 => ES384KeyPair::generate().to_pem().unwrap().into(),
            JwsAlgorithm::P521 => return Err(anyhow!("P521 not supported")),
            JwsAlgorithm::Ed25519 => Ed25519KeyPair::generate().to_pem().into(),
        };

        let challenge: AcmeNonce = self.challenge.into();
        let htm = Htm::Post;
        let htu: Htu = self.htu.as_str().try_into().unwrap();
        let client_id = ClientId::try_from_uri(&self.client_id).expect("Invalid 'client_id'");
        let handle = Handle::from(self.handle.clone())
            .try_to_qualified(&client_id.domain)
            .unwrap();

        let dpop = Dpop {
            challenge,
            htm,
            display_name: self.display_name.clone(),
            htu: htu.clone(),
            handle: handle.clone(),
            team: self.team.clone().into(),
            extra_claims: None,
        };
        let nonce: BackendNonce = self.nonce.into();
        let expiry = core::time::Duration::from_secs(self.expiry);
        let audience = "https://stepca:32902/acme/wire/challenge/I16phsvAPGbruDHr5Bh6akQVPKP6OO5v/dF2LHNmGI20R8rzzcgnrCSv789XcFEyL".parse().unwrap();

        let client_dpop_token =
            RustyJwtTools::generate_dpop_token(dpop, &client_id, nonce.clone(), audience, expiry, alg, &client_kp)
                .expect("Failed generating client Dpop token");

        let leeway: u16 = 5;
        let max_expiration: u64 = 2136351646; // somewhere in 2037
        let hash_alg = HashAlgorithm::from(alg);

        let access_token = RustyJwtTools::generate_access_token(
            &client_dpop_token,
            &client_id,
            handle,
            &self.display_name,
            self.team.into(),
            nonce,
            htu,
            htm,
            leeway,
            max_expiration,
            backend_pk,
            hash_alg,
            self.api_version,
            core::time::Duration::from_secs(360),
        )
        .unwrap();

        println!("{access_token}");

        Ok(())
    }
}
