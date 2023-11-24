use base64::Engine;
use jwt_simple::prelude::*;
use rand::random;

use rusty_jwt_tools::prelude::*;

#[test]
fn e2e_jwt() {
    let mut results = vec![];

    for (alg, key, backend_keys, hash_alg) in keys() {
        println!("# {alg:?} - {hash_alg:?}");

        let nonce: BackendNonce = rand_base64_str(32).into(); // generated by wire-server
        let challenge: AcmeNonce = rand_base64_str(32).to_string().into(); // generated by ACME server
        let user = uuid::Uuid::new_v4().to_string();
        let cid = random::<u64>();
        let (domain, team, handle) = ("wire.com", "wire", "beltram_wire");
        let alice = ClientId::try_new(&user, cid, domain).unwrap();
        let htu: Htu = format!("https://wire.example.com/clients/{cid}/access-token")
            .as_str()
            .try_into()
            .unwrap();
        let htm = Htm::Post;
        let leeway: u16 = 5;
        let expiry = Duration::from_days(1).into();
        let max_expiration: u64 = 2136351646; // somewhere in 2037
        let handle = Handle::from(handle).to_qualified(domain);
        let dpop = Dpop {
            htu: htu.clone(),
            htm,
            challenge: challenge.clone(),
            handle: handle.clone(),
            team: team.into(),
            extra_claims: None,
        };

        // Wire app generates a DPoP JWT token
        let client_dpop = RustyJwtTools::generate_dpop_token(dpop, &alice, nonce.clone(), expiry, alg, &key).unwrap();

        println!(
            "1. generate dpop:\nclient signature key:\n{key}\nDpop token:\nhttps://jwt.io/#id_token={client_dpop}\n"
        );

        // wire-server now validates the 'client_dpop' and generates an access token
        let access_token = RustyJwtTools::generate_access_token(
            &client_dpop,
            &alice,
            handle.clone(),
            team.into(),
            nonce.clone(),
            htu.clone(),
            htm,
            leeway,
            max_expiration,
            backend_keys.clone(),
            hash_alg,
            5,
            core::time::Duration::from_secs(360),
        )
        .unwrap();

        println!("2. generate access token:\nwire-server signature key:\n{backend_keys}\naccess token:\nhttps://jwt.io/#id_token={access_token}\n");

        // now acme server will verify the access token
        let backend_pk: Pem = match alg {
            JwsAlgorithm::P256 => ES256KeyPair::from_pem(backend_keys.as_str())
                .unwrap()
                .public_key()
                .to_pem()
                .unwrap(),
            JwsAlgorithm::P384 => ES384KeyPair::from_pem(backend_keys.as_str())
                .unwrap()
                .public_key()
                .to_pem()
                .unwrap(),
            JwsAlgorithm::Ed25519 => Ed25519KeyPair::from_pem(backend_keys.as_str())
                .unwrap()
                .public_key()
                .to_pem(),
        }
        .into();
        let dpop_header = Token::decode_metadata(&client_dpop).unwrap();
        let dpop_jwk = dpop_header.public_key().unwrap();
        let kid = JwkThumbprint::generate(dpop_jwk, hash_alg).unwrap().kid;
        let verify = RustyJwtTools::verify_access_token(
            &access_token,
            &alice,
            &handle,
            challenge,
            leeway,
            max_expiration,
            htu.clone(),
            backend_pk.clone(),
            kid,
            hash_alg,
            5,
        );
        println!("3. verify access token\nwire-server public signature key:\n{backend_pk}");
        if verify.is_ok() {
            println!("✅ access token verified");
            results.push(verify);
        } else {
            panic!("❌ access token invalid because {:?}", verify.unwrap_err());
        }
        println!("---------------------------------------------------------------------\n");
    }
    assert!(results.into_iter().all(|v| v.is_ok()));
}

fn keys() -> Vec<(JwsAlgorithm, Pem, Pem, HashAlgorithm)> {
    vec![
        (
            JwsAlgorithm::Ed25519,
            Ed25519KeyPair::generate().to_pem().into(),
            Ed25519KeyPair::generate().to_pem().into(),
            HashAlgorithm::SHA256,
        ),
        (
            JwsAlgorithm::P256,
            ES256KeyPair::generate().to_pem().unwrap().into(),
            ES256KeyPair::generate().to_pem().unwrap().into(),
            HashAlgorithm::SHA256,
        ),
        (
            JwsAlgorithm::P384,
            ES384KeyPair::generate().to_pem().unwrap().into(),
            ES384KeyPair::generate().to_pem().unwrap().into(),
            HashAlgorithm::SHA384,
        ),
    ]
}

pub fn rand_base64_str(size: usize) -> String {
    use rand::distributions::{Alphanumeric, DistString};
    let challenge: String = Alphanumeric.sample_string(&mut rand::thread_rng(), size);
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(challenge)
}
