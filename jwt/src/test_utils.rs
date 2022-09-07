use std::str::FromStr;

use elliptic_curve::PublicKey;
use jwt_simple::prelude::*;
pub use rstest::*;
pub use rstest_reuse::{self, *};

use crate::dpop::Dpop;
use crate::{jwk::RustyJwk, JwsAlgorithm};

#[template]
#[export]
#[rstest(
    keys,
    case::Ed25519(crate::test_utils::JwtKeys::new_ed_keys()),
    case::P256(crate::test_utils::JwtKeys::new_ec_keys(JwsAlgorithm::P256))
)]
#[allow(non_snake_case)]
pub fn all_keys(keys: JwtKeys) {}

pub struct JwtKeys {
    pub sk_pem: String,
    pub pk_pem: String,
    pub alg: JwsAlgorithm,
}

impl JwtKeys {
    pub fn new_ed_keys() -> Self {
        let kp = ed25519_compact::KeyPair::generate();
        let sk_pem = kp.sk.to_pem();
        let pk_pem = kp.pk.to_pem();
        let pk = pk_pem.clone();
        Self {
            sk_pem,
            pk_pem,
            alg: JwsAlgorithm::Ed25519,
        }
    }

    pub fn new_ec_keys(alg: JwsAlgorithm) -> Self {
        let kp = ES256KeyPair::generate();
        let kp = kp.key_pair();
        let sk_pem = kp.to_pem().unwrap();
        let pk_pem = kp.public_key().to_pem().unwrap();
        Self { sk_pem, pk_pem, alg }
    }

    pub fn claims(&self, token: &str) -> JWTClaims<Dpop> {
        match self.alg {
            JwsAlgorithm::Ed25519 => {
                let pk = Ed25519PublicKey::from_pem(&self.pk_pem).unwrap();
                pk.verify_token::<Dpop>(&token, None).unwrap()
            }
            JwsAlgorithm::P256 => {
                let pk = ES256PublicKey::from_pem(&self.pk_pem).unwrap();
                pk.verify_token::<Dpop>(&token, None).unwrap()
            }
        }
    }
}

impl RustyJwk {
    pub fn ed25519_jwk_to_kp(jwk: &Jwk) -> Ed25519PublicKey {
        match &jwk.algorithm {
            AlgorithmParameters::OctetKeyPair(p) => {
                let x = base64::decode_config(&p.x, base64::URL_SAFE_NO_PAD).unwrap();
                Ed25519PublicKey::from_bytes(&x).unwrap()
            }
            _ => unreachable!(),
        }
    }

    pub fn p256_jwk_to_kp(jwk: &Jwk) -> ES256PublicKey {
        let jwk = serde_json::to_string(jwk).unwrap();
        let jwk = elliptic_curve::JwkEcKey::from_str(&jwk).unwrap();
        let pk: PublicKey<p256::NistP256> = jwk.to_public_key().unwrap();
        use p256::pkcs8::EncodePublicKey as _;
        let der = pk.to_public_key_der().unwrap();
        let key = ES256PublicKey::from_der(der.as_bytes()).unwrap();
        key
    }

    pub fn rand_jwk(alg: JwsAlgorithm) -> Jwk {
        let pk = match alg {
            JwsAlgorithm::P256 => ES256KeyPair::generate().public_key().to_pem().unwrap(),
            JwsAlgorithm::Ed25519 => Ed25519KeyPair::generate().public_key().to_pem(),
        };
        RustyJwk::new_jwk(alg, pk).unwrap()
    }
}
