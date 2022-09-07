use std::str::FromStr;

use elliptic_curve::PublicKey;
use jwt_simple::prelude::*;
pub use rstest::*;
pub use rstest_reuse::{self, *};

use crate::{
    alg::{JwsEcAlgorithm, JwsEdAlgorithm},
    dpop::Dpop,
    jwk::RustyJwk,
    prelude::*,
};

#[template]
#[export]
#[rstest(
    key,
    case::Ed25519($crate::test_utils::JwtKey::new_key(JwsAlgorithm::Ed25519)),
    case::P256($crate::test_utils::JwtKey::new_key(JwsAlgorithm::P256)),
    case::P384($crate::test_utils::JwtKey::new_key(JwsAlgorithm::P384))
)]
#[allow(non_snake_case)]
pub fn all_keys(key: JwtKey) {}

pub struct JwtKey {
    pub sk_pem: String,
    pub pk_pem: String,
    pub alg: JwsAlgorithm,
}

impl JwtKey {
    pub fn new_key(alg: JwsAlgorithm) -> Self {
        match alg {
            JwsAlgorithm::P256 | JwsAlgorithm::P384 => JwtEcKey::new_key(alg.try_into().unwrap()).into(),
            JwsAlgorithm::Ed25519 => JwtEdKey::new_key(alg.try_into().unwrap()).into(),
        }
    }

    pub fn claims(&self, token: &str) -> JWTClaims<Dpop> {
        match self.alg {
            JwsAlgorithm::P256 | JwsAlgorithm::P384 => JwtEcKey::from(self).claims(token),
            JwsAlgorithm::Ed25519 => JwtEdKey::from(self).claims(token),
        }
    }
}

/// --- Elliptic curves ---
#[template]
#[export]
#[rstest(
    key,
    case::P256($crate::test_utils::JwtEcKey::new_key($crate::alg::JwsEcAlgorithm::P256)),
    case::P384($crate::test_utils::JwtEcKey::new_key($crate::alg::JwsEcAlgorithm::P384))
)]
#[allow(non_snake_case)]
pub fn all_ec_keys(key: JwtEcKey) {}

pub struct JwtEcKey {
    pub sk_pem: String,
    pub pk_pem: String,
    pub alg: JwsEcAlgorithm,
}

impl From<JwtEcKey> for JwtKey {
    fn from(key: JwtEcKey) -> Self {
        Self {
            sk_pem: key.sk_pem,
            pk_pem: key.pk_pem,
            alg: key.alg.into(),
        }
    }
}

impl From<&JwtKey> for JwtEcKey {
    fn from(key: &JwtKey) -> Self {
        Self {
            sk_pem: key.sk_pem.clone(),
            pk_pem: key.pk_pem.clone(),
            alg: key.alg.try_into().unwrap(),
        }
    }
}

impl JwtEcKey {
    pub fn new_key(alg: JwsEcAlgorithm) -> Self {
        match alg {
            JwsEcAlgorithm::P256 => {
                let kp = ES256KeyPair::generate();
                let kp = kp.key_pair();
                let sk_pem = kp.to_pem().unwrap();
                let pk_pem = kp.public_key().to_pem().unwrap();
                Self { sk_pem, pk_pem, alg }
            }
            JwsEcAlgorithm::P384 => {
                let kp = ES384KeyPair::generate();
                let kp = kp.key_pair();
                let sk_pem = kp.to_pem().unwrap();
                let pk_pem = kp.public_key().to_pem().unwrap();
                Self { sk_pem, pk_pem, alg }
            }
        }
    }

    pub fn claims(&self, token: &str) -> JWTClaims<Dpop> {
        match self.alg {
            JwsEcAlgorithm::P256 => ES256PublicKey::from_pem(&self.pk_pem)
                .unwrap()
                .verify_token::<Dpop>(token, None)
                .unwrap(),
            JwsEcAlgorithm::P384 => ES384PublicKey::from_pem(&self.pk_pem)
                .unwrap()
                .verify_token::<Dpop>(token, None)
                .unwrap(),
        }
    }
}

/// --- Edward curves ---

#[template]
#[export]
#[rstest(
    key,
    case::Ed25519($crate::test_utils::JwtEdKey::new_key($crate::alg::JwsEdAlgorithm::Ed25519))
)]
#[allow(non_snake_case)]
pub fn all_ed_keys(key: JwtEdKey) {}

pub struct JwtEdKey {
    pub sk_pem: String,
    pub pk_pem: String,
    pub alg: JwsEdAlgorithm,
}

impl From<JwtEdKey> for JwtKey {
    fn from(key: JwtEdKey) -> Self {
        Self {
            sk_pem: key.sk_pem,
            pk_pem: key.pk_pem,
            alg: key.alg.into(),
        }
    }
}

impl From<&JwtKey> for JwtEdKey {
    fn from(key: &JwtKey) -> Self {
        Self {
            sk_pem: key.sk_pem.clone(),
            pk_pem: key.pk_pem.clone(),
            alg: key.alg.try_into().unwrap(),
        }
    }
}

impl JwtEdKey {
    pub fn new_key(alg: JwsEdAlgorithm) -> Self {
        match alg {
            JwsEdAlgorithm::Ed25519 => {
                let kp = ed25519_compact::KeyPair::generate();
                Self {
                    sk_pem: kp.sk.to_pem(),
                    pk_pem: kp.pk.to_pem(),
                    alg,
                }
            }
        }
    }

    pub fn claims(&self, token: &str) -> JWTClaims<Dpop> {
        match self.alg {
            JwsEdAlgorithm::Ed25519 => Ed25519PublicKey::from_pem(&self.pk_pem)
                .unwrap()
                .verify_token::<Dpop>(token, None)
                .unwrap(),
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

    pub fn p384_jwk_to_kp(jwk: &Jwk) -> ES384PublicKey {
        let jwk = serde_json::to_string(jwk).unwrap();
        let jwk = elliptic_curve::JwkEcKey::from_str(&jwk).unwrap();
        let pk: PublicKey<p384::NistP384> = jwk.to_public_key().unwrap();
        use p384::pkcs8::EncodePublicKey as _;
        let der = pk.to_public_key_der().unwrap();
        let key = ES384PublicKey::from_der(der.as_bytes()).unwrap();
        key
    }

    pub fn rand_jwk(alg: JwsAlgorithm) -> Jwk {
        let pk = match alg {
            JwsAlgorithm::P256 => ES256KeyPair::generate().public_key().to_pem().unwrap(),
            JwsAlgorithm::P384 => ES384KeyPair::generate().public_key().to_pem().unwrap(),
            JwsAlgorithm::Ed25519 => Ed25519KeyPair::generate().public_key().to_pem(),
        };
        RustyJwk::new_jwk(alg, pk).unwrap()
    }
}
