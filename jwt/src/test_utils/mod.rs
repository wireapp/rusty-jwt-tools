use jwt_simple::prelude::*;
pub use rstest::*;
pub use rstest_reuse::{self, *};

pub use jwk::*;
pub use jwt::*;

use crate::{
    alg::{JwsEcAlgorithm, JwsEdAlgorithm},
    dpop::Dpop,
    prelude::*,
};

pub mod jwk;
pub mod jwt;

#[template]
#[export]
#[rstest(
key,
case::Ed25519($ crate::test_utils::JwtKey::new_key(JwsAlgorithm::Ed25519)),
case::P256($ crate::test_utils::JwtKey::new_key(JwsAlgorithm::P256)),
case::P384($ crate::test_utils::JwtKey::new_key(JwsAlgorithm::P384))
)]
#[allow(non_snake_case)]
pub fn all_keys(key: JwtKey) {}

#[derive(Debug, Clone)]
pub struct JwtKey {
    /// KeyPair
    pub kp: Pem,
    /// SecretKey
    pub sk: Pem,
    /// PublicKey
    pub pk: Pem,
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
case::P256($ crate::test_utils::JwtEcKey::new_key($ crate::alg::JwsEcAlgorithm::P256)),
case::P384($ crate::test_utils::JwtEcKey::new_key($ crate::alg::JwsEcAlgorithm::P384))
)]
#[allow(non_snake_case)]
pub fn all_ec_keys(key: JwtEcKey) {}

pub struct JwtEcKey {
    /// KeyPair
    pub kp: Pem,
    /// SecretKey
    pub sk: Pem,
    /// PublicKey
    pub pk: Pem,
    pub alg: JwsEcAlgorithm,
}

impl From<JwtEcKey> for JwtKey {
    fn from(key: JwtEcKey) -> Self {
        Self {
            kp: key.kp,
            sk: key.sk,
            pk: key.pk,
            alg: key.alg.into(),
        }
    }
}

impl From<&JwtKey> for JwtEcKey {
    fn from(key: &JwtKey) -> Self {
        Self {
            kp: key.kp.clone(),
            sk: key.sk.clone(),
            pk: key.pk.clone(),
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
                let sk: Pem = kp.to_pem().unwrap().into();
                let pk = kp.public_key().to_pem().unwrap().into();
                Self {
                    kp: sk.clone(),
                    sk,
                    pk,
                    alg,
                }
            }
            JwsEcAlgorithm::P384 => {
                let kp = ES384KeyPair::generate();
                let kp = kp.key_pair();
                let sk: Pem = kp.to_pem().unwrap().into();
                let pk = kp.public_key().to_pem().unwrap().into();
                Self {
                    kp: sk.clone(),
                    sk,
                    pk,
                    alg,
                }
            }
        }
    }

    pub fn claims(&self, token: &str) -> JWTClaims<Dpop> {
        match self.alg {
            JwsEcAlgorithm::P256 => ES256PublicKey::from_pem(&self.pk)
                .unwrap()
                .verify_token::<Dpop>(token, None)
                .unwrap(),
            JwsEcAlgorithm::P384 => ES384PublicKey::from_pem(&self.pk)
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
case::Ed25519($ crate::test_utils::JwtEdKey::new_key($ crate::alg::JwsEdAlgorithm::Ed25519))
)]
#[allow(non_snake_case)]
pub fn all_ed_keys(key: JwtEdKey) {}

pub struct JwtEdKey {
    /// KeyPair
    pub kp: Pem,
    /// SecretKey
    pub sk: Pem,
    /// PublicKey
    pub pk: Pem,
    pub alg: JwsEdAlgorithm,
}

impl From<JwtEdKey> for JwtKey {
    fn from(key: JwtEdKey) -> Self {
        Self {
            kp: key.kp,
            sk: key.sk,
            pk: key.pk,
            alg: key.alg.into(),
        }
    }
}

impl From<&JwtKey> for JwtEdKey {
    fn from(key: &JwtKey) -> Self {
        Self {
            kp: key.kp.clone(),
            sk: key.sk.clone(),
            pk: key.pk.clone(),
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
                    kp: kp.to_pem().into(),
                    sk: kp.sk.to_pem().into(),
                    pk: kp.pk.to_pem().into(),
                    alg,
                }
            }
        }
    }

    pub fn claims(&self, token: &str) -> JWTClaims<Dpop> {
        match self.alg {
            JwsEdAlgorithm::Ed25519 => Ed25519PublicKey::from_pem(&self.pk)
                .unwrap()
                .verify_token::<Dpop>(token, None)
                .unwrap(),
        }
    }
}
