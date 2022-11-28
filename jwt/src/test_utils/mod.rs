use jwt_simple::prelude::*;
pub use rstest::*;
pub use rstest_reuse::{self, *};
use serde::de::DeserializeOwned;

pub use access::*;
pub use dpop::*;
pub use jwk::*;
pub use utils::*;

use crate::jkt::JktConfirmation;
use crate::jwk::TryIntoJwk;
use crate::{dpop::Dpop, prelude::*};

pub mod access;
pub mod dpop;
pub mod jwk;
pub mod utils;

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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct JwtKey {
    /// KeyPair
    pub kp: Pem,
    /// SecretKey
    pub sk: Pem,
    /// PublicKey
    pub pk: Pem,
    /// Algorithm
    pub alg: JwsAlgorithm,
}

impl JwtKey {
    pub fn new_key(alg: JwsAlgorithm) -> Self {
        match alg {
            JwsAlgorithm::P256 | JwsAlgorithm::P384 => JwtEcKey::new_key(alg.try_into().unwrap()).into(),
            JwsAlgorithm::Ed25519 => JwtEdKey::new_key(alg.try_into().unwrap()).into(),
        }
    }

    pub fn claims<T>(&self, token: &str) -> JWTClaims<T>
    where
        T: Serialize + DeserializeOwned,
    {
        match self.alg {
            JwsAlgorithm::P256 | JwsAlgorithm::P384 => JwtEcKey::from(self).claims::<T>(token),
            JwsAlgorithm::Ed25519 => JwtEdKey::from(self).claims::<T>(token),
        }
    }

    /// Just creates a new fresh key with same algorithm
    pub fn create_another(&self) -> Self {
        Self::new_key(self.alg)
    }

    /// Given an algorithm X returns all the algorithms which are not X
    pub fn reverse_algorithms(&self) -> [JwsAlgorithm; 2] {
        match self.alg {
            JwsAlgorithm::P256 => [JwsAlgorithm::P384, JwsAlgorithm::Ed25519],
            JwsAlgorithm::P384 => [JwsAlgorithm::P256, JwsAlgorithm::Ed25519],
            JwsAlgorithm::Ed25519 => [JwsAlgorithm::P256, JwsAlgorithm::P384],
        }
    }

    pub fn to_jwk(&self) -> Jwk {
        match self.alg {
            JwsAlgorithm::P256 => ES256PublicKey::from_pem(self.pk.as_str())
                .unwrap()
                .try_into_jwk()
                .unwrap(),
            JwsAlgorithm::P384 => ES384PublicKey::from_pem(self.pk.as_str())
                .unwrap()
                .try_into_jwk()
                .unwrap(),
            JwsAlgorithm::Ed25519 => Ed25519PublicKey::from_pem(self.pk.as_str())
                .unwrap()
                .try_into_jwk()
                .unwrap(),
        }
    }
}

impl From<(JwsAlgorithm, Pem)> for JwtKey {
    fn from((alg, kp): (JwsAlgorithm, Pem)) -> Self {
        match alg {
            JwsAlgorithm::P256 | JwsAlgorithm::P384 => JwtEcKey::from((alg.try_into().unwrap(), kp)).into(),
            JwsAlgorithm::Ed25519 => JwtEdKey::from((alg.try_into().unwrap(), kp)).into(),
        }
    }
}

/// --- Elliptic curves ---
#[template]
#[export]
#[rstest(
key,
case::P256($ crate::test_utils::JwtEcKey::new_key($ crate::prelude::JwsEcAlgorithm::P256)),
case::P384($ crate::test_utils::JwtEcKey::new_key($ crate::prelude::JwsEcAlgorithm::P384))
)]
#[allow(non_snake_case)]
pub fn all_ec_keys(key: JwtEcKey) {}

#[derive(Debug, Clone, Eq, PartialEq)]
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
            JwsEcAlgorithm::P256 => (alg, ES256KeyPair::generate().to_pem().unwrap().into()).into(),
            JwsEcAlgorithm::P384 => (alg, ES384KeyPair::generate().to_pem().unwrap().into()).into(),
        }
    }

    pub fn claims<T>(&self, token: &str) -> JWTClaims<T>
    where
        T: Serialize + DeserializeOwned,
    {
        match self.alg {
            JwsEcAlgorithm::P256 => ES256PublicKey::from_pem(&self.pk)
                .unwrap()
                .verify_token::<T>(token, None)
                .unwrap(),
            JwsEcAlgorithm::P384 => ES384PublicKey::from_pem(&self.pk)
                .unwrap()
                .verify_token::<T>(token, None)
                .unwrap(),
        }
    }
}

impl From<(JwsEcAlgorithm, Pem)> for JwtEcKey {
    fn from((alg, kp): (JwsEcAlgorithm, Pem)) -> Self {
        match alg {
            JwsEcAlgorithm::P256 => {
                let kp = ES256KeyPair::from_pem(kp.as_str()).unwrap();
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
                let kp = ES384KeyPair::from_pem(kp.as_str()).unwrap();
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
}

/// --- Edward curves ---
#[template]
#[export]
#[rstest(
key,
case::Ed25519($ crate::test_utils::JwtEdKey::new_key($ crate::prelude::JwsEdAlgorithm::Ed25519))
)]
#[allow(non_snake_case)]
pub fn all_ed_keys(key: JwtEdKey) {}

#[derive(Debug, Clone, Eq, PartialEq)]
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
            JwsEdAlgorithm::Ed25519 => (alg, ed25519_compact::KeyPair::generate().to_pem().into()).into(),
        }
    }

    pub fn claims<T>(&self, token: &str) -> JWTClaims<T>
    where
        T: Serialize + DeserializeOwned,
    {
        match self.alg {
            JwsEdAlgorithm::Ed25519 => Ed25519PublicKey::from_pem(&self.pk)
                .unwrap()
                .verify_token::<T>(token, None)
                .unwrap(),
        }
    }
}

impl From<(JwsEdAlgorithm, Pem)> for JwtEdKey {
    fn from((alg, kp): (JwsEdAlgorithm, Pem)) -> Self {
        match alg {
            JwsEdAlgorithm::Ed25519 => {
                let kp = ed25519_compact::KeyPair::from_pem(kp.as_str()).unwrap();
                Self {
                    kp: kp.to_pem().into(),
                    sk: kp.sk.to_pem().into(),
                    pk: kp.pk.to_pem().into(),
                    alg,
                }
            }
        }
    }
}

#[template]
#[export]
#[rstest(
ciphersuite,
case::Cipher1($crate::test_utils::Ciphersuite::new(JwsAlgorithm::Ed25519, HashAlgorithm::SHA256)),
case::Cipher2($crate::test_utils::Ciphersuite::new(JwsAlgorithm::P256, HashAlgorithm::SHA256)),
case::Cipher7($crate::test_utils::Ciphersuite::new(JwsAlgorithm::P384, HashAlgorithm::SHA384)),
)]
#[allow(non_snake_case)]
pub fn all_ciphersuites(key: JwtKey, hash: HashAlgorithm) {}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ciphersuite {
    pub key: JwtKey,
    pub hash: HashAlgorithm,
}

impl Ciphersuite {
    pub fn new(sign: JwsAlgorithm, hash: HashAlgorithm) -> Self {
        Self {
            key: JwtKey::new_key(sign),
            hash,
        }
    }

    pub fn to_jwk_thumbprint(&self) -> JktConfirmation {
        JktConfirmation::generate(&self.key.to_jwk(), self.hash).unwrap()
    }
}

#[template]
#[export]
#[rstest(hash, case::SHA256(HashAlgorithm::SHA256), case::SHA384(HashAlgorithm::SHA384))]
#[allow(non_snake_case)]
pub fn all_hash(hash: HashAlgorithm) {}

#[template]
#[export]
#[rstest(
    key,
    case::AES128($ crate::test_utils::JweKey::new(JweAlgorithm::AES128GCM)),
    case::AES256($ crate::test_utils::JweKey::new(JweAlgorithm::AES256GCM)),
)]
#[allow(non_snake_case)]
pub fn all_cipher(key: JweKey) {}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct JweKey {
    pub alg: JweAlgorithm,
    pub value: Vec<u8>,
}

impl JweKey {
    pub fn new(alg: JweAlgorithm) -> Self {
        let key = Self::rand_key(alg.key_length());
        Self { alg, value: key }
    }

    fn rand_key(size: usize) -> Vec<u8> {
        use rand::{RngCore as _, SeedableRng as _};
        let mut key = vec![0u8; size];
        let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
        rng.fill_bytes(&mut key);
        key
    }
}
