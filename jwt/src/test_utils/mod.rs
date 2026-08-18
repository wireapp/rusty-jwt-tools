pub use access::*;
pub use dpop::*;
use jsonwebtoken::{DecodingKey, Validation, decode, jwk::Jwk};
use jwt_simple::claims::JWTClaims;
#[allow(unused_imports)]
pub use rstest::*;
pub use rstest_reuse::{self, *};
use sec1::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use serde::{Serialize, de::DeserializeOwned};
pub use utils::*;

use crate::{dpop::Dpop, jwk_thumbprint::JwkThumbprint, prelude::*};

pub mod access;
pub mod dpop;
pub mod utils;

#[template]
#[export]
#[rstest(
    key,
    case::Ed25519($ crate::test_utils::JwtKey::new_key(JwsAlgorithm::EdDSA)),
    case::P256($ crate::test_utils::JwtKey::new_key(JwsAlgorithm::ES256)),
    case::P384($ crate::test_utils::JwtKey::new_key(JwsAlgorithm::ES384)),
    case::P521($ crate::test_utils::JwtKey::new_key(JwsAlgorithm::ES512))
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
            JwsAlgorithm::ES256 | JwsAlgorithm::ES384 | JwsAlgorithm::ES512 => {
                JwtEcKey::new_key(alg.try_into().unwrap()).into()
            }
            JwsAlgorithm::EdDSA => JwtEdKey::new_key(alg.try_into().unwrap()).into(),
        }
    }

    pub fn claims<T>(&self, token: &str) -> JWTClaims<T>
    where
        T: Serialize + DeserializeOwned,
    {
        let key = match self.alg {
            JwsAlgorithm::ES256 | JwsAlgorithm::ES384 | JwsAlgorithm::ES512 => {
                DecodingKey::from_ec_pem(self.pk.as_ref()).expect("Decoding key from pem")
            }
            JwsAlgorithm::EdDSA => DecodingKey::from_ed_pem(self.pk.as_ref()).expect("Decoding key from pem"),
        };
        let mut validation = Validation::new(self.alg.into());
        validation.validate_aud = false;
        decode::<JWTClaims<T>>(token, &key, &validation)
            .expect("decoding token")
            .claims
    }

    /// Just creates a new fresh key with same algorithm
    pub fn create_another(&self) -> Self {
        Self::new_key(self.alg)
    }

    /// Given an algorithm X returns all the algorithms which are not X
    pub fn reverse_algorithms(&self) -> [JwsAlgorithm; 3] {
        match self.alg {
            JwsAlgorithm::ES256 => [JwsAlgorithm::ES384, JwsAlgorithm::ES512, JwsAlgorithm::EdDSA],
            JwsAlgorithm::ES384 => [JwsAlgorithm::ES256, JwsAlgorithm::ES512, JwsAlgorithm::EdDSA],
            JwsAlgorithm::ES512 => [JwsAlgorithm::ES256, JwsAlgorithm::ES384, JwsAlgorithm::EdDSA],
            JwsAlgorithm::EdDSA => [JwsAlgorithm::ES256, JwsAlgorithm::ES384, JwsAlgorithm::ES512],
        }
    }

    pub fn to_jwk(&self) -> Jwk {
        let key = match self.alg {
            JwsAlgorithm::ES256 | JwsAlgorithm::ES384 | JwsAlgorithm::ES512 => {
                DecodingKey::from_ec_pem(self.pk.as_ref()).unwrap()
            }
            JwsAlgorithm::EdDSA => DecodingKey::from_ed_pem(self.pk.as_ref()).unwrap(),
        };
        Jwk::from_decoding_key(&key, Some(self.alg.into())).expect("jwk from decoding key")
    }
}

impl From<(JwsAlgorithm, Pem)> for JwtKey {
    fn from((alg, kp): (JwsAlgorithm, Pem)) -> Self {
        match alg {
            JwsAlgorithm::ES256 | JwsAlgorithm::ES384 | JwsAlgorithm::ES512 => {
                JwtEcKey::from((alg.try_into().unwrap(), kp)).into()
            }
            JwsAlgorithm::EdDSA => JwtEdKey::from((alg.try_into().unwrap(), kp)).into(),
        }
    }
}

/// --- Elliptic curves ---
#[template]
#[export]
#[rstest(
key,
case::P256($ crate::test_utils::JwtEcKey::new_key($ crate::prelude::JwsEcAlgorithm::P256)),
case::P384($ crate::test_utils::JwtEcKey::new_key($ crate::prelude::JwsEcAlgorithm::P384)),
case::P521($ crate::test_utils::JwtEcKey::new_key($ crate::prelude::JwsEcAlgorithm::P521))
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
            JwsEcAlgorithm::P521 => (alg, ES512KeyPair::generate().to_pem().unwrap().into()).into(),
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
            JwsEcAlgorithm::P521 => {
                let kp = ES512KeyPair::from_pem(kp.as_str()).unwrap();
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
            JwsEdAlgorithm::Ed25519 => (
                alg,
                (*ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
                    .to_pkcs8_pem(sec1::LineEnding::LF)
                    .unwrap())
                .clone()
                .into(),
            )
                .into(),
        }
    }
}

impl From<(JwsEdAlgorithm, Pem)> for JwtEdKey {
    fn from((alg, kp): (JwsEdAlgorithm, Pem)) -> Self {
        match alg {
            JwsEdAlgorithm::Ed25519 => {
                let sk = ed25519_dalek::SigningKey::from_pkcs8_pem(kp.as_str()).unwrap();
                let mut keypair_bytes = ed25519_dalek::pkcs8::KeypairBytes::from(&sk);
                let kp_pem = (*keypair_bytes.to_pkcs8_pem(sec1::LineEnding::LF).unwrap())
                    .clone()
                    .into();
                let _ = keypair_bytes.public_key.take();
                let sk_pem = (*keypair_bytes.to_pkcs8_pem(sec1::LineEnding::LF).unwrap())
                    .clone()
                    .into();
                Self {
                    kp: kp_pem,
                    sk: sk_pem,
                    pk: sk
                        .verifying_key()
                        .to_public_key_pem(sec1::LineEnding::LF)
                        .unwrap()
                        .into(),
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
case::Cipher1($crate::test_utils::Ciphersuite::new(JwsAlgorithm::EdDSA, HashAlgorithm::SHA256)),
case::Cipher2($crate::test_utils::Ciphersuite::new(JwsAlgorithm::ES256, HashAlgorithm::SHA256)),
case::Cipher7($crate::test_utils::Ciphersuite::new(JwsAlgorithm::ES384, HashAlgorithm::SHA384)),
case::Cipher5($crate::test_utils::Ciphersuite::new(JwsAlgorithm::ES512, HashAlgorithm::SHA512)),
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

    pub fn to_jwk_thumbprint(&self) -> JwkThumbprint {
        JwkThumbprint::generate(&self.key.to_jwk(), self.hash).unwrap()
    }
}

/// Very useful for debugging a specific test ()
impl Default for Ciphersuite {
    fn default() -> Self {
        Self::new(JwsAlgorithm::EdDSA, HashAlgorithm::SHA256)
    }
}

#[template]
#[export]
#[rstest(
    hash,
    case::SHA256(HashAlgorithm::SHA256),
    case::SHA384(HashAlgorithm::SHA384),
    case::SHA512(HashAlgorithm::SHA512)
)]
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
