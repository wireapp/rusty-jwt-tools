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
        let (sk_pem, pk_pem) = match alg {
            JwsAlgorithm::ES256 => Self::generate_p256_key_pair(),
            JwsAlgorithm::ES384 => Self::generate_p384_keypair(),
            JwsAlgorithm::ES512 => Self::generate_p521_keypair(),
            JwsAlgorithm::EdDSA => Self::generate_ed25519_keypair(),
        };

        Self {
            kp: sk_pem.clone().into(),
            sk: sk_pem.into(),
            pk: pk_pem.into(),
            alg,
        }
    }

    fn generate_p256_key_pair() -> (String, String) {
        let sk = p256::SecretKey::random(&mut rand::thread_rng());
        let sk_pem = sk.to_pkcs8_pem(Default::default()).unwrap().to_string();
        let pk_pem = sk.public_key().to_public_key_pem(Default::default()).unwrap();
        (sk_pem, pk_pem)
    }

    fn generate_p384_keypair() -> (String, String) {
        let sk = p384::SecretKey::random(&mut rand::thread_rng());
        let sk_pem = sk.to_pkcs8_pem(Default::default()).unwrap().to_string();
        let pk_pem = sk.public_key().to_public_key_pem(Default::default()).unwrap();
        (sk_pem, pk_pem)
    }
    fn generate_p521_keypair() -> (String, String) {
        let sk = p521::SecretKey::random(&mut rand::thread_rng());
        let sk_pem = sk.to_pkcs8_pem(Default::default()).unwrap().to_string();
        let pk_pem = sk.public_key().to_public_key_pem(Default::default()).unwrap();
        (sk_pem, pk_pem)
    }

    fn generate_ed25519_keypair() -> (String, String) {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let sk_pem = sk.to_pkcs8_pem(Default::default()).unwrap().to_string();
        let pk_pem = sk.verifying_key().to_public_key_pem(Default::default()).unwrap();
        (sk_pem, pk_pem)
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
        let pk = match alg {
            JwsAlgorithm::ES256 => {
                let sk = p256::SecretKey::from_pkcs8_pem(kp.as_str()).expect("valid P-256 private key");
                sk.public_key()
                    .to_public_key_pem(Default::default())
                    .expect("P-256 public key PEM")
            }

            JwsAlgorithm::ES384 => {
                let sk = p384::SecretKey::from_pkcs8_pem(kp.as_str()).expect("valid P-384 private key");
                sk.public_key()
                    .to_public_key_pem(Default::default())
                    .expect("P-384 public key PEM")
            }

            JwsAlgorithm::ES512 => {
                let sk = p521::SecretKey::from_pkcs8_pem(kp.as_str()).expect("valid P-521 private key");
                sk.public_key()
                    .to_public_key_pem(Default::default())
                    .expect("P-521 public key PEM")
            }

            JwsAlgorithm::EdDSA => {
                let sk = ed25519_dalek::SigningKey::from_pkcs8_pem(kp.as_str()).expect("valid Ed25519 private key");

                sk.verifying_key()
                    .to_public_key_pem(Default::default())
                    .expect("Ed25519 public key PEM")
            }
        };

        Self {
            kp: kp.clone(),
            sk: kp,
            pk: pk.into(),
            alg,
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
