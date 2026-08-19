//! Test utils exposed for e2e test

use jsonwebtoken::{DecodingKey, Validation, decode, jwk::Jwk};
use jwt_simple::claims::JWTClaims;
use sec1::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, EncodePublicKey as _};
use serde::{Serialize, de::DeserializeOwned};

use crate::model::{alg::JwsAlgorithm, pem::Pem};
use rand;

/// Test util to for keys
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
    ///  Create a new key pair
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

    /// Decode the claims of a token
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

    /// Get the Jwk of a key
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
