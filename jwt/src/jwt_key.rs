//! Test utils exposed for e2e test

use jsonwebtoken::{Validation, decode, jwk::Jwk};
use p256::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    jwt::JwtClaims,
    model::{alg::JwsAlgorithm, pem::Pem},
};

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
        (alg, alg.generate_keypair().expect("key pair generation")).into()
    }

    /// Decode the claims of a token
    pub fn claims<T>(&self, token: &str) -> JwtClaims<T>
    where
        T: Serialize + DeserializeOwned,
    {
        let key = self.alg.decoding_key(&self.pk).expect("Decoding key from pem");
        let mut validation = Validation::new(self.alg.into());
        validation.validate_aud = false;
        decode::<JwtClaims<T>>(token, &key, &validation)
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
        let key = self.alg.decoding_key(&self.pk).unwrap();
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
