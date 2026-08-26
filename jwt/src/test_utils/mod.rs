pub use crate::jwt_key;
use crate::{dpop::Dpop, jwk_thumbprint::JwkThumbprint, jwt_key::JwtKey, prelude::*};
pub use access::*;
pub use dpop::*;
use jsonwebtoken::jwk::Jwk;
use jwt_simple::claims::JWTClaims;
#[allow(unused_imports)]
pub use rstest::*;
pub use rstest_reuse::{self, *};
pub use utils::*;
pub mod access;
pub mod dpop;
pub mod utils;

#[template]
#[export]
#[rstest(
    key,
    case::Ed25519($ crate::jwt_key::JwtKey::new_key(JwsAlgorithm::EdDSA)),
    case::P256($ crate::jwt_key::JwtKey::new_key(JwsAlgorithm::ES256)),
    case::P384($ crate::jwt_key::JwtKey::new_key(JwsAlgorithm::ES384)),
    case::P521($ crate::jwt_key::JwtKey::new_key(JwsAlgorithm::ES512))
)]
#[allow(non_snake_case)]
pub fn all_keys(key: JwtKey) {}

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
