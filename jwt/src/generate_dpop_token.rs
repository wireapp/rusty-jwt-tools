use jwt_simple::prelude::*;

use crate::dpop::Dpop;
use crate::jwk::RustyJwk;
use crate::{JwsAlgorithm, RustyJwtResult, RustyJwtTools};

impl RustyJwtTools {
    /// TODO
    pub fn generate_dpop_token(dpop: Dpop, alg: JwsAlgorithm, sk: String, pk: String) -> RustyJwtResult<String> {
        match alg {
            JwsAlgorithm::Ed25519 => {
                let mut kp = Ed25519KeyPair::from_pem(sk.as_str())?;
                kp.attach_metadata(Self::new_metadata(alg, pk)?)?;
                Ok(kp.sign_with_header(dpop.into(), Self::new_header(alg))?)
            }
            JwsAlgorithm::P256 => {
                let mut kp = ES256KeyPair::from_pem(sk.as_str())?;
                kp.attach_metadata(Self::new_metadata(alg, pk)?)?;
                Ok(kp.sign_with_header(dpop.into(), Self::new_header(alg))?)
            }
        }
    }

    fn new_header(alg: JwsAlgorithm) -> JWTHeader {
        let mut header = JWTHeader::default();
        header.algorithm = alg.to_string();
        header.signature_type = Some(Dpop::TYP.to_string());
        header
    }

    fn new_metadata(alg: JwsAlgorithm, pk: String) -> RustyJwtResult<KeyMetadata> {
        Ok(KeyMetadata::default().with_public_key(RustyJwk::new_jwk(alg, pk)?))
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::test_utils::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod headers {
        use super::*;

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_dpop_typ(keys: JwtKeys) {
            let token =
                RustyJwtTools::generate_dpop_token(Dpop::default(), keys.alg, keys.sk_pem, keys.pk_pem).unwrap();
            let header = Token::decode_metadata(token.as_str()).unwrap();
            assert_eq!(header.signature_type(), Some(Dpop::TYP))
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_alg(keys: JwtKeys) {
            let token =
                RustyJwtTools::generate_dpop_token(Dpop::default(), keys.alg, keys.sk_pem, keys.pk_pem).unwrap();
            let header = Token::decode_metadata(token.as_str()).unwrap();
            assert_eq!(header.algorithm(), keys.alg.to_string().as_str())
        }
    }

    pub mod jwk {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        fn should_have_p256_jwk() {
            let keys = JwtKeys::new_ec_keys(JwsAlgorithm::P256);
            let token = RustyJwtTools::generate_dpop_token(Dpop::default(), keys.alg, keys.sk_pem, keys.pk_pem.clone())
                .unwrap();
            let header = Token::decode_metadata(token.as_str()).unwrap();
            let jwk = header.public_key().unwrap();
            let is_valid = |p: &EllipticCurveKeyParameters| {
                p.key_type == EllipticCurveKeyType::EC
                    && p.curve == EllipticCurve::P256
                    && keys.pk_pem == RustyJwk::p256_jwk_to_kp(jwk).to_pem().unwrap()
            };
            assert!(matches!(&jwk.algorithm, AlgorithmParameters::EllipticCurve(p) if is_valid(p)));
        }

        #[test]
        #[wasm_bindgen_test]
        pub fn should_have_ed25519_jwk() {
            let keys = JwtKeys::new_ed_keys();
            let token = RustyJwtTools::generate_dpop_token(Dpop::default(), keys.alg, keys.sk_pem, keys.pk_pem.clone())
                .unwrap();
            let header = Token::decode_metadata(token.as_str()).unwrap();
            let jwk = header.public_key().unwrap();
            let is_valid = |p: &OctetKeyPairParameters| {
                p.key_type == OctetKeyPairType::OctetKeyPair
                    && p.curve == EdwardCurve::Ed25519
                    && keys.pk_pem == RustyJwk::ed25519_jwk_to_kp(jwk).to_pem()
            };
            assert!(matches!(&jwk.algorithm, AlgorithmParameters::OctetKeyPair(p) if is_valid(p)));
        }
    }

    pub mod verify_signature {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        pub fn should_verify_p256() {
            let keys = JwtKeys::new_ec_keys(JwsAlgorithm::P256);
            let token = RustyJwtTools::generate_dpop_token(Dpop::default(), keys.alg, keys.sk_pem, keys.pk_pem.clone())
                .unwrap();

            // validate token given raw public key
            let pk = ES256PublicKey::from_pem(&keys.pk_pem).unwrap();
            assert!(pk.verify_token::<Dpop>(&token, None).is_ok());

            // should not be valid with another key
            let other_pk = ES256KeyPair::generate().public_key();
            assert!(other_pk.verify_token::<Dpop>(&token, None).is_err());

            // validate token given jwk in header
            let header = Token::decode_metadata(token.as_str()).unwrap();
            let jwk = header.public_key().unwrap();
            let is_valid = |j: &Jwk| RustyJwk::p256_jwk_to_kp(j).verify_token::<Dpop>(&token, None).is_ok();
            assert!(matches!(jwk.algorithm, AlgorithmParameters::EllipticCurve(_) if is_valid(jwk)));

            // should not be valid with another jwk
            let jwk = RustyJwk::rand_jwk(JwsAlgorithm::P256);
            assert!(matches!(jwk.algorithm, AlgorithmParameters::EllipticCurve(_) if !is_valid(&jwk)));
        }

        #[test]
        #[wasm_bindgen_test]
        pub fn should_verify_ed25519() {
            let keys = JwtKeys::new_ed_keys();
            let token = RustyJwtTools::generate_dpop_token(Dpop::default(), keys.alg, keys.sk_pem, keys.pk_pem.clone())
                .unwrap();

            // validate token given raw public key
            let pk = Ed25519PublicKey::from_pem(&keys.pk_pem).unwrap();
            assert!(pk.verify_token::<Dpop>(&token, None).is_ok());

            // should not be valid with another key
            let other_pk = Ed25519KeyPair::generate().public_key();
            assert!(other_pk.verify_token::<Dpop>(&token, None).is_err());

            // validate token given jwk in header
            let header = Token::decode_metadata(token.as_str()).unwrap();
            let jwk = header.public_key().unwrap();

            let is_valid = |j: &Jwk| {
                RustyJwk::ed25519_jwk_to_kp(j)
                    .verify_token::<Dpop>(&token, None)
                    .is_ok()
            };
            assert!(matches!(jwk.algorithm, AlgorithmParameters::OctetKeyPair(_) if is_valid(jwk)));

            // should not be valid with another jwk
            let jwk = RustyJwk::rand_jwk(JwsAlgorithm::Ed25519);
            assert!(matches!(jwk.algorithm, AlgorithmParameters::OctetKeyPair(_) if !is_valid(&jwk)));
        }
    }

    pub mod claims {
        use super::*;

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_jti(keys: JwtKeys) {
            let token =
                RustyJwtTools::generate_dpop_token(Dpop::default(), keys.alg, keys.sk_pem.clone(), keys.pk_pem.clone())
                    .unwrap();
            let claims = keys.claims(&token);
            assert!(claims.jwt_id.is_some());
            assert!(uuid::Uuid::try_parse(&claims.jwt_id.unwrap()).is_ok());
        }
    }
}
