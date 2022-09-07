use jwt_simple::prelude::*;

use crate::{dpop::Dpop, jwk::RustyJwk, prelude::*};

impl RustyJwtTools {
    /// Generates a DPoP JWT. Generally used on the client side.
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
            JwsAlgorithm::P384 => {
                let mut kp = ES384KeyPair::from_pem(sk.as_str())?;
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

    use crate::{
        alg::{JwsEcAlgorithm, JwsEdAlgorithm},
        test_utils::*,
    };

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod headers {
        use super::*;

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_dpop_typ(key: JwtKey) {
            let token = RustyJwtTools::generate_dpop_token(Dpop::default(), key.alg, key.sk_pem, key.pk_pem).unwrap();
            let header = Token::decode_metadata(token.as_str()).unwrap();
            assert_eq!(header.signature_type(), Some(Dpop::TYP))
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_alg(key: JwtKey) {
            let token = RustyJwtTools::generate_dpop_token(Dpop::default(), key.alg, key.sk_pem, key.pk_pem).unwrap();
            let header = Token::decode_metadata(token.as_str()).unwrap();
            let expected_alg = match key.alg {
                JwsAlgorithm::P256 => "ES256",
                JwsAlgorithm::P384 => "ES384",
                JwsAlgorithm::Ed25519 => "EdDSA",
            };
            assert_eq!(header.algorithm(), expected_alg)
        }
    }

    pub mod jwk {
        use super::*;

        #[apply(all_ec_keys)]
        #[wasm_bindgen_test]
        fn should_have_ec_jwk(key: JwtEcKey) {
            let token =
                RustyJwtTools::generate_dpop_token(Dpop::default(), key.alg.into(), key.sk_pem, key.pk_pem.clone())
                    .unwrap();
            let header = Token::decode_metadata(token.as_str()).unwrap();
            let jwk = header.public_key().unwrap();
            let is_valid = |p: &EllipticCurveKeyParameters| {
                let (kty, curve, pk_pem) = match key.alg {
                    JwsEcAlgorithm::P256 => {
                        let kty = EllipticCurveKeyType::EC;
                        let curve = EllipticCurve::P256;
                        let pk_pem = RustyJwk::p256_jwk_to_kp(jwk).to_pem().unwrap();
                        (kty, curve, pk_pem)
                    }
                    JwsEcAlgorithm::P384 => {
                        let kty = EllipticCurveKeyType::EC;
                        let curve = EllipticCurve::P384;
                        let pk_pem = RustyJwk::p384_jwk_to_kp(jwk).to_pem().unwrap();
                        (kty, curve, pk_pem)
                    }
                };
                p.key_type == kty && p.curve == curve && key.pk_pem == pk_pem
            };
            assert!(matches!(&jwk.algorithm, AlgorithmParameters::EllipticCurve(p) if is_valid(p)));
        }

        #[apply(all_ed_keys)]
        #[wasm_bindgen_test]
        pub fn should_have_ed25519_jwk(key: JwtEdKey) {
            let token =
                RustyJwtTools::generate_dpop_token(Dpop::default(), key.alg.into(), key.sk_pem, key.pk_pem.clone())
                    .unwrap();
            let header = Token::decode_metadata(token.as_str()).unwrap();
            let jwk = header.public_key().unwrap();
            let is_valid = |p: &OctetKeyPairParameters| {
                let (kty, curve, pk_pem) = match key.alg {
                    JwsEdAlgorithm::Ed25519 => {
                        let kty = OctetKeyPairType::OctetKeyPair;
                        let curve = EdwardCurve::Ed25519;
                        let pk_pem = RustyJwk::ed25519_jwk_to_kp(jwk).to_pem();
                        (kty, curve, pk_pem)
                    }
                };
                p.key_type == kty && p.curve == curve && key.pk_pem == pk_pem
            };
            assert!(matches!(&jwk.algorithm, AlgorithmParameters::OctetKeyPair(p) if is_valid(p)));
        }
    }

    pub mod verify_signature {
        use super::*;

        #[apply(all_ec_keys)]
        #[wasm_bindgen_test]
        pub fn should_verify_ec(key: JwtEcKey) {
            let token =
                RustyJwtTools::generate_dpop_token(Dpop::default(), key.alg.into(), key.sk_pem, key.pk_pem.clone())
                    .unwrap();

            // validate token given raw public key
            let verify = match key.alg {
                JwsEcAlgorithm::P256 => ES256PublicKey::from_pem(&key.pk_pem)
                    .unwrap()
                    .verify_token::<Dpop>(&token, None),
                JwsEcAlgorithm::P384 => ES384PublicKey::from_pem(&key.pk_pem)
                    .unwrap()
                    .verify_token::<Dpop>(&token, None),
            };
            assert!(verify.is_ok());

            // should not be valid with another key
            let verify_with_other_key = match key.alg {
                JwsEcAlgorithm::P256 => ES256KeyPair::generate().public_key().verify_token::<Dpop>(&token, None),
                JwsEcAlgorithm::P384 => ES384KeyPair::generate().public_key().verify_token::<Dpop>(&token, None),
            };
            assert!(verify_with_other_key.is_err());

            // validate token given jwk in header
            let header = Token::decode_metadata(token.as_str()).unwrap();
            let jwk = header.public_key().unwrap();
            let is_valid = |j: &Jwk| {
                match key.alg {
                    JwsEcAlgorithm::P256 => RustyJwk::p256_jwk_to_kp(j).verify_token::<Dpop>(&token, None),
                    JwsEcAlgorithm::P384 => RustyJwk::p384_jwk_to_kp(j).verify_token::<Dpop>(&token, None),
                }
                .is_ok()
            };
            assert!(matches!(jwk.algorithm, AlgorithmParameters::EllipticCurve(_) if is_valid(jwk)));

            // should not be valid with another jwk
            let jwk = RustyJwk::rand_jwk(key.alg.into());
            assert!(matches!(jwk.algorithm, AlgorithmParameters::EllipticCurve(_) if !is_valid(&jwk)));
        }

        #[apply(all_ed_keys)]
        #[wasm_bindgen_test]
        pub fn should_verify_ed(key: JwtEdKey) {
            let token =
                RustyJwtTools::generate_dpop_token(Dpop::default(), key.alg.into(), key.sk_pem, key.pk_pem.clone())
                    .unwrap();

            // validate token given raw public key
            let verify = match key.alg {
                JwsEdAlgorithm::Ed25519 => Ed25519PublicKey::from_pem(&key.pk_pem)
                    .unwrap()
                    .verify_token::<Dpop>(&token, None),
            };
            assert!(verify.is_ok());

            // should not be valid with another key
            let verify = match key.alg {
                JwsEdAlgorithm::Ed25519 => Ed25519KeyPair::generate()
                    .public_key()
                    .verify_token::<Dpop>(&token, None),
            };
            assert!(verify.is_err());

            // validate token given jwk in header
            let header = Token::decode_metadata(token.as_str()).unwrap();
            let jwk = header.public_key().unwrap();

            let is_valid = |j: &Jwk| {
                match key.alg {
                    JwsEdAlgorithm::Ed25519 => RustyJwk::ed25519_jwk_to_kp(j).verify_token::<Dpop>(&token, None),
                }
                .is_ok()
            };
            assert!(matches!(jwk.algorithm, AlgorithmParameters::OctetKeyPair(_) if is_valid(jwk)));

            // should not be valid with another jwk
            let jwk = RustyJwk::rand_jwk(key.alg.into());
            assert!(matches!(jwk.algorithm, AlgorithmParameters::OctetKeyPair(_) if !is_valid(&jwk)));
        }
    }

    pub mod claims {
        use super::*;

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_jti(key: JwtKey) {
            let token =
                RustyJwtTools::generate_dpop_token(Dpop::default(), key.alg, key.sk_pem.clone(), key.pk_pem.clone())
                    .unwrap();
            let claims = key.claims(&token);
            assert!(claims.jwt_id.is_some());
            assert!(uuid::Uuid::try_parse(&claims.jwt_id.unwrap()).is_ok());
        }
    }
}
