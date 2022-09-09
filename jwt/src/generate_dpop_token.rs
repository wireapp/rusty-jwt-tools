use jwt_simple::prelude::*;

use crate::{dpop::Dpop, prelude::*};

impl RustyJwtTools {
    /// Generates a DPoP JWT. Generally used on the client side.
    ///
    /// # Arguments
    ///
    /// * `alg` - Algorithm of the signing key [kp]
    /// * `kp` - Signing key PEM encoded
    /// * `dpop` - Claims of the DPoP JWT
    /// * `nonce` - nonce generated by wire-server
    /// * `client_id` - unique user handle
    pub fn generate_dpop_token(
        alg: JwsAlgorithm,
        kp: Pem,
        dpop: Dpop,
        nonce: BackendNonce,
        client_id: ClientId,
    ) -> RustyJwtResult<String> {
        // TODO: is it up to us to validate the 'client_id' format or is it opaque to us ?
        use crate::jwk::TryIntoJwk as _;

        let header = Self::new_header(alg);
        let claims = dpop.into_jwt_claims(nonce, client_id);
        match alg {
            JwsAlgorithm::Ed25519 => {
                let mut kp = Ed25519KeyPair::from_pem(kp.as_str())?;
                let jwk = kp.public_key().try_into_jwk()?;
                kp.attach_metadata(Self::new_metadata(jwk))?;
                Ok(kp.sign_with_header(claims, header)?)
            }
            JwsAlgorithm::P256 => {
                let mut kp = ES256KeyPair::from_pem(kp.as_str())?;
                let jwk = kp.public_key().try_into_jwk()?;
                kp.attach_metadata(Self::new_metadata(jwk))?;
                Ok(kp.sign_with_header(claims, header)?)
            }
            JwsAlgorithm::P384 => {
                let mut kp = ES384KeyPair::from_pem(kp.as_str())?;
                let jwk = kp.public_key().try_into_jwk()?;
                kp.attach_metadata(Self::new_metadata(jwk))?;
                Ok(kp.sign_with_header(claims, header)?)
            }
        }
    }

    fn new_metadata(jwk: Jwk) -> KeyMetadata {
        KeyMetadata::default().with_public_key(jwk)
    }

    fn new_header(alg: JwsAlgorithm) -> JWTHeader {
        let mut header = JWTHeader::default();
        header.algorithm = alg.to_string();
        header.signature_type = Some(Dpop::TYP.to_string());
        header
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::{
        alg::{JwsEcAlgorithm, JwsEdAlgorithm},
        dpop::*,
        jwk::RustyJwk,
        test_utils::*,
    };
    use fluvio_wasm_timer::{SystemTime, UNIX_EPOCH};

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod headers {
        use super::*;

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_dpop_typ(key: JwtKey) {
            let token = RustyJwtTools::generate_dpop_token(
                key.alg,
                key.kp,
                Dpop::default(),
                BackendNonce::default(),
                ClientId::default(),
            )
            .unwrap();
            let header = Token::decode_metadata(token.as_str()).unwrap();
            assert_eq!(header.signature_type(), Some(Dpop::TYP))
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_alg(key: JwtKey) {
            let token = RustyJwtTools::generate_dpop_token(
                key.alg,
                key.kp,
                Dpop::default(),
                BackendNonce::default(),
                ClientId::default(),
            )
            .unwrap();
            let header = Token::decode_metadata(token.as_str()).unwrap();
            let expected_alg = match key.alg {
                JwsAlgorithm::P256 => "ES256",
                JwsAlgorithm::P384 => "ES384",
                JwsAlgorithm::Ed25519 => "EdDSA",
            };
            assert_eq!(header.algorithm(), expected_alg)
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_right_fields_naming(key: JwtKey) {
            let token = RustyJwtTools::generate_dpop_token(
                key.alg,
                key.kp,
                Dpop::default(),
                BackendNonce::default(),
                ClientId::default(),
            )
            .unwrap();
            let parts = token.split('.').collect::<Vec<&str>>();
            let claims = parts.first().unwrap();
            let claims = base64::decode(claims).unwrap();
            let claims = serde_json::from_slice::<serde_json::Value>(claims.as_slice()).unwrap();
            let claims = claims.as_object().unwrap();
            assert!(claims.get("typ").unwrap().as_str().is_some());
            assert!(claims.get("alg").unwrap().as_str().is_some());
            let jwk = claims.get("jwk").unwrap().as_object().unwrap();
            assert!(jwk.get("kty").unwrap().as_str().is_some());
            assert!(jwk.get("crv").unwrap().as_str().is_some());
            assert!(jwk.get("x").unwrap().as_str().is_some());
            if let JwsAlgorithm::P256 | JwsAlgorithm::P384 = key.alg {
                assert!(jwk.get("y").unwrap().as_str().is_some());
            } else {
                assert!(jwk.get("y").is_none());
            }
        }
    }

    pub mod jwk {
        use super::*;

        #[apply(all_ec_keys)]
        #[wasm_bindgen_test]
        fn should_have_ec_jwk(key: JwtEcKey) {
            let token = RustyJwtTools::generate_dpop_token(
                key.alg.into(),
                key.kp,
                Dpop::default(),
                BackendNonce::default(),
                ClientId::default(),
            )
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
                p.key_type == kty && p.curve == curve && key.pk == pk_pem.into()
            };
            assert!(matches!(&jwk.algorithm, AlgorithmParameters::EllipticCurve(p) if is_valid(p)));
        }

        #[apply(all_ed_keys)]
        #[wasm_bindgen_test]
        pub fn should_have_ed25519_jwk(key: JwtEdKey) {
            let token = RustyJwtTools::generate_dpop_token(
                key.alg.into(),
                key.kp,
                Dpop::default(),
                BackendNonce::default(),
                ClientId::default(),
            )
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
                p.key_type == kty && p.curve == curve && key.pk == pk_pem.into()
            };
            assert!(matches!(&jwk.algorithm, AlgorithmParameters::OctetKeyPair(p) if is_valid(p)));
        }
    }

    pub mod verify_signature {
        use super::*;

        #[apply(all_ec_keys)]
        #[wasm_bindgen_test]
        pub fn should_verify_ec(key: JwtEcKey) {
            let token = RustyJwtTools::generate_dpop_token(
                key.alg.into(),
                key.kp,
                Dpop::default(),
                BackendNonce::default(),
                ClientId::default(),
            )
            .unwrap();

            // validate token given raw public key
            let verify = match key.alg {
                JwsEcAlgorithm::P256 => ES256PublicKey::from_pem(&key.pk)
                    .unwrap()
                    .verify_token::<Dpop>(&token, None),
                JwsEcAlgorithm::P384 => ES384PublicKey::from_pem(&key.pk)
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
            let token = RustyJwtTools::generate_dpop_token(
                key.alg.into(),
                key.kp,
                Dpop::default(),
                BackendNonce::default(),
                ClientId::default(),
            )
            .unwrap();

            // validate token given raw public key
            let verify = match key.alg {
                JwsEdAlgorithm::Ed25519 => Ed25519PublicKey::from_pem(&key.pk)
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
        use std::time::Instant;

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_right_fields_naming(key: JwtKey) {
            let token = RustyJwtTools::generate_dpop_token(
                key.alg,
                key.kp,
                Dpop::default(),
                BackendNonce::default(),
                ClientId::default(),
            )
            .unwrap();
            let parts = token.split('.').collect::<Vec<&str>>();
            let claims = parts.get(1).unwrap();
            let claims = base64::decode(claims).unwrap();
            let claims = serde_json::from_slice::<serde_json::Value>(claims.as_slice()).unwrap();
            let claims = claims.as_object().unwrap();
            assert!(claims.get("jti").unwrap().as_str().is_some());
            assert!(claims.get("htm").unwrap().as_str().is_some());
            assert!(claims.get("nonce").unwrap().as_str().is_some());
            assert!(claims.get("chal").unwrap().as_str().is_some());
            assert!(claims.get("sub").unwrap().as_str().is_some());
            assert!(claims.get("iat").unwrap().as_u64().is_some());
            assert!(claims.get("exp").unwrap().as_u64().is_some());
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_jti(key: JwtKey) {
            let token = RustyJwtTools::generate_dpop_token(
                key.alg,
                key.kp.clone(),
                Dpop::default(),
                BackendNonce::default(),
                ClientId::default(),
            )
            .unwrap();
            let claims = key.claims(&token);
            assert!(claims.jwt_id.is_some());
            assert!(uuid::Uuid::try_parse(&claims.jwt_id.unwrap()).is_ok());
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_htm(key: JwtKey) {
            let dpop = Dpop {
                htm: Htm::Post,
                ..Default::default()
            };
            let token = RustyJwtTools::generate_dpop_token(
                key.alg,
                key.kp.clone(),
                dpop,
                BackendNonce::default(),
                ClientId::default(),
            )
            .unwrap();
            assert_eq!(key.claims(&token).custom.htm, Htm::Post);
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_htu(key: JwtKey) {
            let htu = Htu::try_from("https://wire.com").unwrap();
            let dpop = Dpop {
                htu: htu.clone(),
                ..Default::default()
            };
            let token = RustyJwtTools::generate_dpop_token(
                key.alg,
                key.kp.clone(),
                dpop,
                BackendNonce::default(),
                ClientId::default(),
            )
            .unwrap();
            assert_eq!(key.claims(&token).custom.htu, htu);
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_iat(key: JwtKey) {
            let token = RustyJwtTools::generate_dpop_token(
                key.alg,
                key.kp.clone(),
                Dpop::default(),
                BackendNonce::default(),
                ClientId::default(),
            )
            .unwrap();
            let claims = key.claims(&token);
            assert!(claims.issued_at.is_some());
            let iat = claims.issued_at.unwrap().as_secs();
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let leeway = 1;
            let range = (now - leeway)..=(now + leeway);
            assert!(range.contains(&iat));
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_exp(key: JwtKey) {
            let token = RustyJwtTools::generate_dpop_token(
                key.alg,
                key.kp.clone(),
                Dpop::default(),
                BackendNonce::default(),
                ClientId::default(),
            )
            .unwrap();
            let claims = key.claims(&token);
            assert!(claims.expires_at.is_some());
            let exp = claims.expires_at.unwrap().as_secs();
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let ttl = now + Duration::from_days(90).as_secs();
            let leeway = 1;
            let range = (ttl - leeway)..=(ttl + leeway);
            assert!(range.contains(&exp));
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_backend_nonce(key: JwtKey) {
            let nonce = BackendNonce::default();
            let token = RustyJwtTools::generate_dpop_token(
                key.alg,
                key.kp.clone(),
                Dpop::default(),
                nonce.clone(),
                ClientId::default(),
            )
            .unwrap();
            let claims = key.claims(&token);
            assert!(claims.nonce.is_some());
            let generated_nonce: BackendNonce = claims.nonce.unwrap().into();
            assert!(!generated_nonce.is_empty());
            assert_eq!(generated_nonce, nonce);
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_acme_challenge(key: JwtKey) {
            let challenge = AcmeChallenge::default();
            let dpop = Dpop {
                challenge: challenge.clone(),
                ..Default::default()
            };
            let token = RustyJwtTools::generate_dpop_token(
                key.alg,
                key.kp.clone(),
                dpop,
                BackendNonce::default(),
                ClientId::default(),
            )
            .unwrap();
            let claims = key.claims(&token);
            let generated_challenge: AcmeChallenge = claims.custom.challenge;
            assert!(!generated_challenge.is_empty());
            assert_eq!(generated_challenge, challenge);
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_client_id(key: JwtKey) {
            let client_id: ClientId = "URI:wireapp:SvPfLlwBQi-6oddVRrkqpw/04c7@example.com".to_string().into();
            let token = RustyJwtTools::generate_dpop_token(
                key.alg,
                key.kp.clone(),
                Dpop::default(),
                BackendNonce::default(),
                client_id.clone(),
            )
            .unwrap();
            let claims = key.claims(&token);
            assert!(claims.subject.is_some());
            assert_eq!(claims.subject.unwrap(), String::from(client_id))
        }
    }
}
