use jwt_simple::prelude::*;

use crate::{dpop::Dpop, prelude::*};

impl RustyJwtTools {
    /// Generates a DPoP JWT. Generally used on the client side.
    ///
    /// # Arguments
    ///
    /// * `dpop` - Claims of the DPoP JWT
    /// * `client_id` - unique user handle
    /// * `nonce` - nonce generated by wire-server
    /// * `audience` - the wire-dpop challenge URL
    /// * `expiry` - expiration. Once this duration has passed, the token is invalid
    /// * `alg` - Algorithm of the signing key [kp]
    /// * `kp` - Signing key PEM encoded
    pub fn generate_dpop_token(
        dpop: Dpop,
        client_id: &ClientId,
        nonce: BackendNonce,
        audience: url::Url,
        expiry: core::time::Duration,
        alg: JwsAlgorithm,
        kp: &Pem,
    ) -> RustyJwtResult<String> {
        // TODO: is it up to us to validate the 'client_id' format or is it opaque to us ?
        let header = Self::new_dpop_header(alg);
        let claims = dpop.into_jwt_claims(nonce, client_id, expiry, audience);
        Self::generate_jwt(alg, header, Some(claims), kp, true)
    }

    fn new_dpop_header(alg: JwsAlgorithm) -> JWTHeader {
        JWTHeader {
            algorithm: alg.to_string(),
            signature_type: Some(Dpop::TYP.to_string()),
            ..Default::default()
        }
    }
}

#[cfg(test)]
pub mod tests {
    use fluvio_wasm_timer::{SystemTime, UNIX_EPOCH};
    use wasm_bindgen_test::*;

    use crate::{dpop::*, jwk::RustyJwk, jwk::TryFromJwk, test_utils::*};
    use base64::Engine;
    use serde_json::{json, Value};

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod headers {
        use super::*;

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_dpop_typ(key: JwtKey) {
            let token = RustyJwtTools::generate_dpop_token(
                Dpop::default(),
                &ClientId::default(),
                BackendNonce::default(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg,
                &key.kp,
            )
            .unwrap();
            let header = Token::decode_metadata(token.as_str()).unwrap();
            assert_eq!(header.signature_type(), Some(Dpop::TYP))
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_alg(key: JwtKey) {
            let token = RustyJwtTools::generate_dpop_token(
                Dpop::default(),
                &ClientId::default(),
                BackendNonce::default(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg,
                &key.kp,
            )
            .unwrap();
            let header = Token::decode_metadata(token.as_str()).unwrap();
            assert_eq!(header.algorithm(), key.alg.to_string())
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_right_fields_naming(key: JwtKey) {
            let token = RustyJwtTools::generate_dpop_token(
                Dpop::default(),
                &ClientId::default(),
                BackendNonce::default(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg,
                &key.kp,
            )
            .unwrap();
            let fields = jwt_header(token);
            assert!(fields.get("typ").unwrap().as_str().is_some());
            assert!(fields.get("alg").unwrap().as_str().is_some());
            let jwk = fields.get("jwk").unwrap().as_object().unwrap();
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
                Dpop::default(),
                &ClientId::default(),
                BackendNonce::default(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg.into(),
                &key.kp,
            )
            .unwrap();
            let header = Token::decode_metadata(token.as_str()).unwrap();
            let jwk = header.public_key().unwrap();
            let is_valid = |p: &EllipticCurveKeyParameters| {
                let (kty, curve, jwk_pk) = match key.alg {
                    JwsEcAlgorithm::P256 => {
                        let kty = EllipticCurveKeyType::EC;
                        let curve = EllipticCurve::P256;
                        let pk_pem = ES256PublicKey::try_from_jwk(jwk).unwrap().to_pem().unwrap();
                        (kty, curve, pk_pem)
                    }
                    JwsEcAlgorithm::P384 => {
                        let kty = EllipticCurveKeyType::EC;
                        let curve = EllipticCurve::P384;
                        let pk_pem = ES384PublicKey::try_from_jwk(jwk).unwrap().to_pem().unwrap();
                        (kty, curve, pk_pem)
                    }
                };
                p.key_type == kty && p.curve == curve && key.pk == jwk_pk.into()
            };
            assert!(matches!(&jwk.algorithm, AlgorithmParameters::EllipticCurve(p) if is_valid(p)));
        }

        #[apply(all_ed_keys)]
        #[wasm_bindgen_test]
        pub fn should_have_ed25519_jwk(key: JwtEdKey) {
            let token = RustyJwtTools::generate_dpop_token(
                Dpop::default(),
                &ClientId::default(),
                BackendNonce::default(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg.into(),
                &key.kp,
            )
            .unwrap();
            let header = Token::decode_metadata(token.as_str()).unwrap();
            let jwk = header.public_key().unwrap();
            let is_valid = |p: &OctetKeyPairParameters| {
                let (kty, curve, jwk_pk) = match key.alg {
                    JwsEdAlgorithm::Ed25519 => {
                        let kty = OctetKeyPairType::OctetKeyPair;
                        let curve = EdwardCurve::Ed25519;
                        let pk_pem = Ed25519PublicKey::try_from_jwk(jwk).unwrap().to_pem();
                        (kty, curve, pk_pem)
                    }
                };
                p.key_type == kty && p.curve == curve && key.pk == jwk_pk.into()
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
                Dpop::default(),
                &ClientId::default(),
                BackendNonce::default(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg.into(),
                &key.kp,
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
                    JwsEcAlgorithm::P256 => ES256PublicKey::try_from_jwk(j)
                        .unwrap()
                        .verify_token::<Dpop>(&token, None),
                    JwsEcAlgorithm::P384 => ES384PublicKey::try_from_jwk(j)
                        .unwrap()
                        .verify_token::<Dpop>(&token, None),
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
                Dpop::default(),
                &ClientId::default(),
                BackendNonce::default(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg.into(),
                &key.kp,
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
                    JwsEdAlgorithm::Ed25519 => Ed25519PublicKey::try_from_jwk(j)
                        .unwrap()
                        .verify_token::<Dpop>(&token, None),
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
        fn should_have_right_fields_naming(key: JwtKey) {
            let token = RustyJwtTools::generate_dpop_token(
                Dpop::default(),
                &ClientId::default(),
                BackendNonce::default(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg,
                &key.kp,
            )
            .unwrap();
            let claims = jwt_claims(token);
            assert!(claims.get("jti").unwrap().as_str().is_some());
            assert!(claims.get("htm").unwrap().as_str().is_some());
            assert!(claims.get("htu").unwrap().as_str().is_some());
            assert!(claims.get("nonce").unwrap().as_str().is_some());
            assert!(claims.get("chal").unwrap().as_str().is_some());
            assert!(claims.get("handle").unwrap().as_str().is_some());
            assert!(claims.get("team").unwrap().as_str().is_some());
            assert!(claims.get("name").unwrap().as_str().is_some());
            assert!(claims.get("sub").unwrap().as_str().is_some());
            assert!(claims.get("iat").unwrap().as_u64().is_some());
            assert!(claims.get("exp").unwrap().as_u64().is_some());
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_jti(key: JwtKey) {
            let token = RustyJwtTools::generate_dpop_token(
                Dpop::default(),
                &ClientId::default(),
                BackendNonce::default(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg,
                &key.kp,
            )
            .unwrap();
            let claims = key.claims::<Dpop>(&token);
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
                dpop,
                &ClientId::default(),
                BackendNonce::default(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg,
                &key.kp,
            )
            .unwrap();
            assert_eq!(key.claims::<Dpop>(&token).custom.htm, Htm::Post);
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
                dpop,
                &ClientId::default(),
                BackendNonce::default(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg,
                &key.kp,
            )
            .unwrap();
            assert_eq!(key.claims::<Dpop>(&token).custom.htu, htu);
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_iat_slightly_in_past(key: JwtKey) {
            // we want "nbf" slightly in the past to prevent clock drifts or problems non-monotonic hosts
            let token = RustyJwtTools::generate_dpop_token(
                Dpop::default(),
                &ClientId::default(),
                BackendNonce::default(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg,
                &key.kp,
            )
            .unwrap();
            let claims = key.claims::<Dpop>(&token);
            assert!(claims.issued_at.is_some());
            let iat = claims.issued_at.unwrap().as_secs();

            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let leeway = Dpop::NOW_LEEWAY_SECONDS;

            let test_leeway = 2;
            assert!(iat <= (now - leeway) + test_leeway);
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_nbf_slightly_in_past(key: JwtKey) {
            // we want "nbf" slightly in the past to prevent clock drifts or problems non-monotonic hosts
            let token = RustyJwtTools::generate_dpop_token(
                Dpop::default(),
                &ClientId::default(),
                BackendNonce::default(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg,
                &key.kp,
            )
            .unwrap();
            let claims = key.claims::<Dpop>(&token);
            assert!(claims.invalid_before.is_some());
            let nbf = claims.invalid_before.unwrap().as_secs();

            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let leeway = Dpop::NOW_LEEWAY_SECONDS;

            let test_leeway = 2;
            assert!(nbf <= (now - leeway) + test_leeway);
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_exp(key: JwtKey) {
            let expiry = Duration::from_days(90).into();
            let token = RustyJwtTools::generate_dpop_token(
                Dpop::default(),
                &ClientId::default(),
                BackendNonce::default(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                expiry,
                key.alg,
                &key.kp,
            )
            .unwrap();
            let claims = key.claims::<Dpop>(&token);
            assert!(claims.expires_at.is_some());
            let exp = claims.expires_at.unwrap().as_secs();
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let ttl = now + expiry.as_secs();
            let leeway = 1;
            let range = (ttl - leeway)..=(ttl + leeway);
            assert!(range.contains(&exp));
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_backend_nonce(key: JwtKey) {
            let nonce = BackendNonce::default();
            let token = RustyJwtTools::generate_dpop_token(
                Dpop::default(),
                &ClientId::default(),
                nonce.clone(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg,
                &key.kp,
            )
            .unwrap();
            let claims = key.claims::<Dpop>(&token);
            assert!(claims.nonce.is_some());
            let generated_nonce: BackendNonce = claims.nonce.unwrap().into();
            assert!(!generated_nonce.is_empty());
            assert_eq!(generated_nonce, nonce);
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_handle(key: JwtKey) {
            let handle = Handle::from("beltram_wire").try_to_qualified("wire.com").unwrap();
            let token = RustyJwtTools::generate_dpop_token(
                Dpop {
                    handle: handle.clone(),
                    ..Default::default()
                },
                &ClientId::default(),
                BackendNonce::default().clone(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg,
                &key.kp,
            )
            .unwrap();
            let claims = key.claims::<Dpop>(&token);
            assert_eq!(claims.custom.handle, handle);
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_display_name(key: JwtKey) {
            let display_name = "John Doe";
            let token = RustyJwtTools::generate_dpop_token(
                Dpop {
                    display_name: display_name.to_string(),
                    ..Default::default()
                },
                &ClientId::default(),
                BackendNonce::default().clone(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg,
                &key.kp,
            )
            .unwrap();
            let claims = key.claims::<Dpop>(&token);
            assert_eq!(&claims.custom.display_name, display_name);
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_team(key: JwtKey) {
            let team = "wire";
            let token = RustyJwtTools::generate_dpop_token(
                Dpop {
                    team: team.into(),
                    ..Default::default()
                },
                &ClientId::default(),
                BackendNonce::default().clone(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg,
                &key.kp,
            )
            .unwrap();
            let claims = key.claims::<Dpop>(&token);
            assert_eq!(claims.custom.team.as_ref().unwrap().as_str(), team.to_string());
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_acme_challenge(key: JwtKey) {
            let challenge = AcmeNonce::default();
            let dpop = Dpop {
                challenge: challenge.clone(),
                ..Default::default()
            };
            let token = RustyJwtTools::generate_dpop_token(
                dpop,
                &ClientId::default(),
                BackendNonce::default(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg,
                &key.kp,
            )
            .unwrap();
            let claims = key.claims::<Dpop>(&token);
            let generated_challenge: AcmeNonce = claims.custom.challenge;
            assert!(!generated_challenge.is_empty());
            assert_eq!(generated_challenge, challenge);
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_client_id(key: JwtKey) {
            let client_id = ClientId::try_new(ClientId::DEFAULT_USER.to_string(), 1223, "example.com").unwrap();
            let token = RustyJwtTools::generate_dpop_token(
                Dpop::default(),
                &client_id,
                BackendNonce::default(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg,
                &key.kp,
            )
            .unwrap();
            let claims = key.claims::<Dpop>(&token);
            assert!(claims.subject.is_some());
            assert_eq!(claims.subject.unwrap(), client_id.to_uri())
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_extra_claims(key: JwtKey) {
            let extra_claims = json!({
                "string": "string",
                "number": 42,
                "array": ["a", "b"],
                "obj": { "a": "b" },
            });
            let dpop = Dpop {
                extra_claims: Some(extra_claims),
                ..Default::default()
            };
            let token = RustyJwtTools::generate_dpop_token(
                dpop,
                &ClientId::default(),
                BackendNonce::default(),
                "https://stepca/acme/wire/challenge/aaa/bbb".parse().unwrap(),
                Duration::from_days(1).into(),
                key.alg,
                &key.kp,
            )
            .unwrap();
            let parts = token.split('.').collect::<Vec<&str>>();
            let claims = parts.get(1).unwrap();
            let claims = base64::prelude::BASE64_STANDARD_NO_PAD.decode(claims).unwrap();
            let claims = serde_json::from_slice::<Value>(claims.as_slice()).unwrap();
            let claims = claims.as_object().unwrap();
            assert_eq!(claims.get("string").unwrap().as_str(), Some("string"));
            assert_eq!(claims.get("number").unwrap().as_u64(), Some(42));
            assert_eq!(
                claims.get("array").unwrap().as_array(),
                Some(&vec![json!("a"), json!("b")])
            );
            assert_eq!(claims.get("obj").unwrap().as_object(), json!({"a": "b"}).as_object());
        }
    }
}
