use jwt_simple::{prelude::*, token::Token};
use serde_json::Value;

use crate::jkt::JktConfirmation;
use crate::jwk::TryIntoJwk;
use crate::{
    access::Access,
    dpop::{VerifyDpop, VerifyDpopTokenHeader},
    prelude::*,
};

impl RustyJwtTools {
    /// Validate the provided [dpop_proof] DPoP proof JWT from the client, and if valid, return an
    /// introspectable DPoP access token.
    ///
    /// Verifications:
    /// * [dpop_proof] has the correct syntax
    /// * `typ` header field is "dpop+jwt"
    /// * signature algorithm (alg) in JWT header is a supported algorithm
    /// * signature corresponds to the public key (jwk) in the JWT header
    /// * [client_id] corresponds to the (sub) claim expressed as URI
    /// * [backend_nonce] corresponds to the (nonce) claim encoded as base64url.
    /// * [uri] corresponds to the (htu) claim.
    /// * [method] corresponds to the (htm) claim.
    /// * `jti` claim is present
    /// * `chal` claim is present
    /// * `iat` claim is present and no earlier or later than max_skew_secs seconds of now
    /// * `exp` claim is present and no larger (later) than max_expiration.
    /// * `exp` claim is no later than now plus max_skew_secs.
    ///
    /// # Arguments
    /// * `dpop_proof` - JWS Compact Serialization format. Note that the proof consists of three runs
    /// of base64url characters (header, claims, signature) separated by period characters.
    /// ex: b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" (whitespace in the example is not included in the actual proof)
    /// * `client_id` - see [QualifiedClientId]
    /// * `backend_nonce` - The most recent DPoP nonce provided by the backend to the current client ex: hex!("b62551e728771515234fac0b04b2008d")
    /// * `uri` - The HTTPS URI on the backend for the DPoP auth token endpoint ex: "https://wire.example.com/clients/authtoken"
    /// * `method` - The HTTPS method used on the backend for the DPoP auth token endpoint ex: b"POST"
    /// * `max_skew_secs` - The maximum number of seconds of clock skew the implementation will allow ex: 360 (5 min)
    /// * `max_expiration` - The maximal expiration date and time, in seconds since epoch ex: 1668987368
    /// * `now` - Current time in seconds since epoch ex: 1661211368
    /// * `backend_keys` - PEM format concatenated private key and public key of the Wire backend
    #[allow(clippy::too_many_arguments)]
    pub fn generate_access_token(
        dpop_proof: &str,
        client_id: QualifiedClientId,
        backend_nonce: BackendNonce,
        uri: Htu,
        method: Htm,
        max_skew_secs: u16,
        max_expiration: u64,
        backend_keys: Pem,
        hash_algorithm: HashAlgorithm,
    ) -> RustyJwtResult<String> {
        let header = Token::decode_metadata(dpop_proof)?;
        let (alg, jwk) = header.verify_dpop_header()?;
        let proof_claims = dpop_proof.verify_client_dpop(
            alg,
            jwk,
            client_id,
            &backend_nonce,
            None,
            Some(method),
            &uri,
            max_expiration,
            max_skew_secs,
        )?;
        Self::access_token(
            alg,
            dpop_proof,
            proof_claims,
            backend_keys,
            client_id,
            backend_nonce,
            hash_algorithm,
        )
    }

    fn access_token(
        alg: JwsAlgorithm,
        proof: &str,
        proof_claims: JWTClaims<Dpop>,
        backend_keys: Pem,
        client_id: QualifiedClientId,
        nonce: BackendNonce,
        hash: HashAlgorithm,
    ) -> RustyJwtResult<String> {
        let header = Self::new_access_header(alg);

        let with_jwk = |jwk: Jwk| KeyMetadata::default().with_public_key(jwk);
        // build claims given the JWK thumbprint which requires knowing the algorithm and being in
        // a branch. This simply factorizes this piece of code
        let claims = |cnf: JktConfirmation| {
            // TODO: should be acme server authorization URI but wait for final decision
            let audience = proof_claims.custom.htu.clone();
            Access {
                challenge: proof_claims.custom.challenge,
                cnf,
                proof: proof.to_string(),
                client_id: client_id.to_subject(),
                api_version: Access::WIRE_SERVER_API_VERSION,
                scope: Access::DEFAULT_SCOPE.to_string(),
                extra_claims: proof_claims.custom.extra_claims,
            }
            .into_jwt_claims(client_id, nonce, proof_claims.custom.htu, audience)
        };
        Ok(match alg {
            JwsAlgorithm::P256 => {
                let mut kp = ES256KeyPair::from_pem(backend_keys.as_str())
                    .map_err(|_| RustyJwtError::InvalidBackendKeys("Invalid ES256 key pair"))?;
                let jwk = kp.public_key().try_into_jwk()?;
                let cnf = JktConfirmation::generate(&jwk, hash)?;
                kp.attach_metadata(with_jwk(jwk))?;
                kp.sign_with_header(claims(cnf), header)?
            }
            JwsAlgorithm::P384 => {
                let mut kp = ES384KeyPair::from_pem(backend_keys.as_str())
                    .map_err(|_| RustyJwtError::InvalidBackendKeys("Invalid ES384 key pair"))?;
                let jwk = kp.public_key().try_into_jwk()?;
                let cnf = JktConfirmation::generate(&jwk, hash)?;
                kp.attach_metadata(with_jwk(jwk))?;
                kp.sign_with_header(claims(cnf), header)?
            }
            JwsAlgorithm::Ed25519 => {
                let mut kp = Ed25519KeyPair::from_pem(backend_keys.as_str())
                    .map_err(|_| RustyJwtError::InvalidBackendKeys("Invalid ED25519 key pair"))?;
                let jwk = kp.public_key().try_into_jwk()?;
                let cnf = JktConfirmation::generate(&jwk, hash)?;
                kp.attach_metadata(with_jwk(jwk))?;
                kp.sign_with_header(claims(cnf), header)?
            }
        })
    }

    fn new_access_header(alg: JwsAlgorithm) -> JWTHeader {
        let mut header = JWTHeader::default();
        header.algorithm = alg.to_string();
        header.signature_type = Some(Access::TYP.to_string());
        header
    }
}

#[cfg(test)]
mod tests {
    use jwt_simple::prelude::*;
    use serde_json::{json, Value};

    use crate::{dpop::Dpop, jwk::TryFromJwk, test_utils::*};

    use super::*;

    mod generated_access_token {
        use super::*;

        mod header {
            use super::*;

            #[apply(all_ciphersuites)]
            #[test]
            fn header_should_have_jwt_typ(ciphersuite: Ciphersuite) {
                let token = access_token(ciphersuite.into()).unwrap();
                let header = Token::decode_metadata(token.as_str()).unwrap();
                assert_eq!(header.signature_type(), Some(Access::TYP))
            }

            #[apply(all_ciphersuites)]
            #[test]
            fn header_should_have_alg(ciphersuite: Ciphersuite) {
                let token = access_token(ciphersuite.clone().into()).unwrap();
                let header = Token::decode_metadata(token.as_str()).unwrap();
                assert_eq!(header.algorithm(), ciphersuite.key.alg.to_string())
            }

            #[apply(all_ciphersuites)]
            #[test]
            fn header_should_have_right_fields_naming(ciphersuite: Ciphersuite) {
                let token = access_token(ciphersuite.clone().into()).unwrap();
                let fields = jwt_header(token);
                assert!(fields.get("typ").unwrap().as_str().is_some());
                assert!(fields.get("alg").unwrap().as_str().is_some());
                let jwk = fields.get("jwk").unwrap().as_object().unwrap();
                assert!(jwk.get("kty").unwrap().as_str().is_some());
                assert!(jwk.get("crv").unwrap().as_str().is_some());
                assert!(jwk.get("x").unwrap().as_str().is_some());
                if let JwsAlgorithm::P256 | JwsAlgorithm::P384 = ciphersuite.key.alg {
                    assert!(jwk.get("y").unwrap().as_str().is_some());
                } else {
                    assert!(jwk.get("y").is_none());
                }
            }
        }

        mod jwk {
            use super::*;

            #[apply(all_ec_keys)]
            #[test]
            fn should_have_ec_jwk(key: JwtEcKey) {
                let params = Params::from(Ciphersuite {
                    key: JwtKey::from(key.clone()),
                    hash: HashAlgorithm::SHA256,
                });
                let backend_kp = params.backend_keys.clone();
                let token = access_token(params).unwrap();

                let header = Token::decode_metadata(token.as_str()).unwrap();
                let jwk = header.public_key().unwrap();
                let is_valid = |p: &EllipticCurveKeyParameters| {
                    let (kty, curve, jwk_pk, signing_pk) = match key.alg {
                        JwsEcAlgorithm::P256 => {
                            let kty = EllipticCurveKeyType::EC;
                            let curve = EllipticCurve::P256;
                            let pk_pem = ES256PublicKey::try_from_jwk(jwk).unwrap().to_pem().unwrap();
                            let signing_key_pem = ES256KeyPair::from_pem(backend_kp.as_str())
                                .unwrap()
                                .public_key()
                                .to_pem()
                                .unwrap();
                            (kty, curve, pk_pem, signing_key_pem)
                        }
                        JwsEcAlgorithm::P384 => {
                            let kty = EllipticCurveKeyType::EC;
                            let curve = EllipticCurve::P384;
                            let pk_pem = ES384PublicKey::try_from_jwk(jwk).unwrap().to_pem().unwrap();
                            let signing_key_pem = ES384KeyPair::from_pem(backend_kp.as_str())
                                .unwrap()
                                .public_key()
                                .to_pem()
                                .unwrap();
                            (kty, curve, pk_pem, signing_key_pem)
                        }
                    };
                    p.key_type == kty && p.curve == curve && jwk_pk == signing_pk
                };
                assert!(matches!(&jwk.algorithm, AlgorithmParameters::EllipticCurve(p) if is_valid(p)));
            }

            #[apply(all_ed_keys)]
            #[test]
            fn should_have_ed25519_jwk(key: JwtEdKey) {
                let params = Params::from(Ciphersuite {
                    #[allow(clippy::redundant_clone)]
                    key: JwtKey::from(key.clone()),
                    hash: HashAlgorithm::SHA256,
                });
                let backend_kp = params.backend_keys.clone();
                let token = access_token(params).unwrap();

                let header = Token::decode_metadata(token.as_str()).unwrap();
                let jwk = header.public_key().unwrap();
                let is_valid = |p: &OctetKeyPairParameters| {
                    let (kty, curve, jwk_pk, signing_pk) = match key.alg {
                        JwsEdAlgorithm::Ed25519 => {
                            let kty = OctetKeyPairType::OctetKeyPair;
                            let curve = EdwardCurve::Ed25519;
                            let pk_pem = Ed25519PublicKey::try_from_jwk(jwk).unwrap().to_pem();
                            let signing_key_pem = Ed25519KeyPair::from_pem(backend_kp.as_str())
                                .unwrap()
                                .public_key()
                                .to_pem();
                            (kty, curve, pk_pem, signing_key_pem)
                        }
                    };
                    p.key_type == kty && p.curve == curve && signing_pk == jwk_pk
                };
                assert!(matches!(&jwk.algorithm, AlgorithmParameters::OctetKeyPair(p) if is_valid(p)));
            }

            #[apply(all_ciphersuites)]
            #[test]
            fn should_have_valid_jwk_thumbprint(ciphersuite: Ciphersuite) {
                let params = Params::from(ciphersuite.clone());
                let backend_key = params.backend_keys.clone();
                let token = access_token(params).unwrap();

                let header = Token::decode_metadata(token.as_str()).unwrap();
                let jwk = header.public_key().unwrap();

                let backend_key = JwtKey::from((ciphersuite.key.alg, backend_key));
                let claims = backend_key.claims::<Access>(&token);

                let expected_cnf = JktConfirmation::generate(jwk, ciphersuite.hash).unwrap();
                assert_eq!(claims.custom.cnf, expected_cnf);
            }
        }

        mod claims {
            use super::*;

            #[apply(all_ciphersuites)]
            #[test]
            fn should_have_dpop_token_as_proof(ciphersuite: Ciphersuite) {
                let challenge = AcmeChallenge::rand();
                let dpop = DpopBuilder::from(ciphersuite.key.clone()).build();
                let params = Params::from(ciphersuite.clone());
                let backend_key = params.backend_keys.clone();

                let token = access_token_with_dpop(&dpop, params).unwrap();

                let backend_key = JwtKey::from((ciphersuite.key.alg, backend_key));
                let claims = backend_key.claims::<Access>(&token);
                assert_eq!(claims.custom.proof, dpop);
            }

            #[apply(all_ciphersuites)]
            #[test]
            fn should_have_iss_as_proofs_htu(ciphersuite: Ciphersuite) {
                // should contain a 'iss' claim that is equal to dpop 'htu' claim
                let issuer = "https://a.com/";
                let dpop = DpopBuilder {
                    dpop: TestDpop {
                        htu: Some(issuer.try_into().unwrap()),
                        ..Default::default()
                    },
                    ..ciphersuite.key.clone().into()
                }
                .build();
                let params = Params {
                    uri: issuer.try_into().unwrap(),
                    ..ciphersuite.clone().into()
                };
                let backend_key = params.backend_keys.clone();

                let token = access_token_with_dpop(&dpop, params).unwrap();

                let backend_key = JwtKey::from((ciphersuite.key.alg, backend_key));
                let claims = backend_key.claims::<Access>(&token);
                assert_eq!(claims.issuer.unwrap().as_str(), issuer);
            }

            #[apply(all_ciphersuites)]
            #[test]
            fn should_have_dpop_challenge(ciphersuite: Ciphersuite) {
                let challenge = AcmeChallenge::rand();
                let dpop = DpopBuilder {
                    dpop: TestDpop {
                        challenge: Some(challenge.clone()),
                        ..Default::default()
                    },
                    ..ciphersuite.key.clone().into()
                };
                let params = Params::from(ciphersuite.clone());
                let backend_key = params.backend_keys.clone();
                let token = access_token_with_dpop(&dpop.build(), params).unwrap();

                let backend_key = JwtKey::from((ciphersuite.key.alg, backend_key));
                let claims = backend_key.claims::<Access>(&token);
                assert_eq!(claims.custom.challenge, challenge);
            }

            #[apply(all_ciphersuites)]
            #[test]
            fn should_have_sub_and_client_id(ciphersuite: Ciphersuite) {
                let sub = QualifiedClientId::alice();
                let dpop = DpopBuilder {
                    sub: Some(sub),
                    ..ciphersuite.key.clone().into()
                };
                let params: Params = Params {
                    client_id: sub,
                    ..ciphersuite.clone().into()
                };
                let backend_key = params.backend_keys.clone();
                let token = access_token_with_dpop(&dpop.build(), params).unwrap();

                let backend_key = JwtKey::from((ciphersuite.key.alg, backend_key));
                let claims = backend_key.claims::<Access>(&token);
                assert_eq!(claims.subject, Some(sub.to_subject()));
                assert_eq!(claims.custom.client_id, sub.to_subject());
            }

            #[apply(all_ciphersuites)]
            #[test]
            fn should_have_jti(ciphersuite: Ciphersuite) {
                let params = Params::from(ciphersuite.clone());
                let backend_key = params.backend_keys.clone();
                let token = access_token(params).unwrap();

                let backend_key = JwtKey::from((ciphersuite.key.alg, backend_key));
                let claims = backend_key.claims::<Access>(&token);
                assert!(claims.jwt_id.is_some());
                assert!(uuid::Uuid::try_parse(&claims.jwt_id.unwrap()).is_ok());
            }

            #[apply(all_ciphersuites)]
            #[test]
            fn should_have_api_version(ciphersuite: Ciphersuite) {
                let params = Params::from(ciphersuite.clone());
                let backend_key = params.backend_keys.clone();
                let token = access_token(params).unwrap();

                let backend_key = JwtKey::from((ciphersuite.key.alg, backend_key));
                let claims = backend_key.claims::<Access>(&token);
                assert_eq!(claims.custom.api_version, Access::WIRE_SERVER_API_VERSION);
            }

            #[apply(all_ciphersuites)]
            #[test]
            fn should_have_scope(ciphersuite: Ciphersuite) {
                let params = Params::from(ciphersuite.clone());
                let backend_key = params.backend_keys.clone();
                let token = access_token(params).unwrap();

                let backend_key = JwtKey::from((ciphersuite.key.alg, backend_key));
                let claims = backend_key.claims::<Access>(&token);
                assert_eq!(claims.custom.scope, Access::DEFAULT_SCOPE);
            }

            #[apply(all_ciphersuites)]
            #[test]
            fn should_have_backend_nonce(ciphersuite: Ciphersuite) {
                let nonce = BackendNonce::rand();
                let dpop = DpopBuilder {
                    nonce: Some(nonce.clone()),
                    ..ciphersuite.key.clone().into()
                };
                let params = Params {
                    backend_nonce: nonce.clone(),
                    ..ciphersuite.clone().into()
                };
                let backend_key = params.backend_keys.clone();
                let token = access_token_with_dpop(&dpop.build(), params).unwrap();

                let backend_key = JwtKey::from((ciphersuite.key.alg, backend_key));
                let claims = backend_key.claims::<Access>(&token);
                assert_eq!(claims.nonce, Some(nonce.to_string()));
            }

            #[apply(all_ciphersuites)]
            #[test]
            fn should_have_dpop_extra_claims(ciphersuite: Ciphersuite) {
                let extra = json!({"extra": "some"});
                let dpop = DpopBuilder {
                    dpop: TestDpop {
                        extra_claims: Some(extra),
                        ..Default::default()
                    },
                    ..ciphersuite.key.clone().into()
                };
                let params = Params::from(ciphersuite);
                let token = access_token_with_dpop(&dpop.build(), params).unwrap();

                let parts = token.split('.').collect::<Vec<&str>>();
                let claims = parts.get(1).unwrap();
                let claims = base64::decode(claims).unwrap();
                let claims = serde_json::from_slice::<Value>(claims.as_slice()).unwrap();
                let claims = claims.as_object().unwrap();

                assert_eq!(claims.get("extra").unwrap().as_str(), Some("some"));
            }

            #[apply(all_ciphersuites)]
            #[test]
            fn should_have_right_fields_naming(ciphersuite: Ciphersuite) {
                let params = Params::from(ciphersuite);
                let token = access_token(params).unwrap();
                let claims = jwt_claims(token);

                assert!(claims.get("proof").unwrap().as_str().is_some());
                assert!(claims.get("client_id").unwrap().as_str().is_some());
                assert!(claims.get("iss").unwrap().as_str().is_some());
                assert!(claims.get("sub").unwrap().as_str().is_some());
                assert!(claims.get("aud").unwrap().as_str().is_some());
                assert!(claims.get("scope").unwrap().as_str().is_some());
                assert!(claims.get("api_version").unwrap().as_u64().is_some());
                assert!(claims.get("jti").unwrap().as_str().is_some());
                assert!(claims.get("nonce").unwrap().as_str().is_some());
                assert!(claims.get("chal").unwrap().as_str().is_some());
                assert!(claims.get("iat").unwrap().as_u64().is_some());
                assert!(claims.get("exp").unwrap().as_u64().is_some());
                let cnf = claims.get("cnf").unwrap().as_object().unwrap();
                assert!(cnf.get("jkt").unwrap().as_str().is_some());
            }
        }
    }

    mod backend_keys {
        use super::*;

        #[apply(all_ciphersuites)]
        #[test]
        fn should_sign_access_token(ciphersuite: Ciphersuite) {
            let params = Params::from(ciphersuite.clone());
            let backend_keys = params.backend_keys.clone();
            let access_token = access_token(params).unwrap();
            let verify = match ciphersuite.key.alg {
                JwsAlgorithm::P256 => ES256KeyPair::from_pem(backend_keys.as_str())
                    .unwrap()
                    .public_key()
                    .verify_token::<NoCustomClaims>(&access_token, None),
                JwsAlgorithm::P384 => ES384KeyPair::from_pem(backend_keys.as_str())
                    .unwrap()
                    .public_key()
                    .verify_token::<NoCustomClaims>(&access_token, None),
                JwsAlgorithm::Ed25519 => Ed25519KeyPair::from_pem(backend_keys.as_str())
                    .unwrap()
                    .public_key()
                    .verify_token::<NoCustomClaims>(&access_token, None),
            };
            assert!(verify.is_ok());
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn should_fail_when_invalid(ciphersuite: Ciphersuite) {
            let params = Params {
                backend_keys: rand_str(30).into(),
                ..ciphersuite.clone().into()
            };
            let result = access_token(params);
            let reason = match ciphersuite.key.alg {
                JwsAlgorithm::P256 => "Invalid ES256 key pair",
                JwsAlgorithm::P384 => "Invalid ES384 key pair",
                JwsAlgorithm::Ed25519 => "Invalid ED25519 key pair",
            };
            assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidBackendKeys(r) if r == reason));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn should_fail_when_not_same_alg_as_jwk(ciphersuite: Ciphersuite) {
            // will use an algorithm for signing DPoP proof and another one for `backend_keys`
            for reverse_key in ciphersuite.key.reverse_algorithms().map(JwtKey::new_key) {
                let dpop = DpopBuilder::from(ciphersuite.key.clone());
                let params = Params::from(Ciphersuite {
                    key: reverse_key,
                    ..ciphersuite
                });
                let result = access_token_with_dpop(&dpop.build(), params);
                assert!(result.is_err());
            }
        }
    }

    mod validate_dpop {
        use super::*;

        #[apply(all_ciphersuites)]
        #[test]
        fn typ(ciphersuite: Ciphersuite) {
            // should fail when 'typ' header absent
            let dpop = DpopBuilder {
                typ: None,
                ..ciphersuite.key.clone().into()
            };
            let params = ciphersuite.clone().into();
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingDpopHeader(header) if header == "typ"));

            // should fail when wrong value
            let dpop = DpopBuilder {
                typ: Some("unknown+jwt"),
                ..ciphersuite.key.clone().into()
            };
            let params = ciphersuite.clone().into();
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidDpopTyp));

            // should be valid
            let dpop = DpopBuilder {
                typ: Some("dpop+jwt"),
                ..ciphersuite.key.clone().into()
            };
            let params = ciphersuite.into();
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn alg(ciphersuite: Ciphersuite) {
            // should fail when 'alg' is not supported
            for alg in JwsAlgorithm::UNSUPPORTED {
                let dpop = DpopBuilder {
                    alg: alg.to_string(),
                    ..ciphersuite.key.clone().into()
                };
                let params = ciphersuite.clone().into();
                let result = access_token_with_dpop(&dpop.build(), params);
                assert!(matches!(result.unwrap_err(), RustyJwtError::UnsupportedAlgorithm));
            }

            // should be valid
            let dpop = DpopBuilder {
                alg: ciphersuite.key.alg.to_string(),
                ..ciphersuite.key.clone().into()
            };
            let params = ciphersuite.into();
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn jwk(ciphersuite: Ciphersuite) {
            // should fail when 'jwk' header absent
            let dpop = DpopBuilder {
                jwk: None,
                ..ciphersuite.key.clone().into()
            };
            let params = ciphersuite.clone().into();
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingDpopHeader(header) if header == "jwk"));

            // should be valid
            let params = ciphersuite.into();
            let result = access_token(params);
            assert!(result.is_ok());
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn jwk_and_alg(ciphersuite: Ciphersuite) {
            // should fail when 'jwk' is not of the 'alg' type
            for alg in ciphersuite.key.reverse_algorithms() {
                let dpop = DpopBuilder {
                    alg: alg.to_string(),
                    ..ciphersuite.key.clone().into()
                };
                let params = ciphersuite.clone().into();
                let result = access_token_with_dpop(&dpop.build(), params);
                assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidDpopJwk));
            }
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn signature(ciphersuite: Ciphersuite) {
            // should succeed with valid signature
            let params = ciphersuite.clone().into();
            let result = access_token(params);
            assert!(result.is_ok());

            // should fail when signature not verified by jwk
            let other_jwk = DpopBuilder::from(JwtKey::new_key(ciphersuite.key.alg)).jwk.unwrap();
            // dpop is signed with the former key
            let dpop = DpopBuilder {
                jwk: Some(other_jwk),
                ..ciphersuite.key.clone().into()
            };
            let params = ciphersuite.into();
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidToken(_)));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn sub(ciphersuite: Ciphersuite) {
            // should succeed when client_id and JWT's 'sub' match
            let dpop = DpopBuilder {
                sub: Some(QualifiedClientId::alice()),
                ..ciphersuite.key.clone().into()
            };
            let params = Params {
                client_id: QualifiedClientId::alice(),
                ..ciphersuite.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());

            // JWT's 'sub' is absent
            let dpop = DpopBuilder {
                sub: None,
                ..ciphersuite.key.clone().into()
            };
            let params = Params {
                client_id: QualifiedClientId::bob(),
                ..ciphersuite.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "sub"));

            // should fail when client_id and JWT's 'sub' mismatch
            let dpop = DpopBuilder {
                sub: Some(QualifiedClientId::alice()),
                ..ciphersuite.key.clone().into()
            };
            let params = Params {
                client_id: QualifiedClientId::bob(),
                ..ciphersuite.into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::TokenSubMismatch));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn htu(ciphersuite: Ciphersuite) {
            // should succeed when uri and JWT's 'htu' match
            let dpop = DpopBuilder {
                dpop: TestDpop {
                    htu: Some("https://a.com/".try_into().unwrap()),
                    ..Default::default()
                },
                ..ciphersuite.key.clone().into()
            };
            let params = Params {
                uri: "https://a.com/".try_into().unwrap(),
                ..ciphersuite.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());

            // should fail when uri and JWT's 'htu' mismatch
            let dpop = DpopBuilder {
                dpop: TestDpop {
                    htu: Some("https://a.com/".try_into().unwrap()),
                    ..Default::default()
                },
                ..ciphersuite.key.clone().into()
            };
            let params = Params {
                uri: "https://b.com/".try_into().unwrap(),
                ..ciphersuite.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::DpopHtuMismatch));

            // should fail when 'htu' is absent from dpop token
            let dpop = DpopBuilder {
                dpop: TestDpop {
                    htu: None,
                    ..Default::default()
                },
                ..ciphersuite.key.clone().into()
            };
            let params = ciphersuite.into();
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "htu"));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn htm(ciphersuite: Ciphersuite) {
            // should succeed when method and JWT's 'htm' match
            let dpop = DpopBuilder {
                dpop: TestDpop {
                    htm: Some(Htm::Post),
                    ..Default::default()
                },
                ..ciphersuite.key.clone().into()
            };
            let params = Params {
                method: Htm::Post,
                ..ciphersuite.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());

            // should fail when method and JWT's 'htm' mismatch
            let dpop = DpopBuilder {
                dpop: TestDpop {
                    htm: Some(Htm::Post),
                    ..Default::default()
                },
                ..ciphersuite.key.clone().into()
            };
            let params = Params {
                method: Htm::Put,
                ..ciphersuite.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::DpopHtmMismatch));

            // should fail when 'htm' is absent from dpop token
            let dpop = DpopBuilder {
                dpop: TestDpop {
                    htm: None,
                    ..Default::default()
                },
                ..ciphersuite.key.clone().into()
            };
            let params = ciphersuite.into();
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "htm"));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn jti(ciphersuite: Ciphersuite) {
            // should succeed when 'jti' claim is present in dpop token
            let dpop = DpopBuilder {
                jti: Some("ABCD".to_string()),
                ..ciphersuite.key.clone().into()
            };
            let params = ciphersuite.clone().into();
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());

            // should fail when 'jti' claim is absent from dpop token
            let dpop = DpopBuilder {
                jti: None,
                ..ciphersuite.key.clone().into()
            };
            let params = ciphersuite.into();
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "jti"));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn backend_nonce(ciphersuite: Ciphersuite) {
            // should succeed when backend_nonce and Dpop 'nonce' match
            let nonce = BackendNonce::rand();
            let dpop = DpopBuilder {
                nonce: Some(nonce.clone()),
                ..ciphersuite.key.clone().into()
            };
            let params = Params {
                backend_nonce: nonce,
                ..ciphersuite.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());

            // Dpop 'nonce' is absent
            let dpop = DpopBuilder {
                nonce: None,
                ..ciphersuite.key.clone().into()
            };
            let params = Params {
                backend_nonce: BackendNonce::rand(),
                ..ciphersuite.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "nonce"));

            // should fail when backend_nonce and Dpop 'nonce' mismatch
            let dpop = DpopBuilder {
                nonce: Some(BackendNonce::rand()),
                ..ciphersuite.key.clone().into()
            };
            let params = Params {
                backend_nonce: BackendNonce::rand(),
                ..ciphersuite.into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::DpopNonceMismatch));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn challenge(ciphersuite: Ciphersuite) {
            // should succeed when 'chal' (ACME challenge) claim is present in dpop token
            let dpop = DpopBuilder {
                dpop: TestDpop {
                    challenge: Some(AcmeChallenge::rand()),
                    ..Default::default()
                },
                ..ciphersuite.key.clone().into()
            };
            let params = ciphersuite.clone().into();
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());

            // should fail when 'chal' claim is absent from dpop token
            let dpop = DpopBuilder {
                dpop: TestDpop {
                    challenge: None,
                    ..Default::default()
                },
                ..ciphersuite.key.clone().into()
            };
            let params = ciphersuite.into();
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "chal"));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn iat(ciphersuite: Ciphersuite) {
            // should succeed when 'iat' claim is present in dpop token and in the past
            let yesterday = now() - Duration::from_days(1);
            let dpop = DpopBuilder {
                iat: Some(yesterday),
                ..ciphersuite.key.clone().into()
            };
            let params = ciphersuite.clone().into();
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());

            // should fail when 'iat' claim is absent from dpop token
            let dpop = DpopBuilder {
                iat: None,
                ..ciphersuite.key.clone().into()
            };
            let params = ciphersuite.clone().into();
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "iat"));

            // should fail when issued in the future
            let tomorrow = now() + Duration::from_days(1);
            let dpop = DpopBuilder {
                iat: Some(tomorrow),
                ..ciphersuite.key.clone().into()
            };
            let params = ciphersuite.clone().into();
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidDpopIat));

            // should fail respecting leeway

            // will fail as there is no tolerance
            let in_1_h = now() + Duration::from_hours(1);
            let dpop = DpopBuilder {
                iat: Some(in_1_h),
                ..ciphersuite.key.clone().into()
            };
            let params = Params {
                leeway: 0,
                ..ciphersuite.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidDpopIat));

            // will succeed as there is tolerance
            let dpop = DpopBuilder {
                iat: Some(in_1_h),
                ..ciphersuite.key.clone().into()
            };
            let params = Params {
                leeway: 3600 + 10, // 1h + some test leeway
                ..ciphersuite.into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn exp(ciphersuite: Ciphersuite) {
            // should succeed when 'exp' claim is present in dpop token and in future
            let tomorrow = now() + Duration::from_days(1);
            let dpop = DpopBuilder {
                exp: Some(tomorrow),
                ..ciphersuite.key.clone().into()
            };
            let params = ciphersuite.clone().into();
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());

            // should fail when 'exp' claim is absent from dpop token
            let dpop = DpopBuilder {
                exp: None,
                ..ciphersuite.key.clone().into()
            };
            let params = ciphersuite.clone().into();
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "exp"));

            // should fail when 'exp' claim is in the past
            let yesterday = now() - Duration::from_days(1);
            let dpop = DpopBuilder {
                exp: Some(yesterday),
                ..ciphersuite.key.clone().into()
            };
            let params = ciphersuite.clone().into();
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::TokenExpired));

            // should fail respecting leeway

            // will fail as there is no tolerance
            let previous_hour = now() - Duration::from_hours(1);
            let dpop = DpopBuilder {
                exp: Some(previous_hour),
                ..ciphersuite.key.clone().into()
            };
            let params = Params {
                leeway: 0,
                ..ciphersuite.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::TokenExpired));

            // will succeed as there is tolerance
            let dpop = DpopBuilder {
                exp: Some(previous_hour),
                ..ciphersuite.key.clone().into()
            };
            let params = Params {
                leeway: 3600 + 10, // 1h + some test leeway
                ..ciphersuite.into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn exp_threshold(ciphersuite: Ciphersuite) {
            // should succeed when 'exp' is sooner than supplied 'max_expiration'
            let tomorrow = now() + Duration::from_days(1);
            let day_after_tomorrow = tomorrow + Duration::from_days(1);

            let dpop = DpopBuilder {
                exp: Some(tomorrow),
                ..ciphersuite.key.clone().into()
            };
            let params = Params {
                max_expiration: day_after_tomorrow.as_secs(),
                ..ciphersuite.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());

            // should fail when 'exp' is later than supplied 'max_expiration'
            let dpop = DpopBuilder {
                exp: Some(day_after_tomorrow),
                ..ciphersuite.key.clone().into()
            };
            let params = Params {
                max_expiration: tomorrow.as_secs(),
                ..ciphersuite.into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::TokenLivesTooLong));
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    struct Params<'a> {
        pub dpop_alg: JwsAlgorithm,
        pub key: JwtKey,
        pub dpop: Dpop,
        pub client_id: QualifiedClientId<'a>,
        pub backend_nonce: BackendNonce,
        pub uri: Htu,
        pub method: Htm,
        pub leeway: u16,
        pub max_expiration: u64,
        pub backend_keys: Pem,
        pub hash_alg: HashAlgorithm,
    }

    impl From<Ciphersuite> for Params<'_> {
        fn from(ciphersuite: Ciphersuite) -> Self {
            let backend_keys = ciphersuite.key.create_another().kp;
            Self {
                dpop_alg: ciphersuite.key.alg,
                key: ciphersuite.key,
                dpop: Dpop::default(),
                client_id: QualifiedClientId::default(),
                backend_nonce: BackendNonce::default(),
                uri: Htu::default(),
                method: Htm::default(),
                leeway: 5,
                max_expiration: 2136351646, // somewhere in 2037
                backend_keys,
                hash_alg: ciphersuite.hash,
            }
        }
    }

    fn access_token(params: Params) -> RustyJwtResult<String> {
        let Params {
            dpop_alg,
            key,
            dpop,
            client_id,
            backend_nonce,
            ..
        } = params.clone();
        let expiry = Duration::from_days(1);
        let dpop =
            RustyJwtTools::generate_dpop_token(dpop_alg, key.kp, dpop, backend_nonce, client_id, expiry).unwrap();
        access_token_with_dpop(&dpop, params)
    }

    fn access_token_with_dpop(dpop: &str, params: Params) -> RustyJwtResult<String> {
        let Params {
            client_id,
            backend_nonce,
            uri,
            method,
            leeway,
            max_expiration,
            backend_keys,
            hash_alg,
            ..
        } = params;
        RustyJwtTools::generate_access_token(
            dpop,
            client_id,
            backend_nonce,
            uri,
            method,
            leeway,
            max_expiration,
            backend_keys,
            hash_alg,
        )
    }
}
