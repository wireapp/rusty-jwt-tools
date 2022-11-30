use jwt_simple::prelude::*;

use crate::{
    access::Access,
    introspect::RustyIntrospect,
    jkt::JktConfirmation,
    jwt::{Verify, VerifyJwt, VerifyJwtHeader},
    prelude::*,
};

impl RustyJwtTools {
    /// Validate the provided dpop_token DPoP auth token JWT
    /// provided to the ACME server, and return OK or an error.
    ///
    /// Verifications:
    /// * [access_token] has the correct syntax for an introspectable token [TODO]
    /// * `typ` header field is "dpop+jwt"
    /// * signature algorithm (alg) in JWT header is a supported algorithm
    /// * signature corresponds to the public key (jwk) in the JWT header [TODO]
    /// * [client_id] corresponds to the (sub) claim expressed as URI
    /// * [challenge] corresponds to the (chal) claim encoded as base64url.
    /// * `jti` claim is present in token
    /// * `nonce` claim is present in token
    /// * `iat` claim is present and no earlier or later than max_skew_secs seconds of now
    /// * `exp` claim is present and no larger (later) than max_expiration.
    /// * `exp` claim is no later than now plus max_skew_secs.
    ///
    /// # Arguments
    /// * `dpop_proof` - JWS Compact Serialization format. Note that the proof consists of three runs
    /// of base64url characters (header, claims, signature) separated by period characters.
    /// ex: b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" (whitespace in the example is not included in the actual proof)
    /// * `client_id` - see [QualifiedClientId]
    /// * `challenge` - The most recent challenge nonce provided by the ACME server to the current client ex: hex!("71515234fac0b04b2008db62551e7287")
    /// * `max_skew_secs` - The maximum number of seconds of clock skew the implementation will allow ex: 360 (5 min)
    /// * `max_expiration` - The maximal expiration date and time, in seconds since epoch ex: 1668987368
    /// * `now` - Current time in seconds since epoch ex: 1661211368
    /// * `backend_pk` - PEM format for public key of the Wire backend
    pub fn verify_access_token(
        access_token: &str,
        client_id: QualifiedClientId,
        challenge: AcmeChallenge,
        max_skew_secs: u16,
        max_expiration: u64,
        backend_pk: Pem,
        hash: HashAlgorithm,
    ) -> RustyJwtResult<()> {
        let header = Token::decode_metadata(access_token)?;
        let (alg, jwk) = Self::verify_access_token_header(&header)?;
        Self::verify_access_token_claims(
            access_token,
            alg,
            &backend_pk,
            client_id,
            &challenge,
            max_expiration,
            max_skew_secs,
            jwk,
            hash,
        )
    }

    /// Verifies access token specific header
    fn verify_access_token_header(header: &TokenMetadata) -> RustyJwtResult<(JwsAlgorithm, &Jwk)> {
        let typ = header.signature_type().ok_or(RustyJwtError::MissingDpopHeader("typ"))?;
        if typ != Access::TYP {
            return Err(RustyJwtError::InvalidDpopTyp);
        }
        let alg = header.verify_jwt_header()?;
        // TODO: use JWK thumbprint
        let jwk = header.public_key().ok_or(RustyJwtError::MissingDpopHeader("jwk"))?;
        Ok((alg, jwk))
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_access_token_claims(
        access_token: &str,
        alg: JwsAlgorithm,
        backend_pk: &Pem,
        client_id: QualifiedClientId,
        challenge: &AcmeChallenge,
        max_expiration: u64,
        leeway: u16,
        jwk: &Jwk,
        hash: HashAlgorithm,
    ) -> RustyJwtResult<()> {
        let pk = AnyPublicKey::from((alg, backend_pk));
        let introspect_response = RustyIntrospect::introspect_response(access_token, pk, leeway)?;

        let actual_cnf = &introspect_response.extra_fields().cnf;
        let verify = Verify {
            cnf: Some(actual_cnf),
            leeway,
            client_id,
            backend_nonce: None,
        };

        let pk = AnyPublicKey::from((alg, backend_pk));

        let expected_cnf = JktConfirmation::generate(jwk, hash)?;
        let claims = access_token.verify_jwt::<Access>(&pk, max_expiration, Some(&expected_cnf), verify)?;

        // verify the JWK in access token represents the same key as the one supplied
        if pk != AnyPublicKey::from((alg, jwk)) {
            return Err(RustyJwtError::InvalidDpopJwk);
        }

        if &claims.custom.challenge != challenge {
            return Err(RustyJwtError::DpopChallengeMismatch);
        }
        if claims.custom.api_version != Access::WIRE_SERVER_API_VERSION {
            return Err(RustyJwtError::UnsupportedApiVersion);
        }
        if claims.custom.scope != Access::DEFAULT_SCOPE {
            return Err(RustyJwtError::UnsupportedScope);
        }
        if claims.custom.client_id != claims.subject.ok_or(RustyJwtError::ImplementationError)? {
            return Err(RustyJwtError::TokenSubMismatch);
        }
        let nonce: BackendNonce = claims.nonce.ok_or(RustyJwtError::MissingTokenClaim("nonce"))?.into();

        // Dpop proof verification
        use crate::dpop::{VerifyDpop as _, VerifyDpopTokenHeader as _};
        let proof = claims.custom.proof.as_str();
        let header = Token::decode_metadata(proof)?;
        let (alg, jwk) = header.verify_dpop_header()?;
        let issuer: Htu = claims
            .issuer
            .ok_or(RustyJwtError::MissingTokenClaim("issuer"))
            .and_then(|i| i.as_str().try_into())?;

        proof.verify_client_dpop(
            alg,
            jwk,
            client_id,
            &nonce,
            Some(&claims.custom.challenge),
            None,
            &issuer,
            max_expiration,
            leeway,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use jwt_simple::prelude::*;

    use crate::test_utils::*;

    use super::*;

    mod access {
        use super::*;

        #[apply(all_ciphersuites)]
        #[test]
        fn typ(ciphersuite: Ciphersuite) {
            // should fail when 'typ' header absent
            let access = AccessBuilder {
                typ: None,
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingDpopHeader(header) if header == "typ"));

            // should fail when wrong value
            let access = AccessBuilder {
                typ: Some("unknown+jwt"),
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidDpopTyp));

            // should be valid
            let access = AccessBuilder {
                typ: Some("at+jwt"),
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.into());
            assert!(result.is_ok());
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn alg(ciphersuite: Ciphersuite) {
            let unsupported = &[
                "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES512",
            ]
            .map(|a| a.to_string());
            // should fail when 'alg' is not supported
            for alg in unsupported {
                let access = AccessBuilder {
                    alg: alg.clone(),
                    ..ciphersuite.clone().into()
                };
                let result = verify_token(&access.build(), ciphersuite.clone().into());
                assert!(matches!(result.unwrap_err(), RustyJwtError::UnsupportedAlgorithm));
            }

            // should be valid
            let access = AccessBuilder {
                alg: ciphersuite.key.alg.to_string(),
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.into());
            assert!(result.is_ok());
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn backend_pk_and_alg(ciphersuite: Ciphersuite) {
            // should fail when access_token signature algorithm and supplied public key mismatch
            let others = ciphersuite.key.reverse_algorithms().map(|a| a.to_string());
            for alg in others {
                let access = AccessBuilder::from(ciphersuite.clone());
                let params = Params {
                    backend_pk: Some(JwtKey::new_key(alg.as_str().try_into().unwrap()).pk),
                    ..ciphersuite.clone().into()
                };
                let result = verify_token(&access.build(), params);
                assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidToken(r) if r == "Invalid public key"));
            }
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn signature_with_backend_pk(ciphersuite: Ciphersuite) {
            // signature should be valid with the right key
            let access = AccessBuilder::from(ciphersuite.clone());
            let params = Params {
                backend_pk: Some(ciphersuite.key.clone().pk),
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), params);
            assert!(result.is_ok());

            // signature should not be valid with the wrong key
            let access = AccessBuilder::from(ciphersuite.clone());
            let params = Params {
                backend_pk: Some(ciphersuite.key.create_another().pk),
                ..ciphersuite.into()
            };
            let result = verify_token(&access.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidToken(_)));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn jwk(ciphersuite: Ciphersuite) {
            // should succeed when signature matches with JWK
            let jwk = ciphersuite.key.to_jwk();
            let access = AccessBuilder {
                jwk: Some(jwk),
                ..ciphersuite.clone().into()
            };
            let params = Params::from(ciphersuite.clone());
            let result = verify_token(&access.build(), params);
            result.unwrap();
            // assert!(result.is_ok());

            // should succeed when JWK is missing
            let access = AccessBuilder {
                jwk: None,
                ..ciphersuite.clone().into()
            };
            let params = Params::from(ciphersuite.clone());
            let result = verify_token(&access.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingDpopHeader("jwk")));

            // should succeed when JWK does not match signature
            let invalid_ciphersuite = Ciphersuite {
                key: ciphersuite.key.create_another(),
                ..ciphersuite
            };
            let invalid_jwk = invalid_ciphersuite.key.to_jwk();
            let invalid_cnf = invalid_ciphersuite.to_jwk_thumbprint();
            let access = AccessBuilder {
                jwk: Some(invalid_jwk),
                access: TestAccess {
                    cnf: Some(invalid_cnf),
                    ..ciphersuite.clone().into()
                },
                ..ciphersuite.clone().into()
            };
            let params = Params::from(ciphersuite);
            let result = verify_token(&access.build(), params);
            // result.unwrap();
            assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidDpopJwk));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn jwk_thumbprint(ciphersuite: Ciphersuite) {
            // should succeed when JWK thumbprint matches JWK in header
            let cnf = ciphersuite.to_jwk_thumbprint();
            let access = AccessBuilder {
                access: TestAccess {
                    cnf: Some(cnf),
                    ..ciphersuite.clone().into()
                },
                ..ciphersuite.clone().into()
            };
            let params = Params::from(ciphersuite.clone());
            let result = verify_token(&access.build(), params);
            assert!(result.is_ok());

            // should fail when JWK thumbprint mismatches JWK in header
            let invalid_jwk = ciphersuite.key.create_another().to_jwk();
            let cnf = ciphersuite.to_jwk_thumbprint();
            let access = AccessBuilder {
                access: TestAccess {
                    cnf: Some(cnf),
                    ..ciphersuite.clone().into()
                },
                jwk: Some(invalid_jwk),
                ..ciphersuite.clone().into()
            };
            let params = Params::from(ciphersuite.clone());
            let result = verify_token(&access.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidJwkThumbprint));

            // should fail when JWK thumbprint is absent
            let access = AccessBuilder {
                access: TestAccess {
                    cnf: None,
                    ..ciphersuite.clone().into()
                },
                jwk: Some(ciphersuite.key.to_jwk()),
                ..ciphersuite.clone().into()
            };
            let params = Params::from(ciphersuite);
            let result = verify_token(&access.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim("cnf")));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn sub_and_client_id(ciphersuite: Ciphersuite) {
            // should succeed when client_id and JWT's 'sub' match
            let proof = DpopBuilder {
                sub: Some(QualifiedClientId::alice()),
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = AccessBuilder {
                access: TestAccess {
                    proof: Some(proof),
                    client_id: Some(QualifiedClientId::alice()),
                    ..ciphersuite.clone().into()
                },
                sub: Some(QualifiedClientId::alice()),
                ..ciphersuite.clone().into()
            };
            let params = Params {
                client_id: QualifiedClientId::alice(),
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), params);
            assert!(result.is_ok());

            // JWT's 'sub' is absent
            let access = AccessBuilder {
                sub: None,
                ..ciphersuite.clone().into()
            };
            let params = Params {
                client_id: QualifiedClientId::bob(),
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "sub"));

            // JWT's 'client_id' is absent
            let access = AccessBuilder {
                access: TestAccess {
                    client_id: None,
                    ..ciphersuite.clone().into()
                },
                ..ciphersuite.clone().into()
            };
            let params = Params {
                client_id: QualifiedClientId::bob(),
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "client_id"));

            // should fail when client_id and JWT's 'sub' mismatch
            let access = AccessBuilder {
                sub: Some(QualifiedClientId::alice()),
                ..ciphersuite.clone().into()
            };
            let params = Params {
                client_id: QualifiedClientId::bob(),
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::TokenSubMismatch));

            // should fail when 'sub' and 'client_id' claim mismatch
            let access = AccessBuilder {
                sub: Some(QualifiedClientId::alice()),
                access: TestAccess {
                    client_id: Some(QualifiedClientId::bob()),
                    ..ciphersuite.clone().into()
                },
                ..ciphersuite.clone().into()
            };
            let params = Params {
                client_id: QualifiedClientId::alice(),
                ..ciphersuite.into()
            };
            let result = verify_token(&access.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::TokenSubMismatch));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn jti(ciphersuite: Ciphersuite) {
            // should succeed when 'jti' claim is present in access token
            let access = AccessBuilder {
                jti: Some("ABCD".to_string()),
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.clone().into());
            assert!(result.is_ok());

            // should fail when 'jti' claim is absent from access token
            let access = AccessBuilder {
                jti: None,
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "jti"));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn api_version(ciphersuite: Ciphersuite) {
            // should succeed when 'api_version' claim is present in access token
            let access = AccessBuilder {
                access: TestAccess {
                    api_version: Some(Access::WIRE_SERVER_API_VERSION),
                    ..ciphersuite.clone().into()
                },
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.clone().into());
            assert!(result.is_ok());

            // should fail when 'api_version' claim is absent from access token
            let access = AccessBuilder {
                access: TestAccess {
                    api_version: None,
                    ..ciphersuite.clone().into()
                },
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "api_version"));

            // should fail when 'api_version' claim does not have the expected value
            let access = AccessBuilder {
                access: TestAccess {
                    api_version: Some(Access::WIRE_SERVER_API_VERSION + 1),
                    ..ciphersuite.clone().into()
                },
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::UnsupportedApiVersion));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn scope(ciphersuite: Ciphersuite) {
            // should succeed when 'scope' claim is present in access token
            let access = AccessBuilder {
                access: TestAccess {
                    scope: Some(Access::DEFAULT_SCOPE.to_string()),
                    ..ciphersuite.clone().into()
                },
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.clone().into());
            assert!(result.is_ok());

            // should fail when 'scope' claim is absent from access token
            let access = AccessBuilder {
                access: TestAccess {
                    scope: None,
                    ..ciphersuite.clone().into()
                },
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "scope"));

            // should fail when 'scope' claim does not have the expected value
            let access = AccessBuilder {
                access: TestAccess {
                    scope: Some(format!("a{}z", Access::DEFAULT_SCOPE)),
                    ..ciphersuite.clone().into()
                },
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::UnsupportedScope));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn challenge(ciphersuite: Ciphersuite) {
            // should succeed when challenge and JWT's 'chal' match
            let challenge = AcmeChallenge::rand();
            let proof = DpopBuilder {
                dpop: TestDpop {
                    challenge: Some(challenge.clone()),
                    ..Default::default()
                },
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = AccessBuilder {
                access: TestAccess {
                    challenge: Some(challenge.clone()),
                    proof: Some(proof),
                    ..ciphersuite.clone().into()
                },
                ..ciphersuite.clone().into()
            };
            let params = Params {
                challenge,
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), params);
            assert!(result.is_ok());

            // JWT's 'chal' is absent
            let access = AccessBuilder {
                access: TestAccess {
                    challenge: None,
                    ..ciphersuite.clone().into()
                },
                ..ciphersuite.clone().into()
            };
            let params = Params {
                challenge: AcmeChallenge::rand(),
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "chal"));

            // should fail when challenge and JWT's 'chal' mismatch
            let access = AccessBuilder {
                access: TestAccess {
                    challenge: Some(AcmeChallenge::rand()),
                    ..ciphersuite.clone().into()
                },
                ..ciphersuite.clone().into()
            };
            let params = Params {
                challenge: AcmeChallenge::rand(),
                ..ciphersuite.into()
            };
            let result = verify_token(&access.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::DpopChallengeMismatch));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn backend_nonce(ciphersuite: Ciphersuite) {
            // should succeed when 'nonce' claim is present in access token
            let nonce = BackendNonce::rand();
            let proof = DpopBuilder {
                nonce: Some(nonce.clone()),
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = AccessBuilder {
                access: TestAccess {
                    proof: Some(proof),
                    ..ciphersuite.clone().into()
                },
                nonce: Some(nonce),
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.clone().into());
            assert!(result.is_ok());

            // should fail when 'nonce' claim is absent from access token
            let access = AccessBuilder {
                nonce: None,
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "nonce"));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn iat(ciphersuite: Ciphersuite) {
            // should succeed when 'iat' claim is present in access token and in the past
            let yesterday = now() - Duration::from_days(1);
            let access = AccessBuilder {
                iat: Some(yesterday),
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.clone().into());
            assert!(result.is_ok());

            // should fail when 'iat' claim is absent from access token
            let access = AccessBuilder {
                iat: None,
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "iat"));

            // should fail when issued in the future
            let tomorrow = now() + Duration::from_days(1);
            let access = AccessBuilder {
                iat: Some(tomorrow),
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidDpopIat));

            // should fail respecting leeway

            // will fail as there is no tolerance
            let in_1_h = now() + Duration::from_hours(1);
            let access = AccessBuilder {
                iat: Some(in_1_h),
                ..ciphersuite.clone().into()
            };
            let params = Params {
                leeway: 0,
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidDpopIat));

            // will succeed as there is tolerance
            let access = AccessBuilder {
                iat: Some(in_1_h),
                ..ciphersuite.clone().into()
            };
            let params = Params {
                leeway: 3600 + 10, // 1h + some test leeway
                ..ciphersuite.into()
            };
            let result = verify_token(&access.build(), params);
            assert!(result.is_ok());
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn exp(ciphersuite: Ciphersuite) {
            // should succeed when 'exp' claim is present in access token and in future
            let tomorrow = now() + Duration::from_days(1);
            let access = AccessBuilder {
                exp: Some(tomorrow),
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.clone().into());
            assert!(result.is_ok());

            // should fail when 'exp' claim is absent from access token
            let access = AccessBuilder {
                exp: None,
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "exp"));

            // should fail when 'exp' claim is in the past
            let yesterday = now() - Duration::from_days(1);
            let access = AccessBuilder {
                exp: Some(yesterday),
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::TokenExpired));

            // should fail respecting leeway

            // will fail as there is no tolerance
            let previous_hour = now() - Duration::from_hours(1);
            let access = AccessBuilder {
                exp: Some(previous_hour),
                ..ciphersuite.clone().into()
            };
            let params = Params {
                leeway: 0,
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::TokenExpired));

            // will succeed as there is tolerance
            let access = AccessBuilder {
                exp: Some(previous_hour),
                ..ciphersuite.clone().into()
            };
            let params = Params {
                leeway: 3600 + 10, // 1h + some test leeway
                ..ciphersuite.into()
            };
            let result = verify_token(&access.build(), params);
            assert!(result.is_ok());
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn exp_threshold(ciphersuite: Ciphersuite) {
            // should succeed when 'exp' is sooner than supplied 'max_expiration'
            let tomorrow = now() + Duration::from_days(1);
            let day_after_tomorrow = tomorrow + Duration::from_days(1);

            let access = AccessBuilder {
                exp: Some(tomorrow),
                ..ciphersuite.clone().into()
            };
            let params = Params {
                max_expiration: day_after_tomorrow.as_secs(),
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), params);
            assert!(result.is_ok());

            // should fail when 'exp' is later than supplied 'max_expiration'
            let access = AccessBuilder {
                exp: Some(day_after_tomorrow),
                ..ciphersuite.clone().into()
            };
            let params = Params {
                max_expiration: tomorrow.as_secs(),
                ..ciphersuite.into()
            };
            let result = verify_token(&access.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::TokenLivesTooLong));
        }
    }

    mod proof {
        use super::*;

        #[apply(all_ciphersuites)]
        #[test]
        fn should_have_a_proof_claim(ciphersuite: Ciphersuite) {
            // Succeeds when claim 'proof' is present
            let proof = DpopBuilder::from(ciphersuite.key.clone()).build();
            let access = AccessBuilder {
                access: TestAccess {
                    proof: Some(proof),
                    ..ciphersuite.clone().into()
                },
                ..ciphersuite.clone().into()
            };
            let params = Params::from(ciphersuite.clone());
            let result = verify_token(&access.build(), params);
            assert!(result.is_ok());

            // JWT's 'proof' is absent
            let access = AccessBuilder {
                access: TestAccess {
                    proof: None,
                    ..ciphersuite.clone().into()
                },
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access.build(), ciphersuite.into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "proof"));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn should_have_right_typ_header(ciphersuite: Ciphersuite) {
            // should fail when 'typ' header absent
            let proof = DpopBuilder {
                typ: None,
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingDpopHeader(header) if header == "typ"));

            // should fail when 'typ' has wrong value
            let proof = DpopBuilder {
                typ: Some("unknown+jwt"),
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidDpopTyp));

            // should succeed when 'typ' has right value
            let proof = DpopBuilder {
                typ: Some("dpop+jwt"),
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.into());
            assert!(result.is_ok());
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn should_have_jwk_header(ciphersuite: Ciphersuite) {
            // should fail when 'jwk' header absent
            let proof = DpopBuilder {
                jwk: None,
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingDpopHeader(header) if header == "jwk"));

            // should succeed when 'typ' has right value
            let jwk = ciphersuite.key.to_jwk();
            let proof = DpopBuilder {
                jwk: Some(jwk),
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.into());
            assert!(result.is_ok());
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn should_have_supported_alg(ciphersuite: Ciphersuite) {
            // should fail when 'alg' not supported
            for alg in JwsAlgorithm::UNSUPPORTED {
                let proof = DpopBuilder {
                    alg: alg.to_string(),
                    ..ciphersuite.key.clone().into()
                }
                .build();
                let access = build_access(&ciphersuite, proof);
                let result = verify_token(&access, ciphersuite.clone().into());
                assert!(matches!(result.unwrap_err(), RustyJwtError::UnsupportedAlgorithm));
            }

            // should succeed when 'alg' supported
            let jwk = ciphersuite.key.to_jwk();
            let proof = DpopBuilder {
                alg: ciphersuite.key.alg.to_string(),
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.into());
            assert!(result.is_ok());
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn jwk_and_alg_should_match(ciphersuite: Ciphersuite) {
            // should fail when 'jwk' is not of the 'alg' type
            for alg in ciphersuite.key.reverse_algorithms() {
                let jwk = ciphersuite.key.to_jwk();
                let proof = DpopBuilder {
                    jwk: Some(jwk),
                    alg: alg.to_string(),
                    ..ciphersuite.key.clone().into()
                }
                .build();
                let access = build_access(&ciphersuite, proof);
                let result = verify_token(&access, ciphersuite.clone().into());
                assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidDpopJwk));
            }

            // should succeed when 'alg' matches 'alg'
            let jwk = ciphersuite.key.to_jwk();
            let alg = ciphersuite.key.alg.to_string();
            let proof = DpopBuilder {
                alg,
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.into());
            assert!(result.is_ok());
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn jwk_should_verify_signature(ciphersuite: Ciphersuite) {
            // should succeed with valid signature
            let proof = DpopBuilder::from(ciphersuite.key.clone()).build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.clone().into());
            assert!(result.is_ok());

            // should fail when signature not verified by jwk
            let other_jwk = DpopBuilder::from(JwtKey::new_key(ciphersuite.key.alg)).jwk.unwrap();
            // dpop is signed with the former key
            let proof = DpopBuilder {
                jwk: Some(other_jwk),
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidToken(_)));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn should_match_access_sub_and_client_id(ciphersuite: Ciphersuite) {
            // should succeed when 'sub' claim matches the one in the access token
            let proof = DpopBuilder {
                sub: Some(QualifiedClientId::alice()),
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = AccessBuilder {
                access: TestAccess {
                    proof: Some(proof),
                    client_id: Some(QualifiedClientId::alice()),
                    ..ciphersuite.clone().into()
                },
                sub: Some(QualifiedClientId::alice()),
                ..ciphersuite.clone().into()
            }
            .build();
            let params = Params {
                client_id: QualifiedClientId::alice(),
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access, params);
            assert!(result.is_ok());

            // should fail when 'sub' lacks from proof
            let proof = DpopBuilder {
                sub: None,
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "sub"));

            // should fail when 'sub' from proof mismatches 'sub' or 'client_id' in access token
            let proof = DpopBuilder {
                sub: Some(QualifiedClientId::bob()),
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = AccessBuilder {
                access: TestAccess {
                    proof: Some(proof),
                    client_id: Some(QualifiedClientId::alice()),
                    ..ciphersuite.clone().into()
                },
                sub: Some(QualifiedClientId::alice()),
                ..ciphersuite.clone().into()
            }
            .build();
            let params = Params {
                client_id: QualifiedClientId::alice(),
                ..ciphersuite.into()
            };
            let result = verify_token(&access, params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::TokenSubMismatch));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn htu_should_match_access_iss(ciphersuite: Ciphersuite) {
            // should succeed when 'htu' claim matches the 'iss' claim in the access token
            let proof = DpopBuilder {
                dpop: TestDpop {
                    htu: Some("https://a.com/".try_into().unwrap()),
                    ..Default::default()
                },
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = AccessBuilder {
                access: TestAccess {
                    proof: Some(proof),
                    ..ciphersuite.clone().into()
                },
                issuer: Some("https://a.com/".try_into().unwrap()),
                ..ciphersuite.clone().into()
            }
            .build();
            let result = verify_token(&access, ciphersuite.clone().into());
            assert!(result.is_ok());

            // should fail when 'htu' claim lacks in the proof
            let proof = DpopBuilder {
                dpop: TestDpop {
                    htu: None,
                    ..Default::default()
                },
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "htu"));

            // should fail when 'htu' claim mismatches the 'iss' claim in the access token
            let proof = DpopBuilder {
                dpop: TestDpop {
                    htu: Some("https://a.com/".try_into().unwrap()),
                    ..Default::default()
                },
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = AccessBuilder {
                access: TestAccess {
                    proof: Some(proof),
                    ..ciphersuite.clone().into()
                },
                issuer: Some("https://b.com/".try_into().unwrap()),
                ..ciphersuite.clone().into()
            }
            .build();
            let result = verify_token(&access, ciphersuite.into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::DpopHtuMismatch));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn should_have_htm(ciphersuite: Ciphersuite) {
            // should succeed when 'htm' claim is present
            let proof = DpopBuilder {
                dpop: TestDpop {
                    htm: Some(Htm::Post),
                    ..Default::default()
                },
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.clone().into());
            assert!(result.is_ok());

            // should fail when 'htm' claim lacks in the proof
            let proof = DpopBuilder {
                dpop: TestDpop {
                    htm: None,
                    ..Default::default()
                },
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "htm"));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn should_have_jti(ciphersuite: Ciphersuite) {
            // should succeed when 'jti' claim is present
            let proof = DpopBuilder {
                jti: Some("ABCD".to_string()),
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.clone().into());
            assert!(result.is_ok());

            // should fail when 'jti' claim lacks in the proof
            let proof = DpopBuilder {
                jti: None,
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "jti"));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn nonce_should_match_access_nonce(ciphersuite: Ciphersuite) {
            // should succeed when 'nonce' claim matches the 'nonce' claim in the access token
            let nonce = BackendNonce::rand();
            let proof = DpopBuilder {
                nonce: Some(nonce.clone()),
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = AccessBuilder {
                access: TestAccess {
                    proof: Some(proof),
                    ..ciphersuite.clone().into()
                },
                nonce: Some(nonce),
                ..ciphersuite.clone().into()
            }
            .build();
            let result = verify_token(&access, ciphersuite.clone().into());
            assert!(result.is_ok());

            // should fail when 'nonce' claim lacks in the proof
            let proof = DpopBuilder {
                nonce: None,
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "nonce"));

            // should fail when 'nonce' claim mismatches the 'nonce' claim in the access token
            let nonce1 = BackendNonce::rand();
            let nonce2 = BackendNonce::rand();
            let proof = DpopBuilder {
                nonce: Some(nonce1),
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = AccessBuilder {
                access: TestAccess {
                    proof: Some(proof),
                    ..ciphersuite.clone().into()
                },
                nonce: Some(nonce2),
                ..ciphersuite.clone().into()
            }
            .build();
            let result = verify_token(&access, ciphersuite.into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::DpopNonceMismatch));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn challenge_should_match_access_challenge(ciphersuite: Ciphersuite) {
            // should succeed when 'chal' claim matches the 'chal' claim in the access token
            let challenge = AcmeChallenge::rand();
            let proof = DpopBuilder {
                dpop: TestDpop {
                    challenge: Some(challenge.clone()),
                    ..Default::default()
                },
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = AccessBuilder {
                access: TestAccess {
                    proof: Some(proof),
                    challenge: Some(challenge.clone()),
                    ..ciphersuite.clone().into()
                },
                ..ciphersuite.clone().into()
            }
            .build();
            let params = Params {
                challenge,
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access, params);
            result.unwrap();
            // assert!(result.is_ok());

            // should fail when 'chal' claim lacks in the proof
            let proof = DpopBuilder {
                dpop: TestDpop {
                    challenge: None,
                    ..Default::default()
                },
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "chal"));

            // should fail when 'chal' claim mismatches the 'chal' claim in the access token
            let chal1 = AcmeChallenge::rand();
            let chal2 = AcmeChallenge::rand();
            let proof = DpopBuilder {
                dpop: TestDpop {
                    challenge: Some(chal1),
                    ..Default::default()
                },
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = AccessBuilder {
                access: TestAccess {
                    proof: Some(proof),
                    challenge: Some(chal2.clone()),
                    ..ciphersuite.clone().into()
                },
                ..ciphersuite.clone().into()
            }
            .build();
            let params = Params {
                challenge: chal2,
                ..ciphersuite.into()
            };
            let result = verify_token(&access, params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::DpopChallengeMismatch));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn should_verify_iat(ciphersuite: Ciphersuite) {
            // should succeed when 'iat' claim is present in dpop token and in the past
            let yesterday = now() - Duration::from_days(1);
            let proof = DpopBuilder {
                iat: Some(yesterday),
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.clone().into());
            assert!(result.is_ok());

            // should fail when 'iat' claim is absent from dpop token
            let proof = DpopBuilder {
                iat: None,
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "iat"));

            // should fail when issued in the future
            let tomorrow = now() + Duration::from_days(1);
            let proof = DpopBuilder {
                iat: Some(tomorrow),
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidDpopIat));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn should_verify_expiry(ciphersuite: Ciphersuite) {
            // should succeed when 'exp' claim is present in dpop token and in future
            let tomorrow = now() + Duration::from_days(1);
            let proof = DpopBuilder {
                exp: Some(tomorrow),
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.clone().into());
            assert!(result.is_ok());

            // should fail when 'exp' claim is absent from dpop token
            let proof = DpopBuilder {
                exp: None,
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingTokenClaim(claim) if claim == "exp"));

            // should fail when 'exp' claim is in the past
            let yesterday = now() - Duration::from_days(1);
            let proof = DpopBuilder {
                exp: Some(yesterday),
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let result = verify_token(&access, ciphersuite.into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::TokenExpired));
        }

        #[apply(all_ciphersuites)]
        #[test]
        fn should_verify_max_expiration(ciphersuite: Ciphersuite) {
            // should succeed when 'exp' is sooner than supplied 'max_expiration'
            let tomorrow = now() + Duration::from_days(1);
            let day_after_tomorrow = tomorrow + Duration::from_days(1);

            let proof = DpopBuilder {
                exp: Some(tomorrow),
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let params = Params {
                max_expiration: day_after_tomorrow.as_secs(),
                ..ciphersuite.clone().into()
            };
            let result = verify_token(&access, params);
            assert!(result.is_ok());

            // should fail when 'exp' is later than supplied 'max_expiration'
            let proof = DpopBuilder {
                exp: Some(day_after_tomorrow),
                ..ciphersuite.key.clone().into()
            }
            .build();
            let access = build_access(&ciphersuite, proof);
            let params = Params {
                max_expiration: tomorrow.as_secs(),
                ..ciphersuite.into()
            };
            let result = verify_token(&access, params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::TokenLivesTooLong));
        }

        fn build_access(ciphersuite: &Ciphersuite, proof: String) -> String {
            AccessBuilder {
                access: TestAccess {
                    proof: Some(proof),
                    ..ciphersuite.clone().into()
                },
                ..ciphersuite.clone().into()
            }
            .build()
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    struct Params<'a> {
        pub ciphersuite: Ciphersuite,
        pub client_id: QualifiedClientId<'a>,
        pub challenge: AcmeChallenge,
        pub leeway: u16,
        pub max_expiration: u64,
        pub backend_pk: Option<Pem>,
    }

    impl From<Ciphersuite> for Params<'_> {
        fn from(ciphersuite: Ciphersuite) -> Self {
            Self {
                ciphersuite,
                client_id: QualifiedClientId::default(),
                challenge: AcmeChallenge::default(),
                leeway: 5,
                max_expiration: 2136351646, // somewhere in 2037
                backend_pk: None,
            }
        }
    }

    fn verify_token(access: &str, params: Params) -> RustyJwtResult<()> {
        let Params {
            ciphersuite,
            client_id,
            challenge,
            leeway,
            max_expiration,
            backend_pk,
        } = params;
        let backend_pk = backend_pk.unwrap_or(ciphersuite.key.pk);
        RustyJwtTools::verify_access_token(
            access,
            client_id,
            challenge,
            leeway,
            max_expiration,
            backend_pk,
            ciphersuite.hash,
        )
    }
}
