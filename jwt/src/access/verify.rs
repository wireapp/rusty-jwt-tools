use jwt_simple::prelude::Token;
use jwt_simple::prelude::*;

use crate::access::Access;
use crate::introspect::RustyIntrospect;
use crate::jkt::JktConfirmation;
use crate::jwt::{Verify, VerifyJwt, VerifyJwtHeader};
use crate::prelude::*;

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
        if typ != Dpop::TYP {
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

        if challenge != &claims.custom.challenge {
            return Err(RustyJwtError::DpopChallengeMismatch);
        }
        claims.nonce.ok_or(RustyJwtError::MissingTokenClaim("nonce"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use jwt_simple::prelude::*;

    use crate::test_utils::*;

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
            typ: Some("dpop+jwt"),
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
    fn sub(ciphersuite: Ciphersuite) {
        // should succeed when client_id and JWT's 'sub' match
        let access = AccessBuilder {
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

        // should fail when client_id and JWT's 'sub' mismatch
        let access = AccessBuilder {
            sub: Some(QualifiedClientId::alice()),
            ..ciphersuite.clone().into()
        };
        let params = Params {
            client_id: QualifiedClientId::bob(),
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
    fn challenge(ciphersuite: Ciphersuite) {
        // should succeed when challenge and JWT's 'chal' match
        let challenge = AcmeChallenge::rand();
        let access = AccessBuilder {
            access: TestAccess {
                challenge: Some(challenge.clone()),
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
        let access = AccessBuilder {
            nonce: Some(BackendNonce::rand()),
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
