use jwt_simple::prelude::*;
use jwt_simple::token::Token;

use crate::jwk::TryFromJwk;
use crate::prelude::*;

impl RustyJwtTools {
    /// Validate the provided [dpop_proof] DPoP proof JWT from the client, and if valid, return an
    /// introspectable DPoP access token.
    ///
    /// Verifications:
    /// * [dpop_proof] has the correct syntax
    /// * (typ) header field is "dpop+jwt"
    /// * signature algorithm (alg) in JWT header is a supported algorithm
    /// * signature corresponds to the public key (jwk) in the JWT header
    /// * qualified_client_id corresponds to the (sub) claim expressed as URI:
    /// * backend_nonce corresponds to the (nonce) claim encoded as base64url.
    /// * uri corresponds to the (htu) claim.
    /// * method corresponds to the (htm) claim.
    /// * (jti) claim is present
    /// * (chal) claim is present
    /// * (iat) claim is present and no earlier or later than max_skew_secs seconds of now
    /// * (exp) claim is present and no larger (later) than max_expiration.
    /// * (exp) claim is no later than now plus max_skew_secs.
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
        _now: u64,
        _backend_keys: Pem,
    ) -> RustyJwtResult<String> {
        let header = Token::decode_metadata(dpop_proof)?;
        Self::validate_dpop_header(&header)?;
        Self::validate_dpop(
            &header,
            dpop_proof,
            client_id,
            backend_nonce,
            uri,
            method,
            max_expiration,
            max_skew_secs,
        )?;
        Ok(super::SAMPLE_TOKEN.to_string())
    }

    fn validate_dpop_header(header: &TokenMetadata) -> RustyJwtResult<()> {
        let typ = header.signature_type().ok_or(RustyJwtError::MissingDpopHeader("typ"))?;
        if typ != Dpop::TYP {
            return Err(RustyJwtError::InvalidDpopTyp);
        }
        // fails when the algorithm is not supported
        JwsAlgorithm::try_from(header.algorithm())?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_dpop(
        header: &TokenMetadata,
        dpop: &str,
        client_id: QualifiedClientId,
        backend_nonce: BackendNonce,
        uri: Htu,
        method: Htm,
        max_expiration: u64,
        leeway: u16,
    ) -> RustyJwtResult<()> {
        let jwk = header.public_key().ok_or(RustyJwtError::MissingDpopHeader("jwk"))?;
        let alg = JwsAlgorithm::try_from(header.algorithm())?;
        let verifications = Some(VerificationOptions {
            accept_future: false,
            required_key_id: None, // we don't verify the value, just enforce its presence
            required_subject: Some(client_id.subject()),
            required_nonce: Some(backend_nonce.into()),
            time_tolerance: Some(Duration::from_secs(leeway as u64)),
            ..Default::default()
        });
        let claims = match alg {
            JwsAlgorithm::P256 => ES256PublicKey::try_from_jwk(jwk)?.verify_token::<Dpop>(dpop, verifications),
            JwsAlgorithm::P384 => ES384PublicKey::try_from_jwk(jwk)?.verify_token::<Dpop>(dpop, verifications),
            JwsAlgorithm::Ed25519 => Ed25519PublicKey::try_from_jwk(jwk)?.verify_token::<Dpop>(dpop, verifications),
        }
        .map_err(|e| {
            let reason = e.to_string();
            // since `jwt_simple` returns [anyhow::Error] which we can't pattern match against
            // we have to parse the reason to "guess" the root cause
            match reason.as_str() {
                // standard claims failing because of [VerificationOptions]
                "Required subject missing" => RustyJwtError::MissingDpopClaim("sub"),
                "Required nonce missing" => RustyJwtError::MissingDpopClaim("nonce"),
                "Required subject mismatch" => RustyJwtError::DpopSubMismatch,
                "Required nonce mismatch" => RustyJwtError::DpopNonceMismatch,
                "Clock drift detected" => RustyJwtError::InvalidDpopIat,
                "Token has expired" => RustyJwtError::DpopExpired,
                // DPoP claims failing because of serde
                r if r.starts_with("missing field `chal`") => RustyJwtError::MissingDpopClaim("chal"),
                r if r.starts_with("missing field `htm`") => RustyJwtError::MissingDpopClaim("htm"),
                r if r.starts_with("missing field `htu`") => RustyJwtError::MissingDpopClaim("htu"),
                _ => RustyJwtError::InvalidToken(reason),
            }
        })?;

        claims.jwt_id.ok_or(RustyJwtError::MissingDpopClaim("jti"))?;
        let exp = claims.expires_at.ok_or(RustyJwtError::MissingDpopClaim("exp"))?;
        claims.issued_at.ok_or(RustyJwtError::MissingDpopClaim("iat"))?;

        if exp > Duration::from_secs(max_expiration) {
            return Err(RustyJwtError::DpopLivesTooLong);
        }

        if claims.custom.htu != uri {
            return Err(RustyJwtError::DpopHtuMismatch);
        }

        if claims.custom.htm != method {
            return Err(RustyJwtError::DpopHtmMismatch);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use jwt_simple::prelude::*;
    use wasm_bindgen_test::*;

    use crate::{dpop::Dpop, test_utils::*};

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    mod generated_access_token {
        use super::*;

        #[apply(all_keys)]
        #[test]
        fn should_have_jwt_typ(key: JwtKey) {
            let token = access_token(key.into()).unwrap();
            let header = Token::decode_metadata(token.as_str()).unwrap();
            assert_eq!(header.signature_type(), Some("JWT"))
        }
    }

    mod validate_dpop {
        use super::*;

        #[apply(all_keys)]
        #[test]
        fn typ(key: JwtKey) {
            // should fail when 'typ' header absent
            let dpop = JwtTestBuilder {
                typ: None,
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), key.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingDpopHeader(header) if header == "typ"));

            // should fail when wrong value
            let dpop = JwtTestBuilder {
                typ: Some("unknown+jwt"),
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), key.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidDpopTyp));

            // should be valid
            let dpop = JwtTestBuilder {
                typ: Some("dpop+jwt"),
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), key.into());
            assert!(result.is_ok());
        }

        #[apply(all_keys)]
        #[test]
        fn jwk(key: JwtKey) {
            // should fail when 'jwk' header absent
            let dpop = JwtTestBuilder {
                jwk: None,
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), key.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingDpopHeader(header) if header == "jwk"));

            // should be valid
            let dpop: JwtTestBuilder = key.clone().into();
            let result = access_token_with_dpop(&dpop.build(), key.into());
            assert!(result.is_ok());
        }

        #[apply(all_keys)]
        #[test]
        fn jwk_and_alg(key: JwtKey) {
            // should fail when 'jwk' is not of the 'alg' type
            let others = match key.alg {
                JwsAlgorithm::P256 => [JwsAlgorithm::P384, JwsAlgorithm::Ed25519],
                JwsAlgorithm::P384 => [JwsAlgorithm::P256, JwsAlgorithm::Ed25519],
                JwsAlgorithm::Ed25519 => [JwsAlgorithm::P256, JwsAlgorithm::P384],
            }
            .map(|a| a.to_string());
            for alg in others {
                let dpop = JwtTestBuilder {
                    alg,
                    ..key.clone().into()
                };
                let result = std::panic::catch_unwind(|| access_token_with_dpop(&dpop.build(), key.clone().into()));

                // 'generic-array' crate panics when points have different sizes
                if let Ok(result) = result {
                    assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidDpopJwk));
                }
            }
        }

        #[apply(all_keys)]
        #[test]
        fn alg(key: JwtKey) {
            let unsupported = &[
                "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES512",
            ]
            .map(|a| a.to_string());
            // should fail when 'alg' is not supported
            for alg in unsupported {
                let dpop = JwtTestBuilder {
                    alg: alg.clone(),
                    ..key.clone().into()
                };
                let result = access_token_with_dpop(&dpop.build(), key.clone().into());
                assert!(matches!(result.unwrap_err(), RustyJwtError::UnsupportedAlgorithm));
            }

            // should be valid
            let dpop = JwtTestBuilder {
                alg: key.alg.to_string(),
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), key.into());
            assert!(result.is_ok());
        }

        #[apply(all_keys)]
        #[test]
        fn signature(key: JwtKey) {
            // should succeed with valid signature
            let dpop: JwtTestBuilder = key.clone().into();
            let result = access_token_with_dpop(&dpop.build(), key.clone().into());
            assert!(result.is_ok());

            // should fail when signature not verified by jwk
            let other_jwk = JwtTestBuilder::from(JwtKey::new_key(key.alg)).jwk.unwrap();
            // dpop is signed with the former key
            let dpop = JwtTestBuilder {
                jwk: Some(other_jwk),
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), key.into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidToken(_)));
        }

        #[apply(all_keys)]
        #[test]
        fn sub(key: JwtKey) {
            // should succeed when client_id and jwk's 'sub' match
            let dpop = JwtTestBuilder {
                sub: Some(QualifiedClientId::alice()),
                ..key.clone().into()
            };
            let params = Params {
                client_id: QualifiedClientId::alice(),
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());

            // jwk's 'sub' is absent
            let mut dpop: JwtTestBuilder = key.clone().into();
            dpop.sub = None;
            let params = Params {
                client_id: QualifiedClientId::bob(),
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingDpopClaim(claim) if claim == "sub"));

            // should fail when client_id and jwk's 'sub' mismatch
            let dpop = JwtTestBuilder {
                sub: Some(QualifiedClientId::alice()),
                ..key.clone().into()
            };
            let params = Params {
                client_id: QualifiedClientId::bob(),
                ..key.into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::DpopSubMismatch));
        }

        #[apply(all_keys)]
        #[test]
        fn htu(key: JwtKey) {
            // should succeed when uri and jwk's 'htu' match
            let dpop = JwtTestBuilder {
                dpop: TestDpop {
                    htu: Some("https://a.com".try_into().unwrap()),
                    ..Default::default()
                },
                ..key.clone().into()
            };
            let params = Params {
                uri: "https://a.com".try_into().unwrap(),
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());

            // should fail when uri and jwk's 'htu' mismatch
            let dpop = JwtTestBuilder {
                dpop: TestDpop {
                    htu: Some("https://a.com".try_into().unwrap()),
                    ..Default::default()
                },
                ..key.clone().into()
            };
            let params = Params {
                uri: "https://b.com".try_into().unwrap(),
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::DpopHtuMismatch));

            // should fail when 'htu' is absent from dpop token
            let dpop = JwtTestBuilder {
                dpop: TestDpop {
                    htu: None,
                    ..Default::default()
                },
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), key.into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingDpopClaim(claim) if claim == "htu"));
        }

        #[apply(all_keys)]
        #[test]
        fn htm(key: JwtKey) {
            // should succeed when method and jwk's 'htm' match
            let dpop = JwtTestBuilder {
                dpop: TestDpop {
                    htm: Some(Htm::Post),
                    ..Default::default()
                },
                ..key.clone().into()
            };
            let params = Params {
                method: Htm::Post,
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());

            // should fail when method and jwk's 'htm' mismatch
            let dpop = JwtTestBuilder {
                dpop: TestDpop {
                    htm: Some(Htm::Post),
                    ..Default::default()
                },
                ..key.clone().into()
            };
            let params = Params {
                method: Htm::Put,
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::DpopHtmMismatch));

            // should fail when 'htm' is absent from dpop token
            let dpop = JwtTestBuilder {
                dpop: TestDpop {
                    htm: None,
                    ..Default::default()
                },
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), key.into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingDpopClaim(claim) if claim == "htm"));
        }

        #[apply(all_keys)]
        #[test]
        fn backend_nonce(key: JwtKey) {
            // should succeed when backend_nonce and jwk's 'nonce' match
            let nonce = BackendNonce::rand();
            let dpop = JwtTestBuilder {
                nonce: Some(nonce.clone()),
                ..key.clone().into()
            };
            let params = Params {
                backend_nonce: nonce,
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());

            // jwk's 'nonce' is absent
            let dpop = JwtTestBuilder {
                nonce: None,
                ..key.clone().into()
            };
            let params = Params {
                backend_nonce: BackendNonce::rand(),
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingDpopClaim(claim) if claim == "nonce"));

            // should fail when backend_nonce and jwk's 'nonce' mismatch
            let dpop = JwtTestBuilder {
                nonce: Some(BackendNonce::rand()),
                ..key.clone().into()
            };
            let params = Params {
                backend_nonce: BackendNonce::rand(),
                ..key.into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::DpopNonceMismatch));
        }

        #[apply(all_keys)]
        #[test]
        fn jti(key: JwtKey) {
            // should succeed when 'jti' claim is present in dpop token
            let dpop = JwtTestBuilder {
                jti: Some("ABCD".to_string()),
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), key.clone().into());
            assert!(result.is_ok());

            // should fail when 'jti' claim is absent from dpop token
            let dpop = JwtTestBuilder {
                jti: None,
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), key.into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingDpopClaim(claim) if claim == "jti"));
        }

        #[apply(all_keys)]
        #[test]
        fn challenge(key: JwtKey) {
            // should succeed when 'chal' (ACME challenge) claim is present in dpop token
            let dpop = JwtTestBuilder {
                dpop: TestDpop {
                    challenge: Some(AcmeChallenge::rand()),
                    ..Default::default()
                },
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), key.clone().into());
            assert!(result.is_ok());

            // should fail when 'chal' claim is absent from dpop token
            let dpop = JwtTestBuilder {
                dpop: TestDpop {
                    challenge: None,
                    ..Default::default()
                },
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), key.into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingDpopClaim(claim) if claim == "chal"));
        }

        #[apply(all_keys)]
        #[test]
        fn iat(key: JwtKey) {
            // should succeed when 'iat' claim is present in dpop token and in the past
            let yesterday = JwtTestBuilder::now() - Duration::from_days(1);
            let dpop = JwtTestBuilder {
                iat: Some(yesterday),
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), key.clone().into());
            assert!(result.is_ok());

            // should fail when 'iat' claim is absent from dpop token
            let dpop = JwtTestBuilder {
                iat: None,
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), key.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingDpopClaim(claim) if claim == "iat"));

            // should fail when issued in the future
            let tomorrow = JwtTestBuilder::now() + Duration::from_days(1);
            let dpop = JwtTestBuilder {
                iat: Some(tomorrow),
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), key.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidDpopIat));

            // should fail respecting leeway

            // will fail as there is no tolerance
            let in_1_h = JwtTestBuilder::now() + Duration::from_hours(1);
            let dpop = JwtTestBuilder {
                iat: Some(in_1_h),
                ..key.clone().into()
            };
            let params = Params {
                leeway: 0,
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidDpopIat));

            // will succeed as there is tolerance
            let dpop = JwtTestBuilder {
                iat: Some(in_1_h),
                ..key.clone().into()
            };
            let params = Params {
                leeway: 3600 + 10, // 1h + some test leeway
                ..key.into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());
        }

        #[apply(all_keys)]
        #[test]
        fn exp(key: JwtKey) {
            // should succeed when 'exp' claim is present in dpop token and in future
            let tomorrow = JwtTestBuilder::now() + Duration::from_days(1);
            let dpop = JwtTestBuilder {
                exp: Some(tomorrow),
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), key.clone().into());
            assert!(result.is_ok());

            // should fail when 'exp' claim is absent from dpop token
            let dpop = JwtTestBuilder {
                exp: None,
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), key.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::MissingDpopClaim(claim) if claim == "exp"));

            // should fail when 'exp' claim is in the past
            let yesterday = JwtTestBuilder::now() - Duration::from_days(1);
            let dpop = JwtTestBuilder {
                exp: Some(yesterday),
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), key.clone().into());
            assert!(matches!(result.unwrap_err(), RustyJwtError::DpopExpired));

            // should fail respecting leeway

            // will fail as there is no tolerance
            let previous_hour = JwtTestBuilder::now() - Duration::from_hours(1);
            let dpop = JwtTestBuilder {
                exp: Some(previous_hour),
                ..key.clone().into()
            };
            let params = Params {
                leeway: 0,
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::DpopExpired));

            // will succeed as there is tolerance
            let dpop = JwtTestBuilder {
                exp: Some(previous_hour),
                ..key.clone().into()
            };
            let params = Params {
                leeway: 3600 + 10, // 1h + some test leeway
                ..key.into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());
        }

        #[apply(all_keys)]
        #[test]
        fn exp_threshold(key: JwtKey) {
            // should succeed when 'exp' is sooner than supplied 'max_expiration'
            let tomorrow = JwtTestBuilder::now() + Duration::from_days(1);
            let day_after_tomorrow = tomorrow + Duration::from_days(1);

            let dpop = JwtTestBuilder {
                exp: Some(tomorrow),
                ..key.clone().into()
            };
            let params = Params {
                max_expiration: day_after_tomorrow.as_secs(),
                ..key.clone().into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(result.is_ok());

            // should fail when 'exp' is later than supplied 'max_expiration'
            let dpop = JwtTestBuilder {
                exp: Some(day_after_tomorrow),
                ..key.clone().into()
            };
            let params = Params {
                max_expiration: tomorrow.as_secs(),
                ..key.into()
            };
            let result = access_token_with_dpop(&dpop.build(), params);
            assert!(matches!(result.unwrap_err(), RustyJwtError::DpopLivesTooLong));
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    struct Params<'a> {
        pub dpop_alg: JwsAlgorithm,
        pub dpop: Dpop,
        pub client_id: QualifiedClientId<'a>,
        pub backend_nonce: BackendNonce,
        pub uri: Htu,
        pub method: Htm,
        pub leeway: u16,
        pub max_expiration: u64,
        pub now: u64,
        pub backend_keys: Pem,
    }

    impl From<JwtKey> for Params<'_> {
        fn from(key: JwtKey) -> Self {
            let backend_keys = key.kp;
            Self {
                dpop_alg: key.alg,
                dpop: Dpop::default(),
                client_id: QualifiedClientId::default(),
                backend_nonce: BackendNonce::default(),
                uri: Htu::default(),
                method: Htm::default(),
                leeway: 5,
                max_expiration: 2136351646, // somewhere in 2037
                now: JwtTestBuilder::now().as_secs(),
                backend_keys,
            }
        }
    }

    fn access_token(params: Params) -> RustyJwtResult<String> {
        let Params {
            dpop_alg,
            dpop,
            client_id,
            backend_nonce,
            backend_keys,
            ..
        } = params.clone();
        let dpop =
            RustyJwtTools::generate_dpop_token(dpop_alg, backend_keys, dpop, backend_nonce, client_id.clone()).unwrap();
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
            now,
            backend_keys,
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
            now,
            backend_keys,
        )
    }
}
