#![cfg(not(target_family = "wasm"))]

use jwt_simple::prelude::*;
use serde_json::{json, Value};
use testcontainers::clients::Cli;

use rusty_acme::prelude::*;
use rusty_jwt_tools::prelude::*;
use utils::{
    cfg::{E2eTest, EnrollmentFlow, OidcProvider},
    docker::{stepca::CaCfg, wiremock::WiremockImage},
    id_token::resign_id_token,
    rand_base64_str, rand_client_id,
    wire_server::OauthCfg,
    TestError,
};

#[path = "utils/mod.rs"]
mod utils;

fn docker() -> &'static Cli {
    Box::leak(Box::new(Cli::docker()))
}

/// Tests the nominal case and prints the pretty output with the mermaid chart in this crate README.
#[cfg(not(ci))]
#[tokio::test]
async fn demo_should_succeed() {
    let test = E2eTest::new_demo().start(docker()).await;
    assert!(test.nominal_enrollment().await.is_ok());
}

/// Tests the nominal case and prints the pretty output with the mermaid chart in this crate README.
#[ignore] // needs manual actions. Uncomment to try it.
#[cfg(not(ci))]
#[tokio::test]
async fn google_demo_should_succeed() {
    let default = E2eTest::new_demo();
    let issuer = "https://accounts.google.com".to_string();
    let client_secret = std::env::var("GOOGLE_E2EI_DEMO_CLIENT_SECRET")
        .expect("You have to set the client secret in the 'GOOGLE_E2EI_DEMO_CLIENT_SECRET' env variable");
    let audience = "338888153072-ktbh66pv3mr0ua0dn64sphgimeo0p7ss.apps.googleusercontent.com".to_string();
    let jwks_uri = "https://www.googleapis.com/oauth2/v3/certs".to_string();
    let domain = "wire.com";
    let new_sub =
        ClientId::try_from_raw_parts(default.sub.user_id.as_ref(), default.sub.device_id, domain.as_bytes()).unwrap();
    let test = E2eTest {
        domain: domain.to_string(),
        sub: new_sub,
        display_name: "Beltram Maldant".to_string(),
        handle: "beltram_wire".to_string(),
        oauth_cfg: OauthCfg {
            client_secret,
            client_id: audience.clone(),
            ..default.oauth_cfg
        },
        ca_cfg: CaCfg {
            issuer,
            audience,
            jwks_uri,
            ..default.ca_cfg
        },
        oidc_provider: OidcProvider::Google,
        ..default
    };
    let test = test.start(docker()).await;
    assert!(test.nominal_enrollment().await.is_ok());
}

/// Verify that it works for all MLS ciphersuites
#[cfg(not(ci))]
mod alg {
    use super::*;

    #[tokio::test]
    async fn ed25519_should_succeed() {
        let test = E2eTest::new().with_alg(JwsAlgorithm::Ed25519).start(docker()).await;
        assert!(test.nominal_enrollment().await.is_ok());
    }

    #[tokio::test]
    async fn p256_should_succeed() {
        let test = E2eTest::new().with_alg(JwsAlgorithm::P256).start(docker()).await;
        assert!(test.nominal_enrollment().await.is_ok());
    }

    // TODO: Fails because of hardcoded SHA-256 hash algorithm in stepca
    #[ignore]
    #[tokio::test]
    async fn p384_should_succeed() {
        let test = E2eTest::new().with_alg(JwsAlgorithm::P384).start(docker()).await;
        assert!(test.nominal_enrollment().await.is_ok());
    }
}

/// Since the acme server is a fork, verify its invariants are respected
#[cfg(not(ci))]
mod acme_server {
    use rusty_acme::prelude::RustyAcmeError;

    use super::*;

    /// Challenges returned by ACME server are mixed up
    #[should_panic]
    #[tokio::test]
    async fn should_fail_when_no_replay_nonce_requested() {
        let test = E2eTest::new().start(docker()).await;

        let flow = EnrollmentFlow {
            get_acme_nonce: Box::new(|test, _| {
                Box::pin(async move {
                    // this replay nonce has not been generated by the acme server
                    let unknown_replay_nonce = rand_base64_str(42);
                    Ok((test, unknown_replay_nonce))
                })
            }),
            ..Default::default()
        };
        test.enrollment(flow).await.unwrap();
    }

    /// Replay nonce is reused by the client
    #[should_panic]
    #[tokio::test]
    async fn should_fail_when_replay_nonce_reused() {
        let test = E2eTest::new().start(docker()).await;

        let flow = EnrollmentFlow {
            new_order: Box::new(|mut test, (directory, account, previous_nonce)| {
                Box::pin(async move {
                    // same nonce is used for both 'new_order' & 'new_authz'
                    let (order, order_url, _previous_nonce) =
                        test.new_order(&directory, &account, previous_nonce.clone()).await?;
                    let (_, previous_nonce) = test.new_authz(&account, order.clone(), previous_nonce).await?;
                    Ok((test, (order, order_url, previous_nonce)))
                })
            }),
            ..Default::default()
        };
        test.enrollment(flow).await.unwrap();
    }

    /// Challenges returned by ACME server are mixed up
    #[tokio::test]
    async fn should_fail_when_challenges_inverted() {
        let test = E2eTest::new().start(docker()).await;

        let real_chall = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (real_chall_setter, rc1, rc2) = (real_chall.clone(), real_chall.clone(), real_chall.clone());

        let flow = EnrollmentFlow {
            extract_challenges: Box::new(|mut test, authz| {
                Box::pin(async move {
                    let (dpop_chall, oidc_chall) = test.extract_challenges(authz)?;
                    *real_chall_setter.lock().unwrap() = Some(dpop_chall.clone());
                    // let's invert those challenges for the rest of the flow
                    Ok((test, (oidc_chall, dpop_chall)))
                })
            }),
            // undo the inversion here to verify that it fails on acme server side (we do not want to test wire-server here)
            create_dpop_token: Box::new(|mut test, (_, nonce, expiry)| {
                Box::pin(async move {
                    let challenge = rc1.lock().unwrap().clone().unwrap();
                    let dpop_token = test.create_dpop_token(&challenge, nonce, expiry).await?;
                    Ok((test, dpop_token))
                })
            }),
            get_access_token: Box::new(|mut test, (_, dpop_token)| {
                Box::pin(async move {
                    let challenge = rc2.lock().unwrap().clone().unwrap();
                    let access_token = test.get_access_token(&challenge, dpop_token).await?;
                    Ok((test, access_token))
                })
            }),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ClientImplementationError(
                "a challenge is not supposed to be pending at this point. It must either be 'valid' or 'processing'."
            ))
        ));
    }

    /// Since this call a custom method on our acme server fork, verify we satisfy the invariant:
    /// request payloads must be signed by the same client key which created the acme account.
    ///
    /// This verifies the DPoP challenge verification method on the acme server
    #[should_panic]
    #[tokio::test]
    async fn should_fail_when_dpop_challenge_signed_by_a_different_key() {
        let test = E2eTest::new().start(docker()).await;

        let flow = EnrollmentFlow {
            verify_dpop_challenge: Box::new(|mut test, (account, dpop_chall, access_token, previous_nonce)| {
                Box::pin(async move {
                    let old_kp = test.client_kp;
                    // use another key just for signing this request
                    test.client_kp = Ed25519KeyPair::generate().to_pem().into();
                    let previous_nonce = test
                        .verify_dpop_challenge(&account, dpop_chall, access_token, previous_nonce)
                        .await?;
                    test.client_kp = old_kp;
                    Ok((test, previous_nonce))
                })
            }),
            ..Default::default()
        };
        test.enrollment(flow).await.unwrap();
    }

    /// Since this call a custom method on our acme server fork, verify we satisfy the invariant:
    /// request payloads must be signed by the same client key which created the acme account.
    ///
    /// This verifies the DPoP challenge verification method on the acme server
    #[should_panic]
    #[tokio::test]
    async fn should_fail_when_oidc_challenge_signed_by_a_different_key() {
        let test = E2eTest::new().start(docker()).await;

        let flow = EnrollmentFlow {
            verify_oidc_challenge: Box::new(|mut test, (account, oidc_chall, access_token, previous_nonce)| {
                Box::pin(async move {
                    let old_kp = test.client_kp;
                    // use another key just for signing this request
                    test.client_kp = Ed25519KeyPair::generate().to_pem().into();
                    let previous_nonce = test
                        .verify_oidc_challenge(&account, oidc_chall, access_token, previous_nonce)
                        .await?;
                    test.client_kp = old_kp;
                    Ok((test, previous_nonce))
                })
            }),
            ..Default::default()
        };
        test.enrollment(flow).await.unwrap();
    }
}

#[cfg(not(ci))]
mod dpop_challenge {
    use super::*;

    /// Demonstrates that the client possesses the clientId. Client makes an authenticated request
    /// to wire-server, it delivers a nonce which the client seals in a signed DPoP JWT.
    #[should_panic]
    #[tokio::test]
    async fn should_fail_when_client_dpop_token_has_wrong_backend_nonce() {
        let test = E2eTest::new().start(docker()).await;

        let flow = EnrollmentFlow {
            create_dpop_token: Box::new(|mut test, (dpop_chall, backend_nonce, expiry)| {
                Box::pin(async move {
                    // use a different nonce than the supplied one
                    let wrong_nonce = rand_base64_str(32).into();
                    assert_ne!(wrong_nonce, backend_nonce);

                    let client_dpop_token = test.create_dpop_token(&dpop_chall, wrong_nonce, expiry).await?;
                    Ok((test, client_dpop_token))
                })
            }),
            ..Default::default()
        };
        test.enrollment(flow).await.unwrap();
    }

    /// Acme server should be configured with wire-server public key to verify the access tokens
    /// issued by wire-server.
    #[tokio::test]
    async fn should_fail_when_access_token_not_signed_by_wire_server() {
        let default = E2eTest::new();
        let wrong_backend_kp = Ed25519KeyPair::generate();
        let test = E2eTest {
            ca_cfg: CaCfg {
                sign_key: wrong_backend_kp.public_key().to_pem(),
                ..default.ca_cfg
            },
            ..default
        };
        let test = test.start(docker()).await;
        assert!(matches!(
            test.nominal_enrollment().await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ChallengeError(AcmeChallError::Invalid))
        ));
    }

    /// The access token has a 'chal' claim which should match the Acme challenge 'token'.
    /// This is verified by the acme server
    #[tokio::test]
    async fn should_fail_when_access_token_challenge_claim_is_not_current_challenge_one() {
        let test = E2eTest::new().start(docker()).await;

        let flow = EnrollmentFlow {
            create_dpop_token: Box::new(|mut test, (dpop_chall, backend_nonce, expiry)| {
                Box::pin(async move {
                    // alter the 'token' of the valid challenge
                    let wrong_dpop_chall = AcmeChallenge {
                        token: rand_base64_str(32),
                        ..dpop_chall
                    };
                    let client_dpop_token = test.create_dpop_token(&wrong_dpop_chall, backend_nonce, expiry).await?;
                    Ok((test, client_dpop_token))
                })
            }),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ChallengeError(AcmeChallError::Invalid))
        ));
    }

    /// We first set a clientId for the enrollment process when we create the acme order. This same
    /// clientId must be used and sealed in the accessToken which is verified by the acme server in
    /// the oidc challenge. The challenge should be invalid if they differ
    #[tokio::test]
    async fn should_fail_when_access_token_client_id_mismatches() {
        let test = E2eTest::new().start(docker()).await;

        let flow = EnrollmentFlow {
            new_order: Box::new(|mut test, (directory, account, previous_nonce)| {
                Box::pin(async move {
                    // just alter the clientId for the order creation...
                    let sub = test.sub.clone();
                    test.sub = rand_client_id(Some(sub.device_id));
                    let (order, order_url, previous_nonce) =
                        test.new_order(&directory, &account, previous_nonce).await?;
                    // ...then resume to the regular one to create the client dpop token & access token
                    test.sub = sub;
                    Ok((test, (order, order_url, previous_nonce)))
                })
            }),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ChallengeError(AcmeChallError::Invalid))
        ));
    }

    /// Client DPoP token is nested within access token. The former should not be expired when
    /// acme server verifies the DPoP challenge
    // TODO: not testable in practice because leeway of 360s is hardcoded in acme server
    #[ignore]
    #[should_panic]
    #[tokio::test]
    async fn should_fail_when_expired_client_dpop_token() {
        let test = E2eTest::new().start(docker()).await;

        let flow = EnrollmentFlow {
            create_dpop_token: Box::new(|mut test, (dpop_chall, backend_nonce, _expiry)| {
                Box::pin(async move {
                    let leeway = 360;
                    let expiry = core::time::Duration::from_secs(0);
                    let client_dpop_token = test.create_dpop_token(&dpop_chall, backend_nonce, expiry).await?;
                    tokio::time::sleep(core::time::Duration::from_secs(leeway + 1)).await;
                    Ok((test, client_dpop_token))
                })
            }),
            ..Default::default()
        };
        test.enrollment(flow).await.unwrap();
    }

    /// In order to tie DPoP challenge verification on the acme server, the latter is configured
    /// with the accepted wire-server host which is present in the DPoP "htu" claim and in the access token
    /// "iss" claim.
    /// The challenge should fail if any of those does not match the expected value
    #[tokio::test]
    async fn should_fail_when_access_token_iss_mismatches_target() {
        // "iss" in access token mismatches expected target
        let test = E2eTest::new().start(docker()).await;
        let flow = EnrollmentFlow {
            get_access_token: Box::new(|test, _| {
                Box::pin(async move {
                    let client_id = test.sub.clone();
                    let htu: Htu = "https://unknown.io".try_into().unwrap();
                    let backend_nonce: BackendNonce = rand_base64_str(32).into();
                    let acme_nonce = rand_base64_str(32).into();

                    let client_dpop_token = RustyJwtTools::generate_dpop_token(
                        Dpop {
                            htm: Htm::Post,
                            htu: htu.clone(),
                            challenge: acme_nonce,
                            extra_claims: None,
                        },
                        &client_id,
                        backend_nonce.clone(),
                        core::time::Duration::from_secs(3600),
                        test.alg,
                        &test.client_kp,
                    )
                    .unwrap();

                    let backend_kp: Pem = test.backend_kp.clone();
                    let access_token = RustyJwtTools::generate_access_token(
                        &client_dpop_token,
                        &client_id,
                        backend_nonce,
                        htu,
                        Htm::Post,
                        360,
                        2136351646,
                        backend_kp,
                        test.hash_alg,
                        5,
                    )
                    .unwrap();
                    Ok((test, access_token))
                })
            }),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ChallengeError(AcmeChallError::Invalid))
        ));
    }

    /// see [should_fail_when_access_token_iss_mismatches_target]
    #[tokio::test]
    async fn should_fail_when_access_token_device_id_mismatches_target() {
        // "iss" deviceId mismatches the actual deviceId
        let test = E2eTest::new().start(docker()).await;
        let flow = EnrollmentFlow {
            get_access_token: Box::new(|test, _| {
                Box::pin(async move {
                    // here the DeviceId will be different in "sub" than in "iss" (in the access token)
                    let client_id = ClientId {
                        device_id: 42,
                        ..test.sub.clone()
                    };
                    let htu: Htu = test
                        .ca_cfg
                        .dpop_target_uri
                        .as_ref()
                        .unwrap()
                        .as_str()
                        .try_into()
                        .unwrap();
                    let backend_nonce: BackendNonce = rand_base64_str(32).into();
                    let acme_nonce = rand_base64_str(32).into();

                    let client_dpop_token = RustyJwtTools::generate_dpop_token(
                        Dpop {
                            htm: Htm::Post,
                            htu: htu.clone(),
                            challenge: acme_nonce,
                            extra_claims: None,
                        },
                        &client_id,
                        backend_nonce.clone(),
                        core::time::Duration::from_secs(3600),
                        test.alg,
                        &test.client_kp,
                    )
                    .unwrap();

                    let backend_kp: Pem = test.backend_kp.clone();
                    let access_token = RustyJwtTools::generate_access_token(
                        &client_dpop_token,
                        &client_id,
                        backend_nonce,
                        htu,
                        Htm::Post,
                        360,
                        2136351646,
                        backend_kp,
                        test.hash_alg,
                        5,
                    )
                    .unwrap();
                    Ok((test, access_token))
                })
            }),
            ..Default::default()
        };
        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ChallengeError(AcmeChallError::Invalid))
        ));
    }
}

#[cfg(not(ci))]
mod oidc_challenge {
    use super::*;

    /// Authorization Server (Dex in our case) exposes an endpoint for clients to fetch its public keys.
    /// It is used to validate the signature of the id token we supply to this challenge.
    #[tokio::test]
    async fn should_fail_when_oidc_provider_jwks_uri_unavailable() {
        let mut test = E2eTest::new();
        // invalid jwks uri
        let mut jwks_uri: url::Url = test.ca_cfg.jwks_uri.parse().unwrap();
        jwks_uri.set_port(Some(jwks_uri.port().unwrap() + 1)).unwrap();
        test.ca_cfg.jwks_uri = jwks_uri.to_string();
        let test = test.start(docker()).await;

        // cannot validate the OIDC challenge
        assert!(matches!(
            test.nominal_enrollment().await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ClientImplementationError(
                "a challenge is not supposed to be pending at this point. It must either be 'valid' or 'processing'."
            ))
        ));
    }

    /// Authorization Server (Dex in our case) exposes an endpoint for clients to fetch its public keys.
    /// It is used to validate the signature of the id token we supply to this challenge.
    /// Here, the AS will return a valid JWKS URI but it contains an invalid public key
    /// for verifying the id token.
    #[tokio::test]
    async fn should_fail_when_malicious_jwks_uri() {
        let docker = docker();

        let mut test = E2eTest::new();
        let (jwks_stub, ..) = test.new_jwks_uri_mock();
        // this starts a server serving the abose stub with a malicious JWK
        let attacker_host = "attacker-dex";
        let _attacker_dex = WiremockImage::run(docker, attacker_host, vec![jwks_stub]);

        // invalid jwks uri
        test.ca_cfg.jwks_uri = format!("http://{attacker_host}/oauth2/jwks");
        let test = test.start(docker).await;

        // cannot validate the OIDC challenge
        assert!(matches!(
            test.nominal_enrollment().await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ClientImplementationError(
                "a challenge is not supposed to be pending at this point. It must either be 'valid' or 'processing'."
            ))
        ));
    }

    /// An id token with an invalid name is supplied to ACME server. It should verify that the handle
    /// is the same as the one used in the order.
    #[tokio::test]
    async fn should_fail_when_invalid_handle() {
        let docker = docker();
        let mut test = E2eTest::new();

        // setup fake jwks_uri to be able to resign the id token
        let (jwks_stub, new_kp, kid) = test.new_jwks_uri_mock();
        let attacker_host = "attacker-dex";
        let _attacker_dex = WiremockImage::run(docker, attacker_host, vec![jwks_stub]);
        test.ca_cfg.jwks_uri = format!("https://{attacker_host}/oauth2/jwks");

        let test = test.start(docker).await;

        let flow = EnrollmentFlow {
            fetch_id_token: Box::new(|mut test, oidc_chall| {
                Box::pin(async move {
                    let dex_pk = test.fetch_dex_public_key().await;
                    let dex_pk = RS256PublicKey::from_pem(&dex_pk).unwrap();
                    let id_token = test.fetch_id_token(&oidc_chall).await?;

                    let change_handle = |mut claims: JWTClaims<Value>| {
                        let wrong_handle = format!("{}john.doe.qa@wire.com", ClientId::URI_PREFIX);
                        *claims.custom.get_mut("name").unwrap() = json!(wrong_handle);
                        claims
                    };
                    let modified_id_token = resign_id_token(&id_token, dex_pk, kid, new_kp, change_handle);
                    Ok((test, modified_id_token))
                })
            }),
            ..Default::default()
        };

        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ClientImplementationError(
                "a challenge is not supposed to be pending at this point. It must either be 'valid' or 'processing'."
            ))
        ));
    }

    /// An id token with an invalid name is supplied to ACME server. It should verify that the display name
    /// is the same as the one used in the order.
    #[tokio::test]
    async fn should_fail_when_invalid_display_name() {
        let docker = docker();
        let mut test = E2eTest::new();

        // setup fake jwks_uri to be able to resign the id token
        let (jwks_stub, new_kp, kid) = test.new_jwks_uri_mock();
        let attacker_host = "attacker-dex";
        let _attacker_dex = WiremockImage::run(docker, attacker_host, vec![jwks_stub]);
        test.ca_cfg.jwks_uri = format!("https://{attacker_host}/oauth2/jwks");

        let test = test.start(docker).await;

        let flow = EnrollmentFlow {
            fetch_id_token: Box::new(|mut test, oidc_chall| {
                Box::pin(async move {
                    let dex_pk = test.fetch_dex_public_key().await;
                    let dex_pk = RS256PublicKey::from_pem(&dex_pk).unwrap();
                    let id_token = test.fetch_id_token(&oidc_chall).await?;

                    let change_handle = |mut claims: JWTClaims<Value>| {
                        let wrong_handle = "Doe, John (QA)";
                        *claims.custom.get_mut("preferred_username").unwrap() = json!(wrong_handle);
                        claims
                    };
                    let modified_id_token = resign_id_token(&id_token, dex_pk, kid, new_kp, change_handle);
                    Ok((test, modified_id_token))
                })
            }),
            ..Default::default()
        };

        assert!(matches!(
            test.enrollment(flow).await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ClientImplementationError(
                "a challenge is not supposed to be pending at this point. It must either be 'valid' or 'processing'."
            ))
        ));
    }

    /// An audience field is configured on CA server. The OIDC challenge should fail when the 'aud'
    /// claim in the id token mismatches the expected audience configured in the CA server.
    #[tokio::test]
    async fn should_fail_when_invalid_audience() {
        let docker = docker();
        let default = E2eTest::new();
        let test = E2eTest {
            ca_cfg: CaCfg {
                audience: "unknown".to_string(),
                ..default.ca_cfg
            },
            ..default
        };

        let test = test.start(docker).await;
        assert!(matches!(
            test.nominal_enrollment().await.unwrap_err(),
            TestError::Acme(RustyAcmeError::ClientImplementationError(
                "a challenge is not supposed to be pending at this point. It must either be 'valid' or 'processing'."
            ))
        ));
    }
}

/// Further improvements
#[cfg(not(ci))]
mod optimize {
    use super::*;

    #[tokio::test]
    async fn should_validate_challenges_in_parallel() {
        let docker = Box::leak(Box::new(Cli::docker()));
        let mut test = E2eTest::new().start(docker).await;
        let directory = test.get_acme_directory().await.unwrap();
        let previous_nonce = test.get_acme_nonce(&directory).await.unwrap();
        let (account, previous_nonce) = test.new_account(&directory, previous_nonce).await.unwrap();
        let (order, order_url, previous_nonce) = test.new_order(&directory, &account, previous_nonce).await.unwrap();
        let (authz, previous_nonce) = test.new_authz(&account, order, previous_nonce).await.unwrap();
        let (dpop_chall, oidc_chall) = test.extract_challenges(authz).unwrap();

        let test = std::sync::Arc::new(tokio::sync::Mutex::new(test));
        let t1 = test.clone();
        let account = std::sync::Arc::new(account);
        let acc1 = account.clone();

        let previous_nonce = tokio::task::spawn(async move {
            let mut test = t1.lock().await;
            let backend_nonce = test.get_wire_server_nonce().await.unwrap();
            let expiry = core::time::Duration::from_secs(3600);
            let client_dpop_token = test
                .create_dpop_token(&dpop_chall, backend_nonce, expiry)
                .await
                .unwrap();
            let access_token = test.get_access_token(&dpop_chall, client_dpop_token).await.unwrap();
            test.verify_dpop_challenge(&acc1, dpop_chall, access_token, previous_nonce)
                .await
                .unwrap()
        })
        .await
        .unwrap();

        let t2 = test.clone();
        let acc2 = account.clone();

        tokio::task::spawn(async move {
            let mut test = t2.lock().await;
            let previous_nonce = test.get_acme_nonce(&directory).await.unwrap();
            let id_token = test.fetch_id_token(&oidc_chall).await.unwrap();
            test.verify_oidc_challenge(&acc2, oidc_chall, id_token, previous_nonce)
                .await
                .unwrap();
        })
        .await
        .unwrap();

        let mut test = test.lock().await;
        let (order, previous_nonce) = test
            .verify_order_status(&account, order_url, previous_nonce)
            .await
            .unwrap();
        let (finalize, previous_nonce) = test.finalize(&account, &order, previous_nonce).await.unwrap();
        use std::ops::Deref as _;
        test.get_x509_certificates(account.deref().clone(), finalize, order, previous_nonce)
            .await
            .unwrap();
    }
}
