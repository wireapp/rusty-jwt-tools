use base64::Engine;
use const_oid::db::{
    rfc5912::{ID_EC_PUBLIC_KEY, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1},
    rfc8410::ID_ED_25519,
};
use const_oid::{AssociatedOid as _, ObjectIdentifier};
use itertools::Itertools;
use jwt_simple::prelude::*;
use oauth2::{CsrfToken, PkceCodeChallenge, RedirectUrl, RefreshToken, Scope};
use openidconnect::{
    IssuerUrl, Nonce,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
};
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::collections::{HashMap, hash_map::RandomState};
use url::Url;
use x509_cert::Certificate;
use x509_cert::der::asn1::Ia5String;
use x509_cert::der::{Decode as _, DecodePem, Encode as _};
use x509_cert::ext::pkix::constraints::name::GeneralSubtree;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{KeyUsage, KeyUsages, NameConstraints};

use http::header;
use rusty_acme::prelude::x509::revocation::PkiEnvironment;
use rusty_acme::prelude::*;
use rusty_jwt_tools::{
    jwk::{TryFromJwk, TryIntoJwk},
    prelude::*,
};

use crate::utils::{
    TestError, TestResult,
    cfg::{E2eTest, EnrollmentFlow, OidcProvider, scrap_login},
    ctx::*,
    display::Actor,
    docker::stepca,
    helpers::{AcmeAsserter, ClientHelper, RespHelper},
    rand_base64_str,
};

fn keypair_to_pubkey(alg: JwsAlgorithm, keypair: &Pem) -> Pem {
    match alg {
        JwsAlgorithm::P256 => ES256KeyPair::from_pem(keypair)
            .unwrap()
            .public_key()
            .to_pem()
            .unwrap()
            .into(),
        JwsAlgorithm::P384 => ES384KeyPair::from_pem(keypair)
            .unwrap()
            .public_key()
            .to_pem()
            .unwrap()
            .into(),
        JwsAlgorithm::P521 => ES512KeyPair::from_pem(keypair)
            .unwrap()
            .public_key()
            .to_pem()
            .unwrap()
            .into(),
        JwsAlgorithm::Ed25519 => Ed25519KeyPair::from_pem(keypair).unwrap().public_key().to_pem().into(),
    }
}

fn jws_algorithm_to_x509_oids(alg: JwsAlgorithm) -> (ObjectIdentifier, Option<ObjectIdentifier>) {
    match alg {
        JwsAlgorithm::Ed25519 => (ID_ED_25519, None),
        JwsAlgorithm::P256 => (ID_EC_PUBLIC_KEY, Some(SECP_256_R_1)),
        JwsAlgorithm::P384 => (ID_EC_PUBLIC_KEY, Some(SECP_384_R_1)),
        JwsAlgorithm::P521 => (ID_EC_PUBLIC_KEY, Some(SECP_521_R_1)),
    }
}

impl E2eTest {
    // @SF.PROVISIONING @TSFI.E2EI-PKI-Admin @S8
    pub async fn nominal_enrollment(self) -> TestResult<Self> {
        self.enrollment(EnrollmentFlow::default()).await
    }

    pub async fn enrollment(self, f: EnrollmentFlow) -> TestResult<Self> {
        let (t, directory) = (f.acme_directory)(self, ()).await?;
        let (t, previous_nonce) = (f.get_acme_nonce)(t, directory.clone()).await?;
        let (t, (account, previous_nonce)) = (f.new_account)(t, (directory.clone(), previous_nonce)).await?;
        let (t, (order, order_url, previous_nonce)) =
            (f.new_order)(t, (directory.clone(), account.clone(), previous_nonce)).await?;
        let (t, (authz_a, authz_b, previous_nonce)) =
            (f.new_authorization)(t, (account.clone(), order, previous_nonce)).await?;
        let (t, (dpop_chall, oidc_chall)) = (f.extract_challenges)(t, (authz_a.clone(), authz_b.clone())).await?;

        let thumbprint = JwkThumbprint::generate(&t.acme_jwk, t.hash_alg)?.kid;
        let oidc_chall_token = &oidc_chall.token;
        let keyauth = format!("{oidc_chall_token}.{thumbprint}");

        let (t, backend_nonce) = (f.get_wire_server_nonce)(t, ()).await?;
        let expiry = core::time::Duration::from_secs(3600);
        let handle = Handle::from(t.handle.as_str())
            .try_to_qualified(t.domain.as_str())
            .unwrap();
        let team = t.team.clone().into();
        let display_name = t.display_name.clone();
        let (t, client_dpop_token) = (f.create_dpop_token)(
            t,
            (dpop_chall.clone(), backend_nonce, handle, team, display_name, expiry),
        )
        .await?;
        let (t, access_token) = (f.get_access_token)(t, (dpop_chall.clone(), client_dpop_token)).await?;
        let (t, previous_nonce) =
            (f.verify_dpop_challenge)(t, (account.clone(), dpop_chall, access_token, previous_nonce)).await?;
        let (t, id_token) = (f.fetch_id_token)(t, (oidc_chall.clone(), keyauth)).await?;
        let (t, previous_nonce) =
            (f.verify_oidc_challenge)(t, (account.clone(), oidc_chall, id_token, previous_nonce)).await?;
        let (t, (order, previous_nonce)) =
            (f.verify_order_status)(t, (account.clone(), order_url, previous_nonce)).await?;
        let (t, (finalize, previous_nonce)) = (f.finalize)(t, (account.clone(), order.clone(), previous_nonce)).await?;
        let (mut t, _) = (f.get_x509_certificates)(t, (account, finalize, order, previous_nonce)).await?;
        t.display();
        Ok(t)
    }
}

impl E2eTest {
    /// GET http://acme-server/directory
    pub async fn get_acme_directory(&mut self) -> TestResult<AcmeDirectory> {
        let ca_url = self.acme_server.as_ref().ok_or(TestError::Internal)?.uri.clone();
        self.display_chapter("Initial setup with ACME server");
        // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1
        self.display_step("fetch acme directory for hyperlinks");
        let directory_url = format!("{ca_url}/acme/{}/directory", stepca::ACME_PROVISIONER);
        let req = self.client.get(&directory_url).build()?;
        self.display_req(
            Actor::WireClient,
            Actor::AcmeServer,
            Some(&req),
            Some("/acme/{acme-provisioner}/directory"),
        );

        self.display_step("get the ACME directory with links for newNonce, newAccount & newOrder");
        let mut resp = self.client.execute(req).await?;
        self.display_resp(Actor::AcmeServer, Actor::WireClient, Some(&resp));
        resp.expect_status(StatusCode::OK).expect_content_type_json();
        let resp = resp.json::<Value>().await?;
        let directory = RustyAcme::acme_directory_response(resp)?;
        self.display_body(&directory);
        Ok(directory)
    }

    /// GET http://acme-server/new-nonce
    pub async fn get_acme_nonce(&mut self, directory: &AcmeDirectory) -> TestResult<String> {
        // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.2
        self.display_step("fetch a new nonce for the very first request");
        let new_nonce_url = directory.new_nonce.as_str();
        let req = self.client.head(new_nonce_url).build()?;
        self.display_req(
            Actor::WireClient,
            Actor::AcmeServer,
            Some(&req),
            Some("/acme/{acme-provisioner}/new-nonce"),
        );

        self.display_step("get a nonce for creating an account");
        let mut resp = self.client.execute(req).await?;
        self.display_resp(Actor::AcmeServer, Actor::WireClient, Some(&resp));
        resp.expect_status(StatusCode::OK)
            .expect_header_value(header::CACHE_CONTROL, "no-store")
            .has_replay_nonce();
        let previous_nonce = resp.replay_nonce();
        self.display_str(&previous_nonce, false);
        Ok(previous_nonce)
    }

    /// POST http://acme-server/new-account
    pub async fn new_account(
        &mut self,
        directory: &AcmeDirectory,
        previous_nonce: String,
    ) -> TestResult<(AcmeAccount, String)> {
        // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3
        self.display_step("create a new account");
        let account_req = RustyAcme::new_account_request(directory, self.alg, &self.acme_kp, previous_nonce)?;
        let req = self.client.acme_req(&directory.new_account, &account_req)?;
        self.display_req(
            Actor::WireClient,
            Actor::AcmeServer,
            Some(&req),
            Some("/acme/{acme-provisioner}/new-account"),
        );
        self.display_body(&account_req);

        self.display_step("account created");
        let mut resp = self.client.execute(req).await?;
        self.display_resp(Actor::AcmeServer, Actor::WireClient, Some(&resp));

        if resp.status() != StatusCode::CREATED && resp.status() != StatusCode::OK {
            return Err(TestError::AccountCreationError);
        }
        resp.expect_status_success()
            .has_replay_nonce()
            .has_location()
            .expect_content_type_json();
        let previous_nonce = resp.replay_nonce();
        let account = RustyAcme::new_account_response(resp.json().await.unwrap())?;
        self.display_body(&account);
        Ok((account, previous_nonce))
    }

    /// POST http://acme-server/new-order
    pub async fn new_order(
        &mut self,
        directory: &AcmeDirectory,
        account: &AcmeAccount,
        previous_nonce: String,
    ) -> TestResult<(AcmeOrder, Url, String)> {
        // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
        self.display_chapter("Request a certificate with relevant identifiers");
        self.display_step("create a new order");
        let expiry = core::time::Duration::from_secs(3600 * 24 * 365 * 10); // 10 years
        let order_request = RustyAcme::new_order_request(
            &self.display_name,
            self.sub.clone(),
            &self.handle.clone().into(),
            expiry,
            directory,
            account,
            self.alg,
            &self.acme_kp,
            previous_nonce,
        )?;
        let req = self.client.acme_req(&directory.new_order, &order_request)?;
        self.display_req(
            Actor::WireClient,
            Actor::AcmeServer,
            Some(&req),
            Some("/acme/{acme-provisioner}/new-order"),
        );
        self.display_body(&order_request);

        self.display_step("get new order with authorization URLS and finalize URL");
        let mut resp = self.client.execute(req).await?;
        self.display_resp(Actor::AcmeServer, Actor::WireClient, Some(&resp));
        let previous_nonce = resp.replay_nonce();
        let order_url = resp.location_url();
        resp.expect_status(StatusCode::CREATED)
            .has_replay_nonce()
            .has_location()
            .expect_content_type_json();
        let resp = resp.json().await?;
        let new_order = RustyAcme::new_order_response(resp)?;
        self.display_body(&new_order);
        Ok((new_order, order_url, previous_nonce))
    }

    /// POST http://acme-server/authz
    pub async fn new_authorization(
        &mut self,
        account: &AcmeAccount,
        order: AcmeOrder,
        mut previous_nonce: String,
    ) -> TestResult<(AcmeAuthz, AcmeAuthz, String)> {
        self.display_chapter("Display-name and handle already authorized");
        self.display_step("create authorization and fetch challenges");

        let mut first_authz = None;

        for (i, authz_url) in order.authorizations.iter().enumerate() {
            let authz_req =
                RustyAcme::new_authz_request(authz_url, account, self.alg, &self.acme_kp, previous_nonce.clone())?;
            let req = self.client.acme_req(authz_url, &authz_req)?;
            self.display_req(
                Actor::WireClient,
                Actor::AcmeServer,
                Some(&req),
                Some("/acme/{acme-provisioner}/authz/{authz-id}"),
            );
            self.display_body(&authz_req);

            self.display_step("get back challenges");
            let mut resp = self.client.execute(req).await?;
            self.display_resp(Actor::AcmeServer, Actor::WireClient, Some(&resp));
            let local_previous_nonce = resp.replay_nonce();

            if resp.status() != StatusCode::OK {
                return Err(TestError::AuthzCreationError);
            }

            resp.expect_status(StatusCode::OK)
                .has_replay_nonce()
                .has_location()
                .expect_content_type_json();
            let resp = resp.json().await?;
            let authz = RustyAcme::new_authz_response(resp)?;
            self.display_body(&authz);

            if i == 0 {
                first_authz = Some(authz);
                previous_nonce = local_previous_nonce;
            } else {
                return Ok((first_authz.unwrap(), authz, local_previous_nonce));
            }
        }
        unreachable!()
    }

    /// extract challenges
    pub fn extract_challenges(
        &mut self,
        authz_a: AcmeAuthz,
        authz_b: AcmeAuthz,
    ) -> TestResult<(AcmeChallenge, AcmeChallenge)> {
        let [challenge_a] = authz_a.challenges;
        let [challenge_b] = authz_b.challenges;
        Ok((challenge_a, challenge_b))
    }

    /// HEAD http://wire-server/nonce
    pub async fn get_wire_server_nonce(&mut self) -> TestResult<BackendNonce> {
        self.display_chapter("Client fetches JWT DPoP access token (with wire-server)");
        self.display_step("fetch a nonce from wire-server");
        let nonce_url = format!("{}/clients/token/nonce", self.wire_server_uri());
        let req = self.client.get(nonce_url).build()?;
        self.display_req(Actor::WireClient, Actor::WireServer, Some(&req), None);

        self.display_step("get wire-server nonce");
        let mut resp = self.client.execute(req).await?;

        self.display_resp(Actor::WireServer, Actor::WireClient, Some(&resp));
        resp.expect_status(StatusCode::OK);
        let backend_nonce: BackendNonce = resp.text().await?.into();
        self.display_str(&backend_nonce, false);
        Ok(backend_nonce)
    }

    /// POST http://wire-server/client-dpop-token
    pub async fn create_dpop_token(
        &mut self,
        dpop_chall: &AcmeChallenge,
        backend_nonce: BackendNonce,
        handle: QualifiedHandle,
        team: Team,
        display_name: String,
        expiry: core::time::Duration,
    ) -> TestResult<String> {
        self.display_step("create client DPoP token");
        let htu: Htu = dpop_chall.target.clone().into();
        let audience = dpop_chall.url.clone();
        let acme_nonce: AcmeNonce = dpop_chall.token.as_str().into();
        let dpop = Dpop {
            challenge: acme_nonce,
            htm: Htm::Post,
            htu,
            handle,
            team,
            display_name,
            extra_claims: None,
        };
        let client_dpop_token = RustyJwtTools::generate_dpop_token(
            dpop,
            &self.sub,
            backend_nonce,
            audience,
            expiry,
            self.alg,
            &self.acme_kp,
        )?;
        let alg = self.alg;
        let pubkey = keypair_to_pubkey(alg, &self.acme_kp);
        self.display_operation(Actor::WireClient, "create DPoP token");
        self.display_token("Dpop token", &client_dpop_token, Some(alg), &pubkey);
        Ok(client_dpop_token)
    }

    /// POST http://wire-server/client-dpop-token
    pub async fn get_access_token(
        &mut self,
        dpop_chall: &AcmeChallenge,
        client_dpop_token: String,
    ) -> TestResult<String> {
        self.display_step("trade client DPoP token for an access token");

        let dpop_url = dpop_chall.target.to_string();
        let b64 = |v: &str| base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(v);

        // cheat to share test context
        ctx_store("client-id", self.sub.to_uri());
        ctx_store("backend-kp", self.backend_kp.to_string());
        ctx_store("hash-alg", self.hash_alg.to_string());
        ctx_store("wire-server-uri", dpop_url.clone());
        ctx_store("handle", self.handle.as_str());
        ctx_store("display_name", self.display_name.as_str());
        ctx_store("team", self.team.as_ref().unwrap());

        let req = self
            .client
            .post(&dpop_url)
            .header("dpop", b64(&client_dpop_token))
            .build()?;
        self.display_req(
            Actor::WireClient,
            Actor::WireServer,
            Some(&req),
            Some("/clients/{device-id}/access-token"),
        );

        self.display_step("get a Dpop access token from wire-server");
        let mut resp = self.client.execute(req).await.map_err(|_| TestError::WireServerError)?;
        // .expect("wire-server failed to generate an access token");
        self.display_resp(Actor::WireServer, Actor::WireClient, Some(&resp));
        resp.expect_status(StatusCode::OK);
        let resp = resp.json::<Value>().await?;
        self.display_body(&resp);
        let access_token = resp
            .as_object()
            .and_then(|o| o.get("token"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or(TestError::Internal)?;
        let alg = self.alg;
        let pubkey = keypair_to_pubkey(alg, &self.backend_kp);
        self.display_token("Access token", &access_token, Some(alg), &pubkey);
        Ok(access_token)
    }

    /// client id (dpop) challenge
    /// POST http://acme-server/challenge
    pub async fn verify_dpop_challenge(
        &mut self,
        account: &AcmeAccount,
        dpop_chall: AcmeChallenge,
        access_token: String,
        previous_nonce: String,
    ) -> TestResult<String> {
        // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
        self.display_chapter("Client provides access token");
        self.display_step("validate Dpop challenge (clientId)");
        let dpop_chall_url = dpop_chall.url.clone();
        let dpop_chall_req = RustyAcme::dpop_chall_request(
            access_token.clone(),
            dpop_chall,
            account,
            self.alg,
            &self.acme_kp,
            previous_nonce,
        )?;
        let req = self.client.acme_req(&dpop_chall_url, &dpop_chall_req)?;
        self.display_req(
            Actor::WireClient,
            Actor::AcmeServer,
            Some(&req),
            Some("/acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}"),
        );
        self.display_body(&dpop_chall_req);

        self.display_step("DPoP challenge is valid");
        let mut resp = self.client.execute(req).await?;
        self.display_resp(Actor::AcmeServer, Actor::WireClient, Some(&resp));
        let previous_nonce = resp.replay_nonce();

        if resp.status() != StatusCode::OK {
            return Err(TestError::DpopChallengeError);
        }

        resp.expect_status(StatusCode::OK)
            .has_replay_nonce()
            .has_location()
            .expect_content_type_json();
        let resp = resp.json().await?;
        let resp = RustyAcme::new_chall_response(resp)?;
        self.display_body(&resp);
        Ok(previous_nonce)
    }

    /// handle (oidc) challenge
    /// POST http://acme-server/challenge
    pub async fn verify_oidc_challenge(
        &mut self,
        account: &AcmeAccount,
        oidc_chall: AcmeChallenge,
        id_token: String,
        previous_nonce: String,
    ) -> TestResult<String> {
        // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
        self.display_step("validate oidc challenge (userId + displayName)");

        let oidc_chall_url = oidc_chall.url.clone();
        let idp_pubkey = self.fetch_idp_public_key().await;
        self.display_token("OIDC Id token", &id_token, None, &idp_pubkey);

        self.display_note("The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.");

        let oidc_chall_req =
            RustyAcme::oidc_chall_request(id_token, oidc_chall, account, self.alg, &self.acme_kp, previous_nonce)?;
        let req = self.client.acme_req(&oidc_chall_url, &oidc_chall_req)?;
        self.display_req(
            Actor::WireClient,
            Actor::AcmeServer,
            Some(&req),
            Some("/acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}"),
        );
        self.display_body(&oidc_chall_req);

        self.display_step("OIDC challenge is valid");
        let mut resp = self.client.execute(req).await?;

        self.display_resp(Actor::AcmeServer, Actor::WireClient, Some(&resp));
        let previous_nonce = resp.replay_nonce();

        // tokio::time::sleep(core::time::Duration::from_secs(10)).await;

        if resp.status() != StatusCode::OK {
            return Err(TestError::OidcChallengeError);
        }

        resp.expect_status(StatusCode::OK)
            .has_replay_nonce()
            .has_location()
            .expect_content_type_json();
        let resp = resp.json().await?;
        let resp = RustyAcme::new_chall_response(resp)?;
        self.display_body(&resp);
        Ok(previous_nonce)
    }

    pub async fn fetch_id_token(&mut self, oidc_chall: &AcmeChallenge, keyauth: String) -> TestResult<String> {
        match self.oidc_provider {
            OidcProvider::Keycloak => self.fetch_id_token_from_keycloak(oidc_chall, keyauth).await,
        }
    }

    pub async fn fetch_id_token_from_keycloak(
        &mut self,
        oidc_chall: &AcmeChallenge,
        keyauth: String,
    ) -> TestResult<String> {
        self.display_chapter("Authenticate end user using OIDC Authorization Code with PKCE flow");
        let oidc_target = oidc_chall.target.to_string();

        let mut oidc_target = url::Url::parse(&oidc_target).unwrap();
        let local_port = self.keycloak_cfg.http_host_port;
        oidc_target.set_port(Some(local_port)).unwrap();

        let issuer_url = IssuerUrl::new(oidc_target.as_str().to_string()).unwrap();

        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url.clone(), &async |r| {
            custom_oauth_client("discovery", ctx_get_http_client(), r).await
        })
        .await
        .unwrap();

        let client_id = openidconnect::ClientId::new(self.oauth_cfg.client_id.clone());
        let redirect_url = RedirectUrl::new(self.oauth_cfg.redirect_uri.clone()).unwrap();
        let client =
            CoreClient::from_provider_metadata(provider_metadata, client_id, None).set_redirect_uri(redirect_url);

        self.display_step("OAUTH authorization request");
        self.display_operation(Actor::WireClient, "OAUTH authorization request");
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (code_verifier, code_challenge) = (pkce_verifier.secret(), pkce_challenge.as_str());
        let cv_cc_msg = format!("code_verifier={code_verifier}&code_challenge={code_challenge}");
        self.display_str(&cv_cc_msg, false);

        // A variant of https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
        let acme_audience = oidc_chall.url.clone();
        let extra = json!({
            "id_token": {
                "keyauth": { "essential": true, "value": keyauth },
                "acme_aud": { "essential": true, "value": acme_audience }
            }
        })
        .to_string();

        let (authz_url, ..) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("profile".to_string()))
            .add_extra_param("claims", extra)
            .set_pkce_challenge(pkce_challenge)
            .url();

        self.display_step("OAUTH authorization request (auth code endpoint)");
        let authz_req = self.client.get(authz_url.as_str()).build().unwrap();
        self.display_req(Actor::WireClient, Actor::IdentityProvider, Some(&authz_req), None);

        // Authorization Server redirects to login prompt
        let resp = self.client.execute(authz_req).await.unwrap();

        let cookies = resp.cookies().map(|c| format!("{}={}", c.name(), c.value())).join("; ");

        let html = resp.text().await.unwrap();
        self.display_resp(Actor::IdentityProvider, Actor::WireClient, None);
        let action = scrap_login(html);

        // client signs in
        let mut form_uri = Url::parse(&action).unwrap();
        form_uri.set_host(Some("127.0.0.1")).unwrap();
        let form_body = HashMap::<&str, String, RandomState>::from_iter(vec![
            ("username", self.keycloak_cfg.username.clone()),
            ("password", self.keycloak_cfg.password.clone()),
            ("credentialId", "".to_string()),
        ]);

        // Client submits login form
        let login_form_req = self
            .client
            .post(form_uri)
            .form(&form_body)
            .header(header::COOKIE, cookies)
            .build()?;
        let resp = self.client.execute(login_form_req).await.unwrap();
        let authz_code = resp.text().await.unwrap();

        self.display_step("OAUTH authorization code + verifier (token endpoint)");
        let token_request = client
            .exchange_code(openidconnect::AuthorizationCode::new(authz_code))
            .unwrap()
            .set_pkce_verifier(pkce_verifier);

        let oauth_token_response = token_request
            .request_async(&async |r| custom_oauth_client("exchange-code", ctx_get_http_client(), r).await)
            .await;

        let oauth_token_response = oauth_token_response.unwrap();
        let exchange_code_req = ctx_get_request("exchange-code");
        self.display_req(
            Actor::WireClient,
            Actor::IdentityProvider,
            Some(&exchange_code_req),
            None,
        );
        self.display_str(Self::req_body_str(&exchange_code_req)?.unwrap(), false);

        // Authorization server validates Verifier & Challenge Codes

        // Get OAuth access token
        self.display_step("OAUTH access token");
        let exchange_code_resp = ctx_get_resp("exchange-code", false);
        self.display_resp(Actor::IdentityProvider, Actor::WireClient, None);
        let exchange_code_resp = serde_json::from_str::<Value>(&exchange_code_resp).unwrap();
        let exchange_code_resp = serde_json::to_string_pretty(&exchange_code_resp).unwrap();
        self.display_str(&exchange_code_resp, false);

        use oauth2::TokenResponse as _;
        let idp_pubkey = self.fetch_idp_public_key().await;
        let access_token = oauth_token_response.access_token().secret();
        self.display_token("OAuth Access token", access_token, None, &idp_pubkey);

        if let Some(refresh_token) = oauth_token_response.refresh_token() {
            // Note that this refresh token will always be shown as having an invalid signature
            // because Keycloak generates a HS512 refresh token, which we can't verify due to the
            // fact that verification requires possession of a secret key that only Keycloak has
            // access to.
            self.display_token("OAuth Refresh token", refresh_token.secret(), None, &idp_pubkey);
            self.refresh_token = Some(refresh_token.clone());
        }

        use openidconnect::TokenResponse as _;
        let id_token = oauth_token_response.id_token().unwrap().to_string();

        Ok(id_token)
    }

    pub async fn fetch_id_token_from_refresh_token(
        &mut self,
        oidc_chall: &AcmeChallenge,
        keyauth: String,
        refresh_token: RefreshToken,
    ) -> TestResult<String> {
        match self.oidc_provider {
            OidcProvider::Keycloak => {
                self.fetch_id_token_from_refresh_token_from_keycloak(oidc_chall, keyauth, refresh_token)
                    .await
            }
        }
    }

    pub async fn fetch_id_token_from_refresh_token_from_keycloak(
        &mut self,
        oidc_chall: &AcmeChallenge,
        keyauth: String,
        refresh_token: RefreshToken,
    ) -> TestResult<String> {
        self.display_chapter("Use refreshToken to retrieve idToken");
        let oidc_target = oidc_chall.target.to_string();
        let issuer_url = IssuerUrl::new(oidc_target).unwrap();
        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url.clone(), &async |r| {
            custom_oauth_client("discovery", ctx_get_http_client(), r).await
        })
        .await
        .unwrap();

        let client_id = openidconnect::ClientId::new(self.oauth_cfg.client_id.clone());
        let redirect_url = RedirectUrl::new(self.oauth_cfg.redirect_uri.clone()).unwrap();
        let client =
            CoreClient::from_provider_metadata(provider_metadata, client_id, None).set_redirect_uri(redirect_url);

        let acme_audience = oidc_chall.url.clone();
        let extra = json!({
            "id_token": {
                "keyauth": { "essential": true, "value": keyauth },
                "acme_aud": { "essential": true, "value": acme_audience }
            }
        })
        .to_string();

        let refresh_token_request = client
            .exchange_refresh_token(&refresh_token)
            .unwrap()
            .add_extra_param("claims", extra);

        let refresh_token_response = refresh_token_request
            .request_async(&async |r| custom_oauth_client("refresh-token", ctx_get_http_client(), r).await)
            .await
            .unwrap();
        use openidconnect::TokenResponse as _;
        let id_token = refresh_token_response.id_token().unwrap().to_string();
        Ok(id_token)
    }

    /// POST http://acme-server/order (verify status)
    pub async fn verify_order_status(
        &mut self,
        account: &AcmeAccount,
        order_url: Url,
        previous_nonce: String,
    ) -> TestResult<(AcmeOrder, String)> {
        self.display_chapter("Client presents a CSR and gets its certificate");
        self.display_step("verify the status of the order");
        let order_req_url = order_url.clone();
        let get_order_req =
            RustyAcme::check_order_request(order_url, account, self.alg, &self.acme_kp, previous_nonce)?;
        let req = self.client.acme_req(&order_req_url, &get_order_req)?;
        self.display_req(
            Actor::WireClient,
            Actor::AcmeServer,
            Some(&req),
            Some("/acme/{acme-provisioner}/order/{order-id}"),
        );
        self.display_body(&get_order_req);

        self.display_step("loop (with exponential backoff) until order is ready");
        let mut resp = self.client.execute(req).await?;
        self.display_resp(Actor::AcmeServer, Actor::WireClient, Some(&resp));
        let previous_nonce = resp.replay_nonce();
        resp.expect_status(StatusCode::OK)
            .has_replay_nonce()
            .has_location()
            .expect_content_type_json();
        let resp = resp.json().await?;
        let order = RustyAcme::check_order_response(resp)?;
        self.display_body(&order);
        Ok((order, previous_nonce))
    }

    /// POST http://acme-server/finalize
    pub async fn finalize(
        &mut self,
        account: &AcmeAccount,
        order: &AcmeOrder,
        previous_nonce: String,
    ) -> TestResult<(AcmeFinalize, String)> {
        self.display_step("create a CSR and call finalize url");
        let finalize_url = order.finalize.clone();
        let finalize_req =
            RustyAcme::finalize_req(order, account, self.alg, &self.acme_kp, &self.client_kp, previous_nonce)?;
        let req = self.client.acme_req(&finalize_url, &finalize_req)?;
        self.display_req(
            Actor::WireClient,
            Actor::AcmeServer,
            Some(&req),
            Some("/acme/{acme-provisioner}/order/{order-id}/finalize"),
        );
        self.display_body(&finalize_req);
        let csr = finalize_req.payload;
        let csr = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(csr).unwrap();
        let csr = serde_json::from_slice::<Value>(&csr[..]).unwrap();
        let csr = csr.get("csr").unwrap().as_str().unwrap();
        let csr = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(csr).unwrap();
        self.display_cert("CSR: ", &csr[..], true);

        self.display_step("get back a url for fetching the certificate");
        let mut resp = self.client.execute(req).await?;

        self.display_resp(Actor::AcmeServer, Actor::WireClient, Some(&resp));
        let previous_nonce = resp.replay_nonce();
        resp.expect_status(StatusCode::OK)
            .has_replay_nonce()
            .has_location()
            .expect_content_type_json();
        let resp = resp.json().await?;
        let finalize = RustyAcme::finalize_response(resp)?;
        self.display_body(&finalize);
        Ok((finalize, previous_nonce))
    }

    /// GET http://acme-server/certificate
    pub async fn get_x509_certificates(
        &mut self,
        account: AcmeAccount,
        finalize: AcmeFinalize,
        order: AcmeOrder,
        previous_nonce: String,
        env: Option<&PkiEnvironment>,
    ) -> TestResult<Vec<Vec<u8>>> {
        self.display_step("fetch the certificate");
        let certificate_url = finalize.certificate.clone();
        let certificate_req = RustyAcme::certificate_req(finalize, account, self.alg, &self.acme_kp, previous_nonce)?;
        let req = self.client.acme_req(&certificate_url, &certificate_req)?;
        self.display_req(
            Actor::WireClient,
            Actor::AcmeServer,
            Some(&req),
            Some("/acme/{acme-provisioner}/certificate/{certificate-id}"),
        );
        self.display_body(&certificate_req);

        self.display_step("get the certificate chain");
        let mut resp = self.client.execute(req).await?;
        self.display_resp(Actor::AcmeServer, Actor::WireClient, Some(&resp));
        resp.expect_status(StatusCode::OK)
            .has_replay_nonce()
            .expect_header_absent(header::LOCATION)
            .expect_header_value(header::CONTENT_TYPE, "application/pem-certificate-chain");
        let resp = resp.text().await?;
        self.display_body(&resp);
        let mut certificates = RustyAcme::certificate_response(resp, order, self.hash_alg, env)?;

        let root_ca = self.fetch_acme_root_ca().await;
        let root_cert = x509_cert::Certificate::from_pem(root_ca).unwrap();
        certificates.push(root_cert.to_der().unwrap());

        let mut certs = vec![];

        for (i, cert) in certificates.iter().enumerate() {
            self.display_cert(&format!("Certificate #{}", i + 1), cert, false);
            certs.push(Certificate::from_der(cert).unwrap());
        }
        self.verify_cert_chain();

        let leaf_cert = &certs[0];
        Self::verify_key_type(leaf_cert, self.alg);
        Self::verify_key_usage_is_signature_only(leaf_cert);
        Self::verify_intermediate_ca_cert(&certs[1]);

        Ok(certificates)
    }

    fn verify_key_usage_is_signature_only(cert: &Certificate) {
        let key_usage = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .unwrap()
            .iter()
            .find_map(|ext| {
                (ext.extn_id == KeyUsage::OID).then(|| KeyUsage::from_der(ext.extn_value.as_bytes()).unwrap())
            })
            .unwrap();
        assert_eq!(key_usage, KeyUsage(KeyUsages::DigitalSignature.into()));
    }

    fn verify_key_type(cert: &Certificate, alg: JwsAlgorithm) {
        let (oid, curve_oid) = jws_algorithm_to_x509_oids(alg);

        let spki = &cert.tbs_certificate.subject_public_key_info;
        assert_eq!(spki.algorithm.oid, oid);

        let maybe_curve_oid = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|param| x509_cert::spki::ObjectIdentifier::from_bytes(param.value()).ok());
        assert_eq!(maybe_curve_oid, curve_oid);
    }

    fn verify_intermediate_ca_cert(cert: &Certificate) {
        let name_constraints = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .unwrap()
            .iter()
            .find_map(|ext| {
                (ext.extn_id == NameConstraints::OID)
                    .then(|| NameConstraints::from_der(ext.extn_value.as_bytes()).unwrap())
            })
            .unwrap();

        assert_eq!(
            name_constraints,
            NameConstraints {
                permitted_subtrees: Some(vec![
                    GeneralSubtree {
                        base: GeneralName::DnsName(Ia5String::new("localhost").unwrap()),
                        minimum: 0,
                        maximum: None,
                    },
                    GeneralSubtree {
                        base: GeneralName::DnsName(Ia5String::new("stepca").unwrap()),
                        minimum: 0,
                        maximum: None,
                    },
                    GeneralSubtree {
                        base: GeneralName::UniformResourceIdentifier(Ia5String::new("wire.com").unwrap()),
                        minimum: 0,
                        maximum: None,
                    },
                ]),
                excluded_subtrees: None,
            }
        );
    }
}

impl E2eTest {
    pub async fn fetch_idp_public_key(&self) -> String {
        let jwks_uri = self.oidc_cfg.as_ref().unwrap().jwks_uri.clone();
        let jwks_req = self.client.get(jwks_uri);
        let jwks = jwks_req.send().await.unwrap().json::<Value>().await.unwrap();
        // Make sure to pick the signature key.
        let jwk = jwks
            .get("keys")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .find(|&key| key.get("use").unwrap() == "sig")
            .unwrap();
        let jwk = serde_json::from_value::<Jwk>(jwk.clone()).unwrap();
        match &jwk.algorithm {
            AlgorithmParameters::RSA(_) => RS256PublicKey::try_from_jwk(&jwk).unwrap().to_pem().unwrap(),
            AlgorithmParameters::EllipticCurve(p) if p.curve == EllipticCurve::P256 => {
                ES256PublicKey::try_from_jwk(&jwk).unwrap().to_pem().unwrap()
            }
            AlgorithmParameters::EllipticCurve(p) if p.curve == EllipticCurve::P384 => {
                ES384PublicKey::try_from_jwk(&jwk).unwrap().to_pem().unwrap()
            }
            AlgorithmParameters::OctetKeyPair(_) => Ed25519PublicKey::try_from_jwk(&jwk).unwrap().to_pem(),
            _ => unimplemented!(),
        }
    }

    fn req_body_str(req: &reqwest::Request) -> TestResult<Option<&str>> {
        Ok(req
            .body()
            .and_then(reqwest::Body::as_bytes)
            .map(std::str::from_utf8)
            .transpose()?)
    }

    pub fn new_jwks_uri_mock(&self) -> (Value, RS256KeyPair, String) {
        let kid = rand_base64_str(40);
        let new_kp = RS256KeyPair::generate(2048).unwrap();
        let jwk = new_kp.public_key().try_into_jwk().unwrap();
        let jwk = Jwk {
            common: CommonParameters {
                public_key_use: Some(PublicKeyUse::Signature),
                key_id: Some(kid.clone()),
                algorithm: Some("RS256".to_string()),
                ..Default::default()
            },
            algorithm: jwk.algorithm,
        };
        let stub = serde_json::json!({
            "request": {
                "method": "GET",
                "urlPath": "/realms/master/protocol/openid-connect/certs"
            },
            "response": {
                "jsonBody": {
                    "keys": [jwk]
                }
            }
        });
        (stub, new_kp, kid)
    }
}
