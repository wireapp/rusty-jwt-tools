use std::collections::{hash_map::RandomState, HashMap};

use asserhttp::*;
use base64::Engine;
use jwt_simple::prelude::*;
use oauth2::{ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope};
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    IssuerUrl, Nonce, TokenResponse,
};
use serde_json::Value;
use url::Url;

use rusty_acme::prelude::*;
use rusty_jwt_tools::{
    jwk::{TryFromJwk, TryIntoJwk},
    prelude::*,
};

use crate::utils::{
    cfg::{E2eTest, EnrollmentFlow, OidcProvider},
    ctx::*,
    display::Actor,
    docker::stepca::StepCaImage,
    helpers::{AcmeAsserter, ClientHelper, RespHelper},
    rand_base64_str,
    wire_server::oidc::{scrap_grant, scrap_login},
    TestError, TestResult,
};

// unsafe static mutable channels for the Google OIDC login since it requires tester interaction in browser
pub(crate) static mut GOOGLE_SND: Option<std::sync::Mutex<std::sync::mpsc::Sender<String>>> = None;
static mut GOOGLE_RECV: Option<std::sync::Mutex<std::sync::mpsc::Receiver<String>>> = None;

impl E2eTest<'static> {
    pub async fn nominal_enrollment(self) -> TestResult<()> {
        self.enrollment(EnrollmentFlow::default()).await
    }

    pub async fn enrollment(self, f: EnrollmentFlow) -> TestResult<()> {
        let (t, directory) = (f.acme_directory)(self, ()).await?;
        let (t, previous_nonce) = (f.get_acme_nonce)(t, directory.clone()).await?;
        let (t, (account, previous_nonce)) = (f.new_account)(t, (directory.clone(), previous_nonce)).await?;
        let (t, (order, order_url, previous_nonce)) =
            (f.new_order)(t, (directory.clone(), account.clone(), previous_nonce)).await?;
        let (t, (authz, previous_nonce)) = (f.new_authz)(t, (account.clone(), order, previous_nonce)).await?;
        let (t, (dpop_chall, oidc_chall)) = (f.extract_challenges)(t, authz.clone()).await?;
        let (t, backend_nonce) = (f.get_wire_server_nonce)(t, ()).await?;
        let expiry = core::time::Duration::from_secs(3600);
        let (t, client_dpop_token) = (f.create_dpop_token)(t, (dpop_chall.clone(), backend_nonce, expiry)).await?;
        let (t, access_token) = (f.get_access_token)(t, (dpop_chall.clone(), client_dpop_token)).await?;
        let (t, previous_nonce) =
            (f.verify_dpop_challenge)(t, (account.clone(), dpop_chall, access_token, previous_nonce)).await?;
        let (t, id_token) = (f.fetch_id_token)(t, oidc_chall.clone()).await?;
        let (t, previous_nonce) =
            (f.verify_oidc_challenge)(t, (account.clone(), oidc_chall, id_token, previous_nonce)).await?;
        let (t, (order, previous_nonce)) =
            (f.verify_order_status)(t, (account.clone(), order_url, previous_nonce)).await?;
        let (t, (finalize, previous_nonce)) = (f.finalize)(t, (account.clone(), order.clone(), previous_nonce)).await?;
        let (mut t, _) = (f.get_x509_certificates)(t, (account, finalize, order, previous_nonce)).await?;
        t.display();
        Ok(())
    }
}

impl<'a> E2eTest<'a> {
    /// GET http://acme-server/directory
    pub async fn get_acme_directory(&mut self) -> TestResult<AcmeDirectory> {
        let ca_url = self.acme_server.as_ref().ok_or(TestError::Internal)?.uri.clone();
        self.display_chapter("Initial setup with ACME server");
        // see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1
        self.display_step("fetch acme directory for hyperlinks");
        let directory_url = format!("{ca_url}/acme/{}/directory", StepCaImage::ACME_PROVISIONER);
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
        resp.expect_status_ok().expect_content_type_json();
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
        resp.expect_status_ok()
            .expect_header("cache-control", "no-store")
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
        let account_req = RustyAcme::new_account_request(directory, self.alg, &self.client_kp, previous_nonce)?;
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
        resp.expect_status_created()
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
        let expiry = core::time::Duration::from_secs(3600); // 1h
        let order_request = RustyAcme::new_order_request(
            &self.display_name,
            self.sub.clone(),
            &self.handle,
            expiry,
            directory,
            account,
            self.alg,
            &self.client_kp,
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
        resp.expect_status_created()
            .has_replay_nonce()
            .has_location()
            .expect_content_type_json();
        let resp = resp.json().await?;
        let new_order = RustyAcme::new_order_response(resp)?;
        self.display_body(&new_order);
        Ok((new_order, order_url, previous_nonce))
    }

    /// POST http://acme-server/authz
    pub async fn new_authz(
        &mut self,
        account: &AcmeAccount,
        order: AcmeOrder,
        previous_nonce: String,
    ) -> TestResult<(AcmeAuthz, String)> {
        self.display_chapter("Display-name and handle already authorized");
        self.display_step("create authorization and fetch challenges");
        let authz_url = order.authorizations.get(0).unwrap();
        let authz_req = RustyAcme::new_authz_request(authz_url, account, self.alg, &self.client_kp, previous_nonce)?;
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
        let previous_nonce = resp.replay_nonce();
        resp.expect_status_ok()
            .has_replay_nonce()
            .has_location()
            .expect_content_type_json();
        let resp = resp.json().await?;
        let authz = RustyAcme::new_authz_response(resp)?;
        self.display_body(&authz);
        Ok((authz, previous_nonce))
    }

    /// extract challenges
    pub fn extract_challenges(&mut self, mut authz: AcmeAuthz) -> TestResult<(AcmeChallenge, AcmeChallenge)> {
        Ok((
            authz
                .take_challenge(AcmeChallengeType::WireDpop01)
                .ok_or(TestError::Internal)?,
            authz
                .take_challenge(AcmeChallengeType::WireOidc01)
                .ok_or(TestError::Internal)?,
        ))
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
        resp.expect_status_ok();
        let backend_nonce: BackendNonce = resp.text().await?.into();
        self.display_str(&backend_nonce, false);
        Ok(backend_nonce)
    }

    /// POST http://wire-server/client-dpop-token
    pub async fn create_dpop_token(
        &mut self,
        dpop_chall: &AcmeChallenge,
        backend_nonce: BackendNonce,
        expiry: core::time::Duration,
    ) -> TestResult<String> {
        self.display_step("create client DPoP token");
        let htu: Htu = dpop_chall.target.as_ref().unwrap().clone().into();
        let acme_nonce: AcmeNonce = dpop_chall.token.as_str().into();
        let dpop = Dpop {
            challenge: acme_nonce,
            htm: Htm::Post,
            htu,
            extra_claims: None,
        };
        let client_dpop_token =
            RustyJwtTools::generate_dpop_token(dpop, &self.sub, backend_nonce, expiry, self.alg, &self.client_kp)?;
        let alg = self.alg;
        let client_kp = self.client_kp.to_string();
        self.display_operation(Actor::WireClient, "create DPoP token");
        self.display_token("Dpop token", &client_dpop_token, Some(alg), client_kp);
        Ok(client_dpop_token)
    }

    /// POST http://wire-server/client-dpop-token
    pub async fn get_access_token(
        &mut self,
        dpop_chall: &AcmeChallenge,
        client_dpop_token: String,
    ) -> TestResult<String> {
        self.display_step("trade client DPoP token for an access token");

        let dpop_url = dpop_chall.target.as_ref().unwrap().to_string();
        let b64 = |v: &str| base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(v);

        // cheat to share test context
        ctx_store("client-id", self.sub.to_uri());
        ctx_store("backend-kp", self.backend_kp.to_string());
        ctx_store("hash-alg", self.hash_alg.to_string());
        ctx_store("wire-server-uri", dpop_chall.target.as_ref().unwrap().as_str());

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
        let mut resp = self.client.execute(req).await?;
        self.display_resp(Actor::WireServer, Actor::WireClient, Some(&resp));
        resp.expect_status_ok();
        let resp = resp.json::<Value>().await?;
        self.display_body(&resp);
        let access_token = resp
            .as_object()
            .and_then(|o| o.get("token"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or(TestError::Internal)?;
        let alg = self.alg;
        let backend_kp = self.backend_kp.to_string();
        self.display_token("Access token", &access_token, Some(alg), backend_kp);
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
            &self.client_kp,
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
        resp.expect_status_ok()
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
        let dex_pk = self.fetch_dex_public_key().await;
        self.display_token("Id token", &id_token, None, dex_pk);

        self.display_note("The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.");

        let oidc_chall_req = RustyAcme::oidc_chall_request(
            id_token,
            oidc_chall,
            account,
            self.alg,
            self.hash_alg,
            &self.client_kp,
            &self.client_jwk,
            previous_nonce,
        )?;
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
        resp.expect_status_ok()
            .has_replay_nonce()
            .has_location()
            .expect_content_type_json();
        let resp = resp.json().await?;
        let resp = RustyAcme::new_chall_response(resp)?;
        self.display_body(&resp);
        Ok(previous_nonce)
    }

    pub async fn fetch_id_token(&mut self, oidc_chall: &AcmeChallenge) -> TestResult<String> {
        match self.oidc_provider {
            OidcProvider::Dex => self.fetch_id_token_from_dex(oidc_chall).await,
            OidcProvider::Google => self.fetch_id_token_from_google().await,
        }
    }

    pub async fn fetch_id_token_from_dex(&mut self, oidc_chall: &AcmeChallenge) -> TestResult<String> {
        self.display_chapter("Authenticate end user using OIDC Authorization Code with PKCE flow");
        // let issuer_url = IssuerUrl::new(self.oauth_cfg.issuer_uri.clone()).unwrap();
        let issuer_url = IssuerUrl::new(oidc_chall.target.as_ref().unwrap().to_string()).unwrap();
        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url.clone(), move |r| {
            custom_oauth_client("discovery", ctx_get_http_client(), r)
        })
        .await
        .unwrap();
        let client_id = openidconnect::ClientId::new(self.oauth_cfg.client_id.clone());
        let client_secret = ClientSecret::new(self.oauth_cfg.client_secret.clone());
        let redirect_url = RedirectUrl::new(self.oauth_cfg.redirect_uri.clone()).unwrap();
        let client = CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
            .set_redirect_uri(redirect_url);

        self.display_step("OAUTH authorization request");
        self.display_operation(Actor::WireClient, "OAUTH authorization request");
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (code_verifier, code_challenge) = (pkce_verifier.secret(), pkce_challenge.as_str());
        let cv_cc_msg = format!("code_verifier={code_verifier}&code_challenge={code_challenge}");
        self.display_str(&cv_cc_msg, false);

        let (authz_url, ..) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("profile".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        self.display_step("OAUTH authorization request (auth code endpoint)");
        let authz_req = self.client.get(authz_url.as_str()).build().unwrap();
        self.display_req(Actor::WireClient, Actor::IdentityProvider, Some(&authz_req), None);

        // self.display_step("Authorization Server redirects to login prompt");
        let resp = self.client.execute(authz_req).await.unwrap();
        let html = resp.text().await.unwrap();
        self.display_resp(Actor::IdentityProvider, Actor::WireClient, None);
        // self.display_str(&html, false);
        let action = scrap_login(html.to_string());

        // client signs in
        let authz_server_uri = self.authorization_server_uri();
        let form_uri = Url::parse(&format!("{authz_server_uri}{action}")).unwrap();
        let form_body = HashMap::<&str, String, RandomState>::from_iter(vec![
            ("login", self.ldap_cfg.email.clone()),
            ("password", self.ldap_cfg.password.clone()),
        ]);

        // self.display_step("Client submits login form");
        let login_form_req = self.client.post(form_uri).form(&form_body).build().unwrap();
        // self.display_req(Actor::WireClient, Actor::OidcProvider, Some(&login_form_req), None);
        // self.display_str(Self::req_body_str(&login_form_req)?.unwrap(), false);
        let resp = self.client.execute(login_form_req).await.unwrap();

        // and gets an approval form which he fills
        // self.display_step("Authorization Server presents consent form to client");
        let hmac = resp
            .url()
            .query_pairs()
            .find_map(|(k, v)| match k.as_ref() {
                "hmac" => Some(v.to_string()),
                _ => None,
            })
            .unwrap();
        // self.display_resp(Actor::OidcProvider, Actor::WireClient, Some(&resp));
        let html = resp.text().await.unwrap();
        // self.display_str(&html, false);
        let code = scrap_grant(html);

        // self.display_step("Client submits consent form");
        let form_uri = Url::parse(&format!("{authz_server_uri}/dex/approval?req={code}&hmac={hmac}")).unwrap();
        let form_body =
            HashMap::<&str, &str, RandomState>::from_iter(vec![("req", code.as_str()), ("approval", "approve")]);
        let consent_req = self.client.post(form_uri).form(&form_body).build().unwrap();
        // self.display_req(Actor::WireClient, Actor::OidcProvider, Some(&consent_req), None);
        // self.display_str(Self::req_body_str(&consent_req)?.unwrap(), false);

        self.display_step("OAUTH authorization code");
        let resp = self.client.execute(consent_req).await.unwrap();
        let authz_code = resp.text().await.unwrap();

        self.display_step("OAUTH authorization code");
        self.display_operation(Actor::WireClient, "OAUTH authorization code");

        self.display_step("OAUTH authorization code + verifier (token endpoint)");
        let id_token = client
            .exchange_code(openidconnect::AuthorizationCode::new(authz_code))
            .set_pkce_verifier(pkce_verifier)
            .request_async(move |r| custom_oauth_client("exchange-code", ctx_get_http_client(), r))
            .await
            .unwrap();
        let exchange_code_req = ctx_get_request("exchange-code");
        self.display_req(
            Actor::WireClient,
            Actor::IdentityProvider,
            Some(&exchange_code_req),
            None,
        );
        self.display_str(Self::req_body_str(&exchange_code_req)?.unwrap(), false);

        // self.display_step("Authorization server validates Verifier & Challenge Codes");
        // self.display_operation(Actor::OidcProvider, "verify verifier & challenge codes");
        // self.display_str(&cv_cc_msg, false);

        self.display_step("OAUTH access token");
        let exchange_code_resp = ctx_get_resp("exchange-code", false);
        self.display_resp(Actor::IdentityProvider, Actor::WireClient, None);
        let exchange_code_resp = serde_json::from_str::<Value>(&exchange_code_resp).unwrap();
        let exchange_code_resp = serde_json::to_string_pretty(&exchange_code_resp).unwrap();
        self.display_str(&exchange_code_resp, false);

        let id_token = id_token.id_token().unwrap().to_string();
        self.display_str(&id_token, false);

        Ok(id_token)
    }

    pub async fn fetch_id_token_from_google(&mut self) -> TestResult<String> {
        unsafe {
            let (tx, rx) = std::sync::mpsc::channel();
            GOOGLE_SND = Some(std::sync::Mutex::new(tx));
            GOOGLE_RECV = Some(std::sync::Mutex::new(rx));
        }

        // hack to pass args to wire-server
        ctx_store("domain", &self.domain);
        self.oauth_cfg.cxt_store();

        let issuer_url = self.oauth_cfg.issuer_uri.trim_end_matches('/').to_string();
        let issuer_url = IssuerUrl::new(issuer_url).unwrap();
        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, move |r| {
            custom_oauth_client("discovery", ctx_get_http_client(), r)
        })
        .await
        .unwrap();

        let client_id = openidconnect::ClientId::new(self.oauth_cfg.client_id.clone());
        let client_secret = ClientSecret::new(self.oauth_cfg.client_secret.clone());
        let redirect_url = RedirectUrl::new(self.oauth_cfg.redirect_uri.clone()).unwrap();
        let client = CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
            .set_redirect_uri(redirect_url);

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        ctx_store("pkce-verifier", pkce_verifier.secret());
        ctx_store("pkce-challenge", pkce_challenge.as_str());

        let (authz_url, ..) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            // see https://developers.google.com/identity/protocols/oauth2/scopes
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .add_scope(Scope::new("openid".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();
        webbrowser::open(authz_url.as_str()).unwrap();

        let id_token = unsafe {
            let rx = GOOGLE_RECV.as_ref().unwrap().lock().unwrap();
            rx.recv().unwrap()
        };
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
            RustyAcme::check_order_request(order_url, account, self.alg, &self.client_kp, previous_nonce)?;
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
        resp.expect_status_ok()
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
        let finalize_req = RustyAcme::finalize_req(order, account, self.alg, &self.client_kp, previous_nonce)?;
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
        resp.expect_status_ok()
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
    ) -> TestResult<Vec<Vec<u8>>> {
        self.display_step("fetch the certificate");
        let certificate_url = finalize.certificate.clone();
        let certificate_req = RustyAcme::certificate_req(finalize, account, self.alg, &self.client_kp, previous_nonce)?;
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
        resp.expect_status_ok()
            .has_replay_nonce()
            .expect_header_absent("location")
            .expect_header("content-type", "application/pem-certificate-chain");
        let resp = resp.text().await?;
        self.display_body(&resp);
        let certificates = RustyAcme::certificate_response(resp, order)?;
        for (i, cert) in certificates.iter().enumerate() {
            self.display_cert(&format!("Certificate #{}", i + 1), cert, false);
        }
        Ok(certificates)
    }
}

impl E2eTest<'_> {
    pub async fn fetch_dex_public_key(&self) -> String {
        let jwks_uri = self.oidc_cfg.as_ref().unwrap().jwks_uri.clone();
        let jwks_req = self.client.get(jwks_uri);
        let jwks = jwks_req.send().await.unwrap().json::<Value>().await.unwrap();
        let jwk = jwks.get("keys").unwrap().as_array().unwrap().get(0).unwrap();
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
                "urlPath": "/oauth2/jwks"
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
