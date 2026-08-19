use jsonwebtoken::{EncodingKey, Header, encode};
use jwt_simple::{
    claims::{Audiences, Claims},
    reexports::coarsetime::{Duration, UnixTimeStamp},
};
use serde::{Deserialize, Serialize};

use crate::{jwt_key::JwtKey, test_utils::*};

/// Same as [Dpop] but all fields are optional to simulate missing fields
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TestDpop {
    #[serde(rename = "htm", skip_serializing_if = "Option::is_none")]
    pub htm: Option<Htm>,
    #[serde(rename = "htu", skip_serializing_if = "Option::is_none")]
    pub htu: Option<Htu>,
    #[serde(rename = "chal", skip_serializing_if = "Option::is_none")]
    pub challenge: Option<AcmeNonce>,
    #[serde(rename = "handle", skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(rename = "team", skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra_claims: Option<serde_json::Value>,
}

impl Default for TestDpop {
    fn default() -> Self {
        let dpop = Dpop::default();
        Self {
            htm: Some(dpop.htm),
            htu: Some(dpop.htu),
            challenge: Some(dpop.challenge),
            handle: Some(QualifiedHandle::default().to_string()),
            display_name: Some(dpop.display_name),
            team: dpop.team.0,
            extra_claims: None,
        }
    }
}

/// Helper to build a DPoP token with errors
pub struct DpopBuilder {
    pub alg: String,
    pub typ: Option<&'static str>,
    pub dpop: TestDpop,
    pub jwk: Option<Jwk>,
    pub key: JwtKey,
    pub sub: Option<ClientId>,
    pub nonce: Option<BackendNonce>,
    pub jti: Option<String>,
    pub iat: Option<UnixTimeStamp>,
    pub nbf: Option<UnixTimeStamp>,
    pub exp: Option<UnixTimeStamp>,
}

impl From<JwtKey> for DpopBuilder {
    fn from(key: JwtKey) -> Self {
        let now = now();
        let exp = now + Duration::from_days(2);
        Self {
            alg: key.alg.to_string(),
            typ: Some("dpop+jwt"),
            dpop: TestDpop::default(),
            jwk: Some(key.to_jwk()),
            key,
            sub: Some(ClientId::default()),
            nonce: Some(BackendNonce::default()),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            iat: Some(now),
            nbf: Some(now),
            exp: Some(exp),
        }
    }
}

impl DpopBuilder {
    pub fn build(self) -> String {
        let key = match self.key.alg {
            JwsAlgorithm::ES256 | JwsAlgorithm::ES384 | JwsAlgorithm::ES512 => {
                EncodingKey::from_ec_pem(self.key.kp.as_ref())
            }
            JwsAlgorithm::EdDSA => EncodingKey::from_ed_pem(self.key.kp.as_ref()),
        }
        .expect("encoding key from pem");

        let header = Header {
            alg: JwsAlgorithm::try_from(self.alg.as_str()).unwrap().into(),
            typ: self.typ.map(|s| s.to_string()),
            jwk: self.jwk.clone(),
            ..Default::default()
        };

        encode(&header, &self.claims(), &key).unwrap()
    }

    fn claims(&self) -> JWTClaims<TestDpop> {
        let exp = Duration::from_days(2);
        let mut claims = Claims::with_custom_claims(self.dpop.clone(), exp);
        claims.audiences = Some(Audiences::AsString(
            "https://stepca/acme/wire/challenge/aaa/bbb".to_string(),
        ));
        claims.subject = self.sub.as_ref().map(|c| c.to_uri());
        claims.nonce = self.nonce.as_ref().map(|n| n.as_str().to_string());
        claims.jwt_id = self.jti.clone();
        claims.issued_at = self.iat;
        claims.expires_at = self.exp;
        claims.invalid_before = self.nbf;
        claims
    }
}
