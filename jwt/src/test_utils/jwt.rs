use jwt_simple::prelude::*;

use crate::test_utils::*;

/// Same as [Dpop] but all fields are optional to simulate missing fields
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TestDpop {
    #[serde(rename = "htm", skip_serializing_if = "Option::is_none")]
    pub htm: Option<Htm>,
    #[serde(rename = "htu", skip_serializing_if = "Option::is_none")]
    pub htu: Option<Htu>,
    #[serde(rename = "chal", skip_serializing_if = "Option::is_none")]
    pub challenge: Option<AcmeChallenge>,
}

impl Default for TestDpop {
    fn default() -> Self {
        let dpop = Dpop::default();
        Self {
            htm: Some(dpop.htm),
            htu: Some(dpop.htu),
            challenge: Some(dpop.challenge),
        }
    }
}

/// Helper to build a DPoP token with errors
pub struct JwtTestBuilder {
    pub alg: String,
    pub typ: Option<&'static str>,
    pub dpop: TestDpop,
    pub jwk: Option<Jwk>,
    pub key: JwtKey,
    pub sub: Option<QualifiedClientId<'static>>,
    pub nonce: Option<BackendNonce>,
    pub jti: Option<String>,
    pub iat: Option<UnixTimeStamp>,
    pub exp: Option<UnixTimeStamp>,
}

impl From<JwtKey> for JwtTestBuilder {
    fn from(key: JwtKey) -> Self {
        use crate::jwk::TryIntoJwk as _;

        let pk = key.pk.as_str();
        let jwk = match key.alg {
            JwsAlgorithm::P256 => ES256PublicKey::from_pem(pk).unwrap().try_into_jwk().unwrap(),
            JwsAlgorithm::P384 => ES384PublicKey::from_pem(pk).unwrap().try_into_jwk().unwrap(),
            JwsAlgorithm::Ed25519 => Ed25519PublicKey::from_pem(pk).unwrap().try_into_jwk().unwrap(),
        };
        let iat = Self::now();
        let exp = iat + Duration::from_days(2);
        Self {
            alg: key.alg.to_string(),
            typ: Some("dpop+jwt"),
            dpop: TestDpop::default(),
            jwk: Some(jwk),
            key,
            sub: Some(QualifiedClientId::default()),
            nonce: Some(BackendNonce::default()),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            iat: Some(iat),
            exp: Some(exp),
        }
    }
}

impl JwtTestBuilder {
    pub fn build(self) -> String {
        let kp = self.key.kp.as_str();
        match self.key.alg {
            JwsAlgorithm::P256 => ES256KeyPair::from_pem(kp)
                .unwrap()
                .sign_with_header(self.claims(), self.header())
                .unwrap(),
            JwsAlgorithm::P384 => ES384KeyPair::from_pem(kp)
                .unwrap()
                .sign_with_header(self.claims(), self.header())
                .unwrap(),
            JwsAlgorithm::Ed25519 => Ed25519KeyPair::from_pem(kp)
                .unwrap()
                .sign_with_header(self.claims(), self.header())
                .unwrap(),
        }
    }

    fn header(&self) -> JWTHeader {
        let mut header = JWTHeader::default();
        header.algorithm = self.alg.clone();
        header.signature_type = self.typ.map(|s| s.to_string());
        header.public_key = self.jwk.clone();
        header
    }

    fn claims(&self) -> JWTClaims<TestDpop> {
        let exp = Duration::from_days(2);
        let mut claims = Claims::with_custom_claims(self.dpop.clone(), exp);
        claims.subject = self.sub.as_ref().map(|c| c.subject());
        claims.nonce = self.nonce.as_ref().map(|n| n.as_str().to_string());
        claims.jwt_id = self.jti.clone();
        claims.issued_at = self.iat;
        claims.expires_at = self.exp;
        claims
    }

    pub fn now() -> UnixTimeStamp {
        use fluvio_wasm_timer::{SystemTime, UNIX_EPOCH};
        let now = UnixTimeStamp::from_secs(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
        now - Duration::from_secs(5)
    }
}
