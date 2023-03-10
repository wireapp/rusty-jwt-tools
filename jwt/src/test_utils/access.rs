use crate::{access::Access, jwk_thumbprint::JwkThumbprint, test_utils::*};

/// Same as [Dpop] but all fields are optional to simulate missing fields
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
pub struct TestAccess {
    #[serde(rename = "chal", skip_serializing_if = "Option::is_none")]
    pub challenge: Option<AcmeNonce>,
    #[serde(rename = "cnf", skip_serializing_if = "Option::is_none")]
    pub cnf: Option<JwkThumbprint>,
    #[serde(rename = "proof", skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(rename = "client_id", skip_serializing_if = "Option::is_none")]
    pub client_id: Option<ClientId>,
    #[serde(rename = "api_version", skip_serializing_if = "Option::is_none")]
    pub api_version: Option<u32>,
    #[serde(rename = "scope", skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl From<Ciphersuite> for TestAccess {
    fn from(ciphersuite: Ciphersuite) -> Self {
        let access = Access::default();
        let proof = DpopBuilder::from(ciphersuite.key.clone()).build();
        Self {
            challenge: Some(access.challenge),
            cnf: Some(ciphersuite.to_jwk_thumbprint()),
            proof: Some(proof),
            client_id: Some(ClientId::default()),
            api_version: Some(Access::WIRE_SERVER_API_VERSION),
            scope: Some(Access::DEFAULT_SCOPE.to_string()),
        }
    }
}

/// Helper to build an Access token with errors
pub struct AccessBuilder {
    pub alg: String,
    pub typ: Option<&'static str>,
    pub access: TestAccess,
    pub jwk: Option<Jwk>,
    pub ciphersuite: Ciphersuite,
    pub sub: Option<ClientId>,
    pub nonce: Option<BackendNonce>,
    pub jti: Option<String>,
    pub iat: Option<UnixTimeStamp>,
    pub exp: Option<UnixTimeStamp>,
    pub issuer: Option<Htu>,
}

impl From<Ciphersuite> for AccessBuilder {
    fn from(ciphersuite: Ciphersuite) -> Self {
        let iat = now();
        let exp = iat + Duration::from_days(2);
        let proof = DpopBuilder::from(ciphersuite.key.clone());
        Self {
            alg: ciphersuite.key.alg.to_string(),
            typ: Some("at+jwt"),
            access: TestAccess::from(ciphersuite.clone()),
            jwk: Some(ciphersuite.key.to_jwk()),
            ciphersuite,
            sub: Some(ClientId::default()),
            nonce: Some(BackendNonce::default()),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            iat: Some(iat),
            exp: Some(exp),
            issuer: proof.dpop.htu,
        }
    }
}

impl AccessBuilder {
    pub fn build(self) -> String {
        let kp = self.ciphersuite.key.kp.as_str();
        match self.ciphersuite.key.alg {
            JwsAlgorithm::P256 => ES256KeyPair::from_pem(kp)
                .unwrap()
                .sign_with_header(Some(self.claims()), self.header())
                .unwrap(),
            JwsAlgorithm::P384 => ES384KeyPair::from_pem(kp)
                .unwrap()
                .sign_with_header(Some(self.claims()), self.header())
                .unwrap(),
            JwsAlgorithm::Ed25519 => Ed25519KeyPair::from_pem(kp)
                .unwrap()
                .sign_with_header(Some(self.claims()), self.header())
                .unwrap(),
        }
    }

    fn header(&self) -> JWTHeader {
        JWTHeader {
            algorithm: self.alg.clone(),
            signature_type: self.typ.map(|s| s.to_string()),
            public_key: self.jwk.clone(),
            ..Default::default()
        }
    }

    fn claims(&self) -> JWTClaims<TestAccess> {
        let exp = Duration::from_days(2);
        let mut claims = Claims::with_custom_claims(self.access.clone(), exp);
        claims.subject = self.sub.as_ref().map(|c| c.to_uri());
        claims.nonce = self.nonce.as_ref().map(|n| n.as_str().to_string());
        claims.jwt_id = self.jti.clone();
        claims.issued_at = self.iat;
        claims.expires_at = self.exp;
        claims.issuer = self.issuer.as_ref().map(|iss| iss.to_string());
        claims
    }
}
