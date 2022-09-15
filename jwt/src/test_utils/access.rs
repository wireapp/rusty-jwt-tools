use crate::{access::Access, jkt::JktConfirmation, test_utils::*};

/// Same as [Dpop] but all fields are optional to simulate missing fields
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
pub struct TestAccess {
    #[serde(rename = "chal", skip_serializing_if = "Option::is_none")]
    pub challenge: Option<AcmeChallenge>,
    #[serde(rename = "cnf", skip_serializing_if = "Option::is_none")]
    pub cnf: Option<JktConfirmation>,
}

impl From<Ciphersuite> for TestAccess {
    fn from(ciphersuite: Ciphersuite) -> Self {
        let access = Access::default();
        Self {
            challenge: Some(access.challenge),
            cnf: Some(ciphersuite.to_jwk_thumbprint()),
        }
    }
}

/// Helper to build a DPoP token with errors
pub struct AccessBuilder {
    pub alg: String,
    pub typ: Option<&'static str>,
    pub access: TestAccess,
    pub jwk: Option<Jwk>,
    pub ciphersuite: Ciphersuite,
    pub sub: Option<QualifiedClientId<'static>>,
    pub nonce: Option<BackendNonce>,
    pub jti: Option<String>,
    pub iat: Option<UnixTimeStamp>,
    pub exp: Option<UnixTimeStamp>,
}

impl From<Ciphersuite> for AccessBuilder {
    fn from(ciphersuite: Ciphersuite) -> Self {
        let iat = now();
        let exp = iat + Duration::from_days(2);
        Self {
            alg: ciphersuite.key.alg.to_string(),
            typ: Some("dpop+jwt"),
            access: TestAccess::from(ciphersuite.clone()),
            jwk: Some(ciphersuite.key.to_jwk()),
            ciphersuite,
            sub: Some(QualifiedClientId::default()),
            nonce: Some(BackendNonce::default()),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            iat: Some(iat),
            exp: Some(exp),
        }
    }
}

impl AccessBuilder {
    pub fn build(self) -> String {
        let kp = self.ciphersuite.key.kp.as_str();
        match self.ciphersuite.key.alg {
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

    fn claims(&self) -> JWTClaims<TestAccess> {
        let exp = Duration::from_days(2);
        let mut claims = Claims::with_custom_claims(self.access.clone(), exp);
        claims.subject = self.sub.as_ref().map(|c| c.to_subject());
        claims.nonce = self.nonce.as_ref().map(|n| n.as_str().to_string());
        claims.jwt_id = self.jti.clone();
        claims.issued_at = self.iat;
        claims.expires_at = self.exp;
        claims
    }
}
