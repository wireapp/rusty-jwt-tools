use rusty_jwt_tools::prelude::*;

pub struct RustyJwtToolsFfi;

impl RustyJwtToolsFfi {
    pub fn generate_dpop_token(
        alg: JwsAlgorithm,
        kp_pem: Vec<u8>,
        uri: Vec<u8>,
        method: &'static str,
        acme_challenge: Vec<u8>,
        nonce: Vec<u8>,
        client_id: Vec<u8>,
        extra_claims: Option<Vec<u8>>,
    ) -> RustyJwtResult<Vec<u8>> {
        let kp = Pem::try_from(kp_pem.as_slice())?;
        let htu = Htu::try_from(uri.as_slice())?;
        let htm = Htm::try_from(method)?;
        let challenge = AcmeChallenge::try_from(acme_challenge.as_slice())?;
        let extra_claims = extra_claims.as_deref().map(serde_json::from_slice).transpose()?;
        let dpop = Dpop {
            htu,
            htm,
            challenge,
            extra_claims,
        };
        let nonce = BackendNonce::try_from_bytes(&nonce)?;
        let client_id = QualifiedClientId::try_from(client_id.as_slice())?;

        RustyJwtTools::generate_dpop_token(alg, kp, dpop, nonce, client_id).map(String::into_bytes)
    }
}
