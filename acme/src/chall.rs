use crate::account::AcmeAccount;
use crate::jws::AcmeJws;
use crate::prelude::*;
use rusty_jwt_tools::prelude::*;

impl RustyAcme {
    /// 17. parse the response from `POST /acme/challenge/{token}`
    /// see [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1)
    pub fn new_chall_request(
        handle_chall: AcmeChallenge,
        account: &AcmeAccount,
        alg: JwsAlgorithm,
        kp: &Pem,
        previous_nonce: String,
    ) -> RustyAcmeResult<AcmeJws> {
        // Extract the account URL from previous response which created a new account
        let acct_url = account.acct_url()?;

        // No payload required for chall
        let payload = None::<serde_json::Value>;
        let req = AcmeJws::new(alg, previous_nonce, &handle_chall.url, Some(&acct_url), payload, kp)?;
        Ok(req)
    }

    /// 18. parse the response from `POST /acme/challenge/{token}`
    /// [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1)
    pub fn new_chall_response(response: serde_json::Value) -> RustyAcmeResult<AcmeChallenge> {
        let chall = serde_json::from_value::<AcmeChallenge>(response)?;
        match chall.status {
            Some(AcmeChallengeStatus::Valid) => {}
            Some(AcmeChallengeStatus::Processing) => return Err(AcmeChallError::Processing)?,
            Some(AcmeChallengeStatus::Invalid) => return Err(AcmeChallError::Invalid)?,
            Some(AcmeChallengeStatus::Pending) => {
                return Err(RustyAcmeError::ClientImplementationError(
                    "A challenge is not supposed to be pending at this point. \
                    It must either be 'valid' or 'processing'.",
                ))
            }
            None => {
                return Err(RustyAcmeError::ClientImplementationError(
                    "At this point a challenge is supposed to have a status",
                ))
            }
        }
        Ok(chall)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AcmeChallError {
    /// This challenge is invalid
    #[error("This challenge is invalid")]
    Invalid,
    /// This challenge is being processed, retry later
    #[error("This challenge is being processed, retry later")]
    Processing,
}

/// For creating a challenge
/// see [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeChallenge {
    #[serde(rename = "type")]
    /// Should be `wire-http-01` or `wire-oidc-01`
    pub typ: AcmeChallengeType,
    /// URL to call for the acme server to complete the challenge
    pub url: url::Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Should be `valid`
    pub status: Option<AcmeChallengeStatus>,
    /// The acme challenge value to store in the Dpop token
    pub token: String,
}

/// see [RFC 8555 Section 7.1.6](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.6)
#[derive(Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcmeChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum AcmeChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    /// Custom type for clientId challenge
    #[serde(rename = "wire-http-01")]
    WireHttp01,
    /// Custom type for handle + display name challenge
    #[serde(rename = "wire-oidc-01")]
    WireOidc01,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test]
    fn can_deserialize_rfc_sample_response() {
        // http challenge
        // see https://www.rfc-editor.org/rfc/rfc8555.html#section-8.3
        let rfc_sample = json!({
            "type": "http-01",
            "url": "https://example.com/acme/chall/prV_B7yEyA4",
            "status": "pending",
            "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
        });
        assert!(serde_json::from_value::<AcmeChallenge>(rfc_sample).is_ok());

        // dns challenge
        // see https://www.rfc-editor.org/rfc/rfc8555.html#section-8.4
        let rfc_sample = json!({
            "type": "dns-01",
            "url": "https://example.com/acme/chall/Rg5dV14Gh1Q",
            "status": "pending",
            "token": "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
        });
        assert!(serde_json::from_value::<AcmeChallenge>(rfc_sample).is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn chall_type_should_deserialize_as_expected() {
        use serde_json::from_value as deser;
        assert_eq!(
            deser::<AcmeChallengeType>(json!("http-01")).unwrap(),
            AcmeChallengeType::Http01
        );
        assert_eq!(
            deser::<AcmeChallengeType>(json!("dns-01")).unwrap(),
            AcmeChallengeType::Dns01
        );
        assert_eq!(
            deser::<AcmeChallengeType>(json!("tls-alpn-01")).unwrap(),
            AcmeChallengeType::TlsAlpn01
        );
        assert_eq!(
            deser::<AcmeChallengeType>(json!("wire-http-01")).unwrap(),
            AcmeChallengeType::WireHttp01
        );
        assert_eq!(
            deser::<AcmeChallengeType>(json!("wire-oidc-01")).unwrap(),
            AcmeChallengeType::WireOidc01
        );
        assert!(deser::<AcmeChallengeType>(json!("Http-01")).is_err());
        assert!(deser::<AcmeChallengeType>(json!("http01")).is_err());
    }
}
