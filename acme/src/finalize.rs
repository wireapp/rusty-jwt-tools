use crate::{
    order::{AcmeOrderError, AcmeOrderStatus},
    prelude::*,
};
use base64::Engine;

use rusty_jwt_tools::prelude::*;

impl RustyAcme {
    /// see [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4)
    pub fn finalize_req(
        mut order: AcmeOrder,
        account: &AcmeAccount,
        alg: JwsAlgorithm,
        kp: &Pem,
        previous_nonce: String,
    ) -> RustyAcmeResult<AcmeJws> {
        // Extract the account URL from previous response which created a new account
        let acct_url = account.acct_url()?;

        let id = order.identifiers.pop().ok_or(RustyAcmeError::ImplementationError)?;
        let csr = Self::generate_csr(alg, id.to_wire_identifier()?, kp)?;
        let payload = AcmeFinalizeRequest { csr };
        let req = AcmeJws::new(alg, previous_nonce, &order.finalize, Some(&acct_url), Some(payload), kp)?;
        Ok(req)
    }

    fn generate_csr(alg: JwsAlgorithm, identifier: WireIdentifier, kp: &Pem) -> RustyAcmeResult<String> {
        let mut params = rcgen::CertificateParams::new(vec![]);
        let mut dn = rcgen::DistinguishedName::new();

        // TODO: temporarily using a custom OIDC for carrying the display name without having it listed as a DNS SAN.
        // reusing LDAP's OID for diplay name see http://oid-info.com/get/2.16.840.1.113730.3.1.241
        let display_name_oid = vec![2, 16, 840, 1, 113730, 3, 1, 241];
        dn.push(rcgen::DnType::CustomDnType(display_name_oid), identifier.display_name);

        dn.push(rcgen::DnType::OrganizationName, identifier.domain.clone());
        params.distinguished_name = dn;
        params.alg = match alg {
            JwsAlgorithm::Ed25519 => &rcgen::PKCS_ED25519,
            #[cfg(not(target_family = "wasm"))]
            JwsAlgorithm::P256 => &rcgen::PKCS_ECDSA_P256_SHA256,
            #[cfg(not(target_family = "wasm"))]
            JwsAlgorithm::P384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            #[cfg(target_family = "wasm")]
            JwsAlgorithm::P256 | JwsAlgorithm::P384 => return Err(RustyAcmeError::NotSupported),
        };
        params.key_pair = Some(rcgen::KeyPair::from_pem(kp.as_str())?);
        params.subject_alt_names = vec![
            rcgen::SanType::URI(identifier.client_id.to_lowercase()),
            rcgen::SanType::URI(identifier.handle.to_lowercase()),
        ];

        let cert = rcgen::Certificate::from_params(params)?;
        let csr = cert.serialize_request_der()?;
        let csr = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(csr);
        Ok(csr)
    }

    /// see [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4)
    pub fn finalize_response(response: serde_json::Value) -> RustyAcmeResult<AcmeFinalize> {
        let finalize = serde_json::from_value::<AcmeFinalize>(response)?;
        Ok(finalize)
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct AcmeFinalizeError(#[from] AcmeOrderError);

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
#[cfg_attr(test, derive(Clone))]
#[serde(rename_all = "camelCase")]
pub struct AcmeFinalizeRequest {
    /// Certificate Signing Request in DER format
    csr: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(test, derive(Clone))]
#[serde(rename_all = "camelCase")]
pub struct AcmeFinalize {
    pub certificate: url::Url,
    #[serde(flatten)]
    pub order: AcmeOrder,
}

impl AcmeFinalize {
    pub fn verify(&self) -> RustyAcmeResult<()> {
        match self.order.status {
            AcmeOrderStatus::Valid => {}
            AcmeOrderStatus::Pending | AcmeOrderStatus::Processing | AcmeOrderStatus::Ready => {
                return Err(RustyAcmeError::ClientImplementationError(
                    "finalize is not supposed to be 'pending | processing | ready' at this point. \
                    It means you have forgotten previous steps",
                ))
            }
            AcmeOrderStatus::Invalid => return Err(AcmeFinalizeError(AcmeOrderError::Invalid))?,
        }
        self.order.verify().map_err(|e| match e {
            RustyAcmeError::OrderError(e) => RustyAcmeError::FinalizeError(AcmeFinalizeError(e)),
            _ => e,
        })?;
        Ok(())
    }
}

#[cfg(test)]
impl Default for AcmeFinalize {
    fn default() -> Self {
        Self {
            certificate: "https://acme-server/acme/wire-acme/certificate/poWXmZGdL5d5qlvHMHRC19w2O9s96fvz"
                .parse()
                .unwrap(),
            order: AcmeOrder {
                status: AcmeOrderStatus::Valid,
                ..Default::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    mod json {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        fn can_deserialize_sample_response() {
            let rfc_sample = json!({
                "status": "valid",
                "expires": "2016-01-20T14:09:07.99Z",
                "notBefore": "2016-01-01T00:00:00Z",
                "notAfter": "2016-01-08T00:00:00Z",
                "identifiers": [
                    { "type": "wireapp-id", "value": "www.example.org" },
                    { "type": "wireapp-id", "value": "example.org" }
                ],
                "authorizations": [
                    "https://example.com/acme/authz/PAniVnsZcis",
                    "https://example.com/acme/authz/r4HqLzrSrpI"
                ],
                "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize",
                "certificate": "https://example.com/acme/cert/mAt3xBGaobw"
            });
            assert!(serde_json::from_value::<AcmeFinalize>(rfc_sample).is_ok());
        }
    }

    mod verify {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        fn should_succeed_when_valid() {
            let finalize = AcmeFinalize {
                order: AcmeOrder {
                    status: AcmeOrderStatus::Valid,
                    ..Default::default()
                },
                ..Default::default()
            };
            assert!(finalize.verify().is_ok());
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_expired() {
            // just make sure we delegate to order.verify()
            let yesterday = time::OffsetDateTime::now_utc() - time::Duration::days(1);
            let finalize = AcmeFinalize {
                order: AcmeOrder {
                    status: AcmeOrderStatus::Valid,
                    expires: Some(yesterday),
                    ..Default::default()
                },
                ..Default::default()
            };
            assert!(matches!(
                finalize.verify().unwrap_err(),
                RustyAcmeError::FinalizeError(AcmeFinalizeError(AcmeOrderError::Expired))
            ));
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_status_not_valid() {
            for status in [
                AcmeOrderStatus::Pending,
                AcmeOrderStatus::Processing,
                AcmeOrderStatus::Ready,
            ] {
                let finalize = AcmeFinalize {
                    order: AcmeOrder {
                        status,
                        ..Default::default()
                    },
                    ..Default::default()
                };
                assert!(matches!(
                    finalize.verify().unwrap_err(),
                    RustyAcmeError::ClientImplementationError(_),
                ));
            }
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_status_invalid() {
            let finalize = AcmeFinalize {
                order: AcmeOrder {
                    status: AcmeOrderStatus::Invalid,
                    ..Default::default()
                },
                ..Default::default()
            };
            assert!(matches!(
                finalize.verify().unwrap_err(),
                RustyAcmeError::FinalizeError(AcmeFinalizeError(AcmeOrderError::Invalid)),
            ));
        }
    }
}
