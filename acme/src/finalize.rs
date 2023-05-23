use asn1_rs::ToDer;
use base64::Engine;
use jwt_simple::prelude::*;
use x509_cert::der::Encode;

use rusty_jwt_tools::prelude::*;

use crate::{
    order::{AcmeOrderError, AcmeOrderStatus},
    prelude::*,
};

impl RustyAcme {
    /// see [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4)
    pub fn finalize_req(
        order: &AcmeOrder,
        account: &AcmeAccount,
        alg: JwsAlgorithm,
        kp: &Pem,
        previous_nonce: String,
    ) -> RustyAcmeResult<AcmeJws> {
        // Extract the account URL from previous response which created a new account
        let acct_url = account.acct_url()?;

        let id = order.identifiers.first().ok_or(RustyAcmeError::ImplementationError)?;
        let csr = Self::generate_csr(alg, id.to_wire_identifier()?, kp)?;
        let payload = AcmeFinalizeRequest { csr };
        let req = AcmeJws::new(alg, previous_nonce, &order.finalize, Some(&acct_url), Some(payload), kp)?;
        Ok(req)
    }

    fn generate_csr(alg: JwsAlgorithm, identifier: WireIdentifier, kp: &Pem) -> RustyAcmeResult<String> {
        let algorithm = Self::csr_alg(alg)?;
        let cert_info = x509_cert::request::CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject: Self::csr_subject(&identifier)?,
            public_key: Self::csr_spki(alg, kp)?,
            attributes: Self::csr_attributes(identifier)?,
        };
        let signature = Self::csr_signature(alg, kp, &cert_info)?;

        let csr = x509_cert::request::CertReq {
            info: cert_info,
            algorithm,
            signature,
        };
        let csr = csr.to_der()?;
        let csr = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(csr);
        Ok(csr)
    }

    fn csr_alg(alg: JwsAlgorithm) -> RustyAcmeResult<x509_cert::spki::AlgorithmIdentifierOwned> {
        let oid = match alg {
            JwsAlgorithm::Ed25519 => oid_registry::OID_SIG_ED25519,
            JwsAlgorithm::P256 => oid_registry::OID_SIG_ECDSA_WITH_SHA256,
            JwsAlgorithm::P384 => oid_registry::OID_SIG_ECDSA_WITH_SHA384,
        };
        Self::into_asn1_alg(oid, None)
    }

    fn csr_subject(identifier: &WireIdentifier) -> RustyAcmeResult<x509_cert::name::DistinguishedName> {
        let dn_domain_oid = oid_registry::OID_X509_ORGANIZATION_NAME.as_bytes().try_into()?;
        let dn_domain_value =
            x509_cert::attr::AttributeValue::new(x509_cert::der::Tag::Utf8String, identifier.domain.as_bytes())?;
        let dn_domain = x509_cert::attr::AttributeTypeAndValue {
            oid: dn_domain_oid,
            value: dn_domain_value,
        };

        // TODO: temporarily using a custom OIDC for carrying the display name without having it listed as a DNS SAN.
        // reusing LDAP's OID for display_name see http://oid-info.com/get/2.16.840.1.113730.3.1.241
        let dn_display_name_oid = asn1_rs::oid!(2.16.840 .1 .113730 .3 .1 .241).as_bytes().try_into()?;
        let dn_display_name_value =
            x509_cert::attr::AttributeValue::new(x509_cert::der::Tag::Utf8String, identifier.display_name.as_bytes())?;
        let dn_display_name = x509_cert::attr::AttributeTypeAndValue {
            oid: dn_display_name_oid,
            value: dn_display_name_value,
        };

        let domain = x509_cert::name::RelativeDistinguishedName(vec![dn_domain].try_into()?);
        let display_name = x509_cert::name::RelativeDistinguishedName(vec![dn_display_name].try_into()?);
        let subject = x509_cert::name::DistinguishedName::from(vec![domain, display_name]);
        Ok(subject)
    }

    fn csr_spki(alg: JwsAlgorithm, kp: &Pem) -> RustyAcmeResult<x509_cert::spki::SubjectPublicKeyInfoOwned> {
        let (pk, algorithm) = match alg {
            JwsAlgorithm::Ed25519 => {
                let pk = Ed25519KeyPair::from_pem(kp.as_str())?.public_key().to_bytes();
                // see https://www.rfc-editor.org/rfc/rfc8410#section-3
                let alg = Self::into_asn1_alg(oid_registry::OID_SIG_ED25519, None)?;
                (pk, alg)
            }
            JwsAlgorithm::P256 => {
                let kp = ES256KeyPair::from_pem(kp.as_str())?;
                let pk = kp.public_key().public_key().to_bytes_uncompressed();

                // see https://www.rfc-editor.org/rfc/rfc3279#section-2.3.5
                let alg = Self::into_asn1_alg(
                    oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY,
                    Some(oid_registry::OID_EC_P256),
                )?;
                (pk, alg)
            }
            JwsAlgorithm::P384 => {
                let kp = ES384KeyPair::from_pem(kp.as_str())?;
                let pk = kp.public_key().public_key().to_bytes_uncompressed();

                // see https://www.rfc-editor.org/rfc/rfc3279#section-2.3.5
                let alg = Self::into_asn1_alg(
                    oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY,
                    Some(oid_registry::OID_NIST_EC_P384),
                )?;
                (pk, alg)
            }
        };
        let subject_public_key = x509_cert::der::asn1::BitString::new(0, pk)?;
        Ok(x509_cert::spki::SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key,
        })
    }

    // TODO: find a cleaner way to encode this reusing more x509-cert structs
    fn csr_attributes(identifier: WireIdentifier) -> RustyAcmeResult<x509_cert::attr::Attributes> {
        let gn = |n: String| -> RustyAcmeResult<x509_cert::ext::pkix::name::GeneralName> {
            let ia5_str = x509_cert::der::asn1::Ia5String::new(&n)?;
            Ok(x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
                ia5_str,
            ))
        };
        let san = x509_cert::ext::pkix::SubjectAltName(vec![gn(identifier.client_id)?, gn(identifier.handle)?]);
        let san = x509_cert::attr::AttributeValue::new(x509_cert::der::Tag::OctetString, san.to_der()?)?;

        let san_oid = oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME.to_der_vec()?;
        let san = [san_oid, san.to_der()?].concat();
        let san = x509_cert::attr::AttributeValue::new(x509_cert::der::Tag::Sequence, san)?;
        let san = x509_cert::attr::AttributeValue::new(x509_cert::der::Tag::Sequence, san.to_der()?)?;

        let attributes = vec![x509_cert::attr::Attribute {
            oid: oid_registry::OID_PKCS9_EXTENSION_REQUEST.as_bytes().try_into()?,
            values: vec![san].try_into()?,
        }];
        Ok(attributes.try_into()?)
    }

    fn csr_signature(
        alg: JwsAlgorithm,
        kp: &Pem,
        cert_info: &x509_cert::request::CertReqInfo,
    ) -> RustyAcmeResult<x509_cert::der::asn1::BitString> {
        use signature::Signer as _;
        let cert_data = cert_info.to_der()?;

        let signature = match alg {
            JwsAlgorithm::Ed25519 => {
                let kp = Ed25519KeyPair::from_pem(kp.as_str())?;
                let noise = ed25519_compact::Noise::generate();
                let signature = kp.key_pair().as_ref().sk.sign(&cert_data, Some(noise));
                x509_cert::der::asn1::BitString::new(0, signature.as_ref())?
            }
            JwsAlgorithm::P256 => {
                let kp = ES256KeyPair::from_pem(kp.as_str())?;
                let sk: &p256::ecdsa::SigningKey = kp.key_pair().as_ref();
                let signature: p256::ecdsa::DerSignature = sk.try_sign(&cert_data)?;
                x509_cert::der::asn1::BitString::new(0, signature.to_der()?)?
            }
            JwsAlgorithm::P384 => {
                let kp = ES384KeyPair::from_pem(kp.as_str())?;
                let sk: &p384::ecdsa::SigningKey = kp.key_pair().as_ref();
                let signature: p384::ecdsa::DerSignature = sk.try_sign(&cert_data)?;
                x509_cert::der::asn1::BitString::new(0, signature.to_der()?)?
            }
        };
        Ok(signature)
    }

    fn into_asn1_alg(
        oid: oid_registry::Oid,
        oid_parameter: Option<oid_registry::Oid>,
    ) -> RustyAcmeResult<x509_cert::spki::AlgorithmIdentifierOwned> {
        let oid = oid.as_bytes().try_into()?;
        let parameters = oid_parameter
            .map(|p| x509_cert::attr::AttributeValue::new(x509_cert::der::Tag::ObjectIdentifier, p.as_bytes()))
            .transpose()?;
        let alg = x509_cert::spki::AlgorithmIdentifierOwned { oid, parameters };
        Ok(alg)
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
    use serde_json::json;
    use wasm_bindgen_test::*;

    use super::*;

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
