use x509_cert::der::Decode as _;

use rusty_jwt_tools::prelude::*;

use crate::error::CertificateError;
use crate::prelude::*;

mod status;
mod thumbprint;

#[derive(Debug, Clone)]
pub struct WireIdentity {
    pub client_id: String,
    pub handle: QualifiedHandle,
    pub display_name: String,
    pub domain: String,
    pub status: IdentityStatus,
    pub thumbprint: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IdentityStatus {
    /// All is fine
    Valid,
    /// The Certificate is expired
    Expired,
    /// The Certificate is revoked
    Revoked,
}

pub trait WireIdentityReader {
    /// Verifies a proof of identity, may it be a x509 certificate (or a Verifiable Presentation (later)).
    /// We do not verify anything else e.g. expiry, it is left to MLS implementation
    fn extract_identity(&self) -> RustyAcmeResult<WireIdentity>;

    /// returns the 'Not Before' claim which usually matches the creation timestamp
    fn extract_created_at(&self) -> RustyAcmeResult<u64>;

    /// returns the 'Subject Public Key Info' claim
    fn extract_public_key(&self) -> RustyAcmeResult<Vec<u8>>;
}

impl WireIdentityReader for x509_cert::Certificate {
    fn extract_identity(&self) -> RustyAcmeResult<WireIdentity> {
        let (client_id, handle) = try_extract_san(&self.tbs_certificate)?;
        let (display_name, domain) = try_extract_subject(&self.tbs_certificate)?;
        let status = status::extract_status(&self.tbs_certificate);
        let thumbprint = thumbprint::try_compute_jwk_canonicalized_thumbprint(&self.tbs_certificate)?;

        Ok(WireIdentity {
            client_id,
            handle,
            display_name,
            domain,
            status,
            thumbprint,
        })
    }

    fn extract_created_at(&self) -> RustyAcmeResult<u64> {
        Ok(self.tbs_certificate.validity.not_before.to_unix_duration().as_secs())
    }

    fn extract_public_key(&self) -> RustyAcmeResult<Vec<u8>> {
        Ok(self
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec())
    }
}

impl WireIdentityReader for &[u8] {
    fn extract_identity(&self) -> RustyAcmeResult<WireIdentity> {
        x509_cert::Certificate::from_der(self)?.extract_identity()
    }

    fn extract_created_at(&self) -> RustyAcmeResult<u64> {
        x509_cert::Certificate::from_der(self)?.extract_created_at()
    }

    fn extract_public_key(&self) -> RustyAcmeResult<Vec<u8>> {
        x509_cert::Certificate::from_der(self)?.extract_public_key()
    }
}

impl WireIdentityReader for Vec<u8> {
    fn extract_identity(&self) -> RustyAcmeResult<WireIdentity> {
        self.as_slice().extract_identity()
    }

    fn extract_created_at(&self) -> RustyAcmeResult<u64> {
        self.as_slice().extract_created_at()
    }

    fn extract_public_key(&self) -> RustyAcmeResult<Vec<u8>> {
        self.as_slice().extract_public_key()
    }
}

fn try_extract_subject(cert: &x509_cert::TbsCertificate) -> RustyAcmeResult<(String, String)> {
    let mut display_name = None;
    let mut domain = None;

    let mut subjects = cert.subject.0.iter().flat_map(|n| n.0.iter());
    subjects.try_for_each(|s| -> RustyAcmeResult<()> {
        if s.oid.as_bytes() == oid_registry::OID_X509_ORGANIZATION_NAME.as_bytes() {
            domain = Some(std::str::from_utf8(s.value.value())?);
        } else if s.oid.as_bytes() == oid_registry::OID_X509_COMMON_NAME.as_bytes() {
            display_name = Some(std::str::from_utf8(s.value.value())?);
        }
        Ok(())
    })?;
    let display_name = display_name.ok_or(CertificateError::MissingDisplayName)?.to_string();
    let domain = domain.ok_or(CertificateError::MissingDomain)?.to_string();
    Ok((display_name, domain))
}

/// extract Subject Alternative Name to pick client-id & display name
fn try_extract_san(cert: &x509_cert::TbsCertificate) -> RustyAcmeResult<(String, QualifiedHandle)> {
    let extensions = cert.extensions.as_ref().ok_or(CertificateError::InvalidFormat)?;

    let san = extensions
        .iter()
        .find(|e| e.extn_id.as_bytes() == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME.as_bytes())
        .map(|e| x509_cert::ext::pkix::SubjectAltName::from_der(e.extn_value.as_bytes()))
        .transpose()?
        .ok_or(CertificateError::InvalidFormat)?;

    let mut client_id = None;
    let mut handle = None;
    san.0
        .iter()
        .filter_map(|n| match n {
            x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(ia5_str) => Some(ia5_str.as_str()),
            _ => None,
        })
        .try_for_each(|name| -> RustyAcmeResult<()> {
            // since both ClientId & handle are in the SAN we first try to parse the element as
            // a ClientId (since it's the most characterizable) and else fallback to a handle
            if let Ok(cid) = ClientId::try_from_uri(name) {
                client_id = Some(cid.to_qualified());
            } else if let Ok(h) = QualifiedHandle::try_from(name) {
                handle = Some(h);
            }
            Ok(())
        })?;

    let client_id = client_id.ok_or(CertificateError::MissingClientId)?;
    let handle = handle.ok_or(CertificateError::MissingHandle)?;
    Ok((client_id, handle))
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    const CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIICGDCCAb+gAwIBAgIQHhoe3LLRoHP+EPY4KOTgATAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
MzExMTYxMDM3MjZaFw0zMzExMTMxMDM3MjZaMCkxETAPBgNVBAoTCHdpcmUuY29t
MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhANmHK7rIOLVhj/vmKmK1
qei8Dor8Lu/FPOnXmKLZGKrfo4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUFlquvWRvc3MxFaLrNgzv+UdGoaswHwYD
VR0jBBgwFoAUz40pQ/qEp4eFDfctCF0jmJB+5xswaQYDVR0RBGIwYIYhaW06d2ly
ZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29thjtpbTp3aXJlYXBwPXlsLThBX3da
U2ZhUzJ1VjhWdU1FQncvN2U3OTcyM2E4YmRjNjk0ZkB3aXJlLmNvbTAdBgwrBgEE
AYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDRwAwRAIgRqbsOAF7
OseMTgkjrKe3UO/UjDUGzW+jlDWOGLZsh5ECIDdNastqkvwOGfbWaeh+IuM6/oBz
flIOs9TQGOVc0YL1
-----END CERTIFICATE-----"#;

    const CERT_EXPIRED: &str = r#"-----BEGIN CERTIFICATE-----
MIICGDCCAb+gAwIBAgIQM1JQFaSAmNPtoyWrvmZNGjAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
MzExMTYxMDQ2MDVaFw0yMzExMTYxMTA2MDVaMCkxETAPBgNVBAoTCHdpcmUuY29t
MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAEJioXny0jRMd1GAo9aq
ywcUQBJwuc4ym1DxDBuTrFCzo4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQU3OFsPDRVZrOLHbL7vGiVE9CzyKwwHwYD
VR0jBBgwFoAUusKuRvUWmJgzjSYJL3ndc8W2414waQYDVR0RBGIwYIYhaW06d2ly
ZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29thjtpbTp3aXJlYXBwPXlhRld5M3Yt
UUZDZms0X2VkLW9fNEEvNGU4NTI0ZWY0ZTIzMDY4YkB3aXJlLmNvbTAdBgwrBgEE
AYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDRwAwRAIgPA0RmEYk
k9Jtg4ND98qu7qkUM3vtVVLiZkbCnRlFF04CIGCwhSo/78Kt8h6292SkT8c8eCS6
4PmNd7NrZ71etdKR
-----END CERTIFICATE-----"#;

    #[test]
    #[wasm_bindgen_test]
    fn should_find_claims_in_x509() {
        let cert_der = pem::parse(CERT).unwrap();
        let identity = cert_der.contents().extract_identity().unwrap();

        let expected_client_id = "yl-8A_wZSfaS2uV8VuMEBw:7e79723a8bdc694f@wire.com";
        assert_eq!(&identity.client_id, expected_client_id);
        assert_eq!(identity.handle.as_str(), "im:wireapp=%40alice_wire@wire.com");
        assert_eq!(&identity.display_name, "Alice Smith");
        assert_eq!(&identity.domain, "wire.com");
    }

    #[test]
    #[wasm_bindgen_test]
    fn should_find_created_at_claim() {
        let cert_der = pem::parse(CERT).unwrap();
        let created_at = cert_der.contents().extract_created_at().unwrap();
        assert_eq!(created_at, 1700131046);
    }

    #[test]
    #[wasm_bindgen_test]
    fn should_find_public_key() {
        let cert_der = pem::parse(CERT).unwrap();
        let spki = cert_der.contents().extract_public_key().unwrap();
        assert_eq!(
            hex::encode(spki),
            "d9872bbac838b5618ffbe62a62b5a9e8bc0e8afc2eefc53ce9d798a2d918aadf"
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn should_have_valid_status() {
        let cert_der = pem::parse(CERT).unwrap();
        let identity = cert_der.contents().extract_identity().unwrap();
        assert_eq!(&identity.status, &IdentityStatus::Valid);

        let cert_der = pem::parse(CERT_EXPIRED).unwrap();
        let identity = cert_der.contents().extract_identity().unwrap();
        assert_eq!(&identity.status, &IdentityStatus::Expired);
    }

    #[test]
    #[wasm_bindgen_test]
    fn should_have_thumbprint() {
        let cert_der = pem::parse(CERT).unwrap();
        let identity = cert_der.contents().extract_identity().unwrap();
        assert!(!identity.thumbprint.is_empty());
    }
}
