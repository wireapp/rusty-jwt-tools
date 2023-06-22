use x509_cert::der::Decode as _;

use rusty_jwt_tools::prelude::*;

use crate::error::CertificateError;
use crate::prelude::*;

#[derive(Debug, Clone)]
pub struct WireIdentity {
    pub client_id: String,
    pub handle: String,
    pub display_name: String,
    pub domain: String,
}

pub trait WireIdentityReader {
    /// Verifies a proof of identity, may it be a x509 certificate (or a Verifiable Presentation (later)).
    /// We do not verify anything else e.g. expiry, it is left to MLS implementation
    fn extract_identity(&self) -> RustyAcmeResult<WireIdentity>;

    /// returns the 'Not Before' claim which usually matches the creation timestamp
    fn extract_created_at(&self) -> RustyAcmeResult<u64>;
}

impl WireIdentityReader for x509_cert::Certificate {
    fn extract_identity(&self) -> RustyAcmeResult<WireIdentity> {
        let (client_id, handle) = try_extract_san(&self.tbs_certificate)?;
        let (display_name, domain) = try_extract_subject(&self.tbs_certificate)?;

        Ok(WireIdentity {
            client_id,
            handle,
            display_name,
            domain,
        })
    }

    fn extract_created_at(&self) -> RustyAcmeResult<u64> {
        Ok(self.tbs_certificate.validity.not_before.to_unix_duration().as_secs())
    }
}

impl WireIdentityReader for &[u8] {
    fn extract_identity(&self) -> RustyAcmeResult<WireIdentity> {
        x509_cert::Certificate::from_der(self)?.extract_identity()
    }

    fn extract_created_at(&self) -> RustyAcmeResult<u64> {
        x509_cert::Certificate::from_der(self)?.extract_created_at()
    }
}

impl WireIdentityReader for Vec<u8> {
    fn extract_identity(&self) -> RustyAcmeResult<WireIdentity> {
        self.as_slice().extract_identity()
    }

    fn extract_created_at(&self) -> RustyAcmeResult<u64> {
        self.as_slice().extract_created_at()
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
fn try_extract_san(cert: &x509_cert::TbsCertificate) -> RustyAcmeResult<(String, String)> {
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
            if let Ok(cid) = ClientId::try_from_uri(name) {
                client_id = Some(cid.to_raw());
            } else if name.starts_with(ClientId::URI_PREFIX) {
                let h = name
                    .strip_prefix(ClientId::URI_PREFIX)
                    .ok_or(RustyAcmeError::ImplementationError)?
                    .to_string();
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
MIICLjCCAdWgAwIBAgIRAO0V5lJjXkcp2unghc4O6mkwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMwNDA0MTQ1NzU3WhcNMjMwNDA0MTU1NzU3WjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQD7KP0Ou0KX27jnuc44
xW2fIS5jpDFRyLM0CAgNTsRvGKOCAQYwggECMA4GA1UdDwEB/wQEAwIHgDAdBgNV
HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFDyjYEhXKTtucBMx
10GxG6rho37EMB8GA1UdIwQYMBaAFKcR13SG3Ulj7SmER5TjpK4REu6KMHIGA1Ud
EQRrMGmGUGltOndpcmVhcHA9WlRObFpHUXlaVEUzWWpWak5EY3hZbUV4WXpSbFpE
STNaRGMzT0dNME1tTS82YmYzNTMxYzQ4MTFiNTc1QHdpcmUuY29thhVpbTp3aXJl
YXBwPWFsaWNlX3dpcmUwHQYMKwYBBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoG
CCqGSM49BAMCA0cAMEQCIAZzup0xzgZ5i1FflEPwbXl8uigVYKyuAMHLCEeh3Eln
AiAVcCmqcVr3MXYNsIa/gnzYlF2/CSGNDD27ke1sLVUo9w==
-----END CERTIFICATE-----"#;

    #[test]
    #[wasm_bindgen_test]
    fn should_find_claims_in_x509() {
        let cert_der = pem::parse(CERT).unwrap();
        let identity = cert_der.contents().extract_identity().unwrap();

        let expected_client_id = "ZTNlZGQyZTE3YjVjNDcxYmExYzRlZDI3ZDc3OGM0MmM:6bf3531c4811b575@wire.com";
        assert_eq!(&identity.client_id, expected_client_id);
        assert_eq!(&identity.handle, "alice_wire");
        assert_eq!(&identity.display_name, "Alice Smith");
        assert_eq!(&identity.domain, "wire.com");
    }

    #[test]
    #[wasm_bindgen_test]
    fn should_find_created_at_claim() {
        let cert_der = pem::parse(CERT).unwrap();
        let created_at = cert_der.contents().extract_created_at().unwrap();
        assert_eq!(created_at, 1680620277);
    }
}
