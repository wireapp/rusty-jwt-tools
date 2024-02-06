use x509_cert::Certificate;

use rusty_jwt_tools::prelude::*;

use crate::{error::CertificateError, identifier::CanonicalIdentifier, prelude::*};

impl RustyAcme {
    /// For fetching the generated certificate
    /// see [RFC 8555 Section 7.4.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2)
    pub fn certificate_req(
        finalize: AcmeFinalize,
        account: AcmeAccount,
        alg: JwsAlgorithm,
        kp: &Pem,
        previous_nonce: String,
    ) -> RustyAcmeResult<AcmeJws> {
        // Extract the account URL from previous response which created a new account
        let acct_url = account.acct_url()?;

        // No payload required for getting a certificate
        let payload = None::<serde_json::Value>;
        let req = AcmeJws::new(alg, previous_nonce, &finalize.certificate, Some(&acct_url), payload, kp)?;
        Ok(req)
    }

    /// see [RFC 8555 Section 7.4.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2)
    pub fn certificate_response(response: String, order: AcmeOrder) -> RustyAcmeResult<Vec<Vec<u8>>> {
        order.verify()?;
        let pems: Vec<pem::Pem> = pem::parse_many(response)?;
        pems.into_iter()
            .enumerate()
            .try_fold(vec![], move |mut acc, (i, cert_pem)| -> RustyAcmeResult<Vec<Vec<u8>>> {
                // see https://datatracker.ietf.org/doc/html/rfc8555#section-11.4
                if cert_pem.tag() != "CERTIFICATE" {
                    return Err(RustyAcmeError::SmallstepImplementationError(
                        "Something other than x509 certificates was returned by the ACME server",
                    ));
                }
                use x509_cert::der::Decode as _;
                let cert = x509_cert::Certificate::from_der(cert_pem.contents())?;

                rusty_x509_check::revocation::PkiEnvironment::extract_ski_aki_from_cert(&cert)?;

                // only verify that leaf has the right identity fields
                if i == 0 {
                    Self::verify_leaf_certificate(cert, &order.try_get_coalesce_identifier()?)?;
                }
                acc.push(cert_pem.contents().to_vec());
                Ok(acc)
            })
    }

    /// Ensure that the generated certificate matches our expectations (i.e. that the acme server is configured the right way)
    /// We verify that the fields in the certificate match the ones in the ACME order
    fn verify_leaf_certificate(cert: Certificate, identifier: &CanonicalIdentifier) -> RustyAcmeResult<()> {
        // TODO: verify that cert is signed by enrollment.sign_kp
        let cert_identity = cert.extract_identity()?;

        let invalid_client_id =
            ClientId::try_from_qualified(&cert_identity.client_id)? != ClientId::try_from_uri(&identifier.client_id)?;
        if invalid_client_id {
            return Err(CertificateError::ClientIdMismatch)?;
        }

        let invalid_display_name = cert_identity.display_name != identifier.display_name;
        if invalid_display_name {
            return Err(CertificateError::DisplayNameMismatch)?;
        }

        let invalid_handle = cert_identity.handle != identifier.handle;
        if invalid_handle {
            return Err(CertificateError::HandleMismatch)?;
        }

        let invalid_domain = cert_identity.domain != identifier.domain;
        if invalid_domain {
            return Err(CertificateError::DomainMismatch)?;
        }
        Ok(())
    }
}
