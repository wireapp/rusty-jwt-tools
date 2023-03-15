use crate::prelude::*;
use rusty_jwt_tools::prelude::*;

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
    pub fn certificate_response(response: String) -> RustyAcmeResult<Vec<Vec<u8>>> {
        pem::parse_many(response)?
            .into_iter()
            .try_fold(vec![], |mut acc, cert_pem| -> RustyAcmeResult<Vec<Vec<u8>>> {
                Self::parse_x509_and_validate(&cert_pem)?;
                acc.push(cert_pem.contents);
                Ok(acc)
            })
    }

    fn parse_x509_and_validate(cert: &pem::Pem) -> RustyAcmeResult<()> {
        let (_, _cert) = x509_parser::parse_x509_certificate(&cert.contents[..])?;
        Ok(())
    }
}
