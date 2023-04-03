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
        let pems: Vec<pem::Pem> = pem::parse_many(response)?;
        pems.into_iter()
            .enumerate()
            .try_fold(vec![], |mut acc, (i, cert_pem)| -> RustyAcmeResult<Vec<Vec<u8>>> {
                use x509_cert::der::Decode as _;
                let cert = x509_cert::Certificate::from_der(cert_pem.contents())?;
                // only verify that leaf has the right identity fields
                if i == 0 {
                    let _ = cert.extract_identity()?;
                }
                acc.push(cert_pem.contents().to_vec());
                Ok(acc)
            })
    }
}
