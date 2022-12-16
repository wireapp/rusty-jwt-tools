use crate::{account::AcmeAccount, finalize::AcmeFinalize, jws::AcmeJws, prelude::*};
use rusty_jwt_tools::prelude::*;

impl RustyAcme {
    const CERTIFICATE_BEGIN: &'static str = "-----BEGIN CERTIFICATE-----";
    const CERTIFICATE_END: &'static str = "-----END CERTIFICATE-----";

    /// For fetching the generated certificate
    /// see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2
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

    /// see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2
    pub fn certificate_response(response: String) -> RustyAcmeResult<Vec<String>> {
        response
            .split(Self::CERTIFICATE_BEGIN)
            .filter(|c| !c.is_empty())
            .map(|c| c.trim().trim_end_matches(Self::CERTIFICATE_END).trim())
            .into_iter()
            .try_fold(vec![], |mut acc, cert_pem| -> RustyAcmeResult<Vec<String>> {
                Self::parse_x509_and_validate(cert_pem)?;
                acc.push(cert_pem.to_string());
                Ok(acc)
            })
    }

    fn parse_x509_and_validate(certificate: &str) -> RustyAcmeResult<()> {
        let certificate = format!("{}\n{certificate}\n{}", Self::CERTIFICATE_BEGIN, Self::CERTIFICATE_END);
        let pem = x509_parser::prelude::parse_x509_pem(certificate.as_bytes()).map(|(_, cert)| cert)?;
        let _certificate = pem.parse_x509()?;
        Ok(())
    }
}
