use crate::{pem::*, utils::*};
use clap::Parser;
use rusty_jwt_tools::prelude::*;
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct AccessVerify {
    /// access token to verify
    ///
    /// e.g. 'eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IkZudjVnOHQ0aWpJTXFPLUxIRzB4TFF5dXNZdHgwYTNBQy1HNnVNVW9taGMiLCJ5IjoiMFVLc2N2aFZWS0hleVkxaS03ZjJmLWp2eDlMWlBkYXpKQ2RTREFTZnBTWSJ9fQ.eyJpYXQiOjE2Njk5NzM0NTMsImV4cCI6MTY3Nzc0OTQ1MywibmJmIjoxNjY5OTczNDUzLCJpc3MiOiJodHRwczovL3dpcmUuZXhhbXBsZS5jb20vY2xpZW50cy84ODg2NDA5NjM0NTA1NzM0Njc2L2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA6T0RNNU5ESmtPV1JsWW1JNE5HTmhaV0l6TnpkbU0ySm1Oall3TnpKak5tSS83YjUyZGU3YWY5NTJiYTE0QHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly93aXJlLmV4YW1wbGUuY29tL2NsaWVudHMvODg4NjQwOTYzNDUwNTczNDY3Ni9hY2Nlc3MtdG9rZW4iLCJqdGkiOiIwNDZlMDVmOS05MmI4LTQzZjYtOTNhZS1mYWY1YzM2NDBiNmQiLCJub25jZSI6IldFODhFdk9CemJxR2Vyem5NKzJQL0FhZFZmNzM3NHkwY0gxOXNEU1pBMkEiLCJjaGFsIjoib2tBSjMzWW0vWFMycW1taGhoN2FXU2JCbFl5NFR0bTFFeXNxVzhJLzluZyIsImNuZiI6eyJraWQiOiJjeHhtQVFiS19Rekk4VlNMdC10MkNkS0JEdjdfT3A4Tm1LQm5ENmpJYWFZIn0sInByb29mIjoiZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lNVFpoVUV0UFozRkVNbWQ2T0hOamNtMXBYeTEwU1dweFNUWTJOWFp6T0hwd2MxRlBXVlF6TlRWR1dTSXNJbmtpT2lKUk1uYzRkVXR3UkZjdE5ESnFWRzB4WjFCelgweG9UR0pPWm10eFVrdzRhR2hOYzFnM1pHbHFUbGt3SW4xOS5leUpwWVhRaU9qRTJOams1TnpNME5UTXNJbVY0Y0NJNk1UWTNNREExT1RnMU15d2libUptSWpveE5qWTVPVGN6TkRVekxDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd09rOUVUVFZPUkVwclQxZFNiRmx0U1RST1IwNW9XbGRKZWs1NlpHMU5Na3B0VG1wWmQwNTZTbXBPYlVrdk4ySTFNbVJsTjJGbU9UVXlZbUV4TkVCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpNek1XTmhNak5tTFdVM05ESXROREk1TkMxaU9XVm1MV1ZtTURJNVpXVTBZMlF4WXlJc0ltNXZibU5sSWpvaVYwVTRPRVYyVDBKNlluRkhaWEo2Ymswck1sQXZRV0ZrVm1ZM016YzBlVEJqU0RFNWMwUlRXa0V5UVNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3Y3pvdkwzZHBjbVV1WlhoaGJYQnNaUzVqYjIwdlkyeHBaVzUwY3k4NE9EZzJOREE1TmpNME5UQTFOek0wTmpjMkwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUp2YTBGS016TlpiUzlZVXpKeGJXMW9hR2czWVZkVFlrSnNXWGswVkhSdE1VVjVjM0ZYT0Vrdk9XNW5JbjAuY2w0eUxpaDN4VjY3NXNac2JyUmdSX2ExZ3ZJMWtia0VjWExzaWthQm5Rd0phOWxCYXpaRE12UWUzcXVOOFJCRlFVOWo5b21ITlZsMWt1eE9aR183dGciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwOk9ETTVOREprT1dSbFltSTROR05oWldJek56ZG1NMkptTmpZd056SmpObUkvN2I1MmRlN2FmOTUyYmExNEB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.Z3NuWYoJBYDlkk_2roo3_bQvofS3nCRaK-lb_tnxBX3rsBjVO5NaD9pcRcZBxh9Gily-PImZ11I8wIjyYnscRA'
    access_token: Option<PathBuf>,
    /// qualified wire client id
    ///
    /// e.g. 'im:wireapp:ODM5NDJkOWRlYmI4NGNhZWIzNzdmM2JmNjYwNzJjNmI/7b52de7af952ba14@wire.com'
    #[arg(short = 'i', long)]
    client_id: String,
    /// challenge (nonce) generated by acme server
    ///
    /// e.g. 'okAJ33Ym/XS2qmmhhh7aWSbBlYy4Ttm1EysqW8I/9ng'
    #[arg(short = 'c', long)]
    challenge: String,
    /// maximum of clock skew in seconds allowed. Defaults to 360.
    ///
    /// e.g. '360' (5 min)
    #[arg(short = 'l', long, default_value = "360")]
    leeway: u16,
    /// access token maximum allowed expiration expressed as unix timestamp
    ///
    /// e.g. '1701507459'
    #[arg(short = 'e', long)]
    max_expiry: u64,
    /// hash algorithm used to compute the JWK thumbprint. Supported values: ['SHA-256', 'SHA-384']
    ///
    /// e.g. 'SHA-256'
    #[arg(short = 'a', long)]
    hash_algorithm: HashAlgorithm,
    /// path to file with wire-server's signature public key in PEM format
    #[arg(short = 'k', long)]
    key: PathBuf,
}

impl AccessVerify {
    pub fn execute(self) -> anyhow::Result<()> {
        let access_token = read_file(self.access_token.as_ref())
            .unwrap_or_else(read_stdin)
            .trim()
            .to_string();

        let client_id: ClientId = self.client_id.as_str().try_into().expect("Invalid 'client_id'");
        let challenge: AcmeNonce = self.challenge.into();
        let (_, backend_pk) = parse_public_key_pem(read_file(Some(&self.key)).unwrap());

        let verification = RustyJwtTools::verify_access_token(
            &access_token,
            client_id,
            challenge,
            self.leeway,
            self.max_expiry,
            backend_pk,
            self.hash_algorithm,
        );

        if verification.is_ok() {
            println!("✅ access token is valid");
        } else {
            panic!("❌ access token is not valid because {:?}", verification.unwrap_err());
        }

        Ok(())
    }
}
