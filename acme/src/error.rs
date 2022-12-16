/// Wrapper over a [Result] with a [RustyAcmeError] error
pub type RustyAcmeResult<T> = Result<T, RustyAcmeError>;

/// All errors which [crate::RustyAcme] might throw
#[derive(Debug, thiserror::Error)]
pub enum RustyAcmeError {
    /// Invalid Json representation
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    /// Invalid URL
    #[error(transparent)]
    UrlError(#[from] url::ParseError),
    /// Error while building a JWT
    #[error(transparent)]
    JwtError(#[from] rusty_jwt_tools::prelude::RustyJwtError),
    /// Error while parsing certificate
    #[error(transparent)]
    CertificateError(#[from] x509_parser::nom::Err<x509_parser::error::X509Error>),
    /// Error while parsing certificate in PEM format
    #[error(transparent)]
    CertificatePemError(#[from] x509_parser::nom::Err<x509_parser::error::PEMError>),
    /// Error while generating a CSR
    #[error(transparent)]
    CertificateGenerationError(#[from] rcgen::RcgenError),
    /// We have done something terribly wrong
    #[error("We have done something terribly wrong and it needs to be fixed")]
    ImplementationError,
    /// Mostly related to WASM support
    #[error("Requested functionality is not supported for the moment")]
    NotSupported,
    /// This library has been used the wrong way by users
    #[error("This library has been used the wrong way by users")]
    ClientImplementationError(&'static str),
    /// Smallstep ACME server is not correctly implemented
    #[error("Incorrect response from ACME server because {0}")]
    SmallstepImplementationError(&'static str),
    /// Error while processing an account
    #[error(transparent)]
    AccountError(#[from] crate::account::AcmeAccountError),
    /// Error while processing an order
    #[error(transparent)]
    OrderError(#[from] crate::order::AcmeOrderError),
    /// Error while processing an authorization
    #[error(transparent)]
    AuthzError(#[from] crate::authz::AcmeAuthzError),
    /// Error while validating a challenge
    #[error(transparent)]
    ChallengeError(#[from] crate::chall::AcmeChallError),
    /// Error while finalizing an order
    #[error(transparent)]
    FinalizeError(#[from] crate::finalize::AcmeFinalizeError),
}
