/// Wrapper over a [Result] with a [RustyJwtError] error
pub type RustyJwtResult<T> = Result<T, RustyJwtError>;

/// All errors which [crate::RustyJwtTools] might throw
#[derive(Debug, thiserror::Error)]
pub enum RustyJwtError {
    /// JWT error from `jwt-simple` crate
    #[error(transparent)]
    JwtSimpleError(#[from] jwt_simple::Error),
    /// Invalid elliptic curve, either for [crate::JwsAlgorithm::P256] or [crate::JwsAlgorithm::P384]
    #[error(transparent)]
    EllipticCurveError(#[from] elliptic_curve::Error),
    /// Invalid URL
    #[error(transparent)]
    UrlParseError(#[from] url::ParseError),
    /// Invalid URL
    #[error("Invalid Htu '{0}' in DPoP token because {1}")]
    HtuError(url::Url, &'static str),
    /// We have done something terribly wrong
    #[error("We have done something terribly wrong and it needs to be fixed")]
    ImplementationError,
}
