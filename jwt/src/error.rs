/// Wrapper over a [Result] with a [RustyJwtError] error
pub type RustyJwtResult<T> = Result<T, RustyJwtError>;

/// All errors which [crate::RustyJwtTools] might throw
#[derive(Debug, thiserror::Error)]
pub enum RustyJwtError {
    /// JWT error from `jwt-simple` crate
    #[error(transparent)]
    JwtSimpleError(#[from] jwt_simple::Error),
    /// JWT error from `jwt-simple` crate
    #[error(transparent)]
    JwtError(#[from] jwt_simple::JWTError),
    /// Elliptic curve error
    #[error("Elliptic curve error because {0}")]
    Sec1Error(sec1::Error),
    /// Invalid URL
    #[error(transparent)]
    UrlParseError(#[from] url::ParseError),
    /// UTF-8 parsing error
    #[error(transparent)]
    Utf8Error(#[from] core::str::Utf8Error),
    /// Base64 decoding error
    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),
    /// Invalid URL
    #[error("Invalid Htu '{0}' in DPoP token because {1}")]
    InvalidHtu(url::Url, &'static str),
    /// Invalid HTTP method
    #[error("Invalid Htm '{0}'")]
    InvalidHtm(String),
    /// Invalid DPoP proof jwk
    #[error("Invalid JWK in DPoP token")]
    InvalidDpopJwk,
    /// DPoP 'iat' claim is issued in the future
    #[error("DPoP 'iat' claim is issued in the future")]
    InvalidDpopIat,
    /// JWT token verification failed
    #[error("JWT token verification failed because {0}")]
    InvalidToken(String),
    /// DPoP token lacks header field
    #[error("DPoP token should have a '{0}' header field")]
    MissingDpopHeader(&'static str),
    /// DPoP token should have a 'typ' header field equal to 'dpop+jwt'
    #[error("DPoP token should have a 'typ' header field equal to 'dpop+jwt'")]
    InvalidDpopTyp,
    /// DPoP token 'sub' claim mismatches with the expected one
    #[error("DPoP token 'sub' claim mismatches with the expected one")]
    DpopSubMismatch,
    /// DPoP token is expired
    #[error("DPoP token is expired")]
    DpopExpired,
    /// DPoP token expiry is later than supplied threshold
    #[error("DPoP token expiry is later than supplied threshold")]
    DpopLivesTooLong,
    /// DPoP token lacks a claim
    #[error("DPoP token lacks '{0}' claim")]
    MissingDpopClaim(&'static str),
    /// DPoP token 'nonce' claim mismatches with the expected backend_nonce
    #[error("DPoP token 'nonce' claim mismatches with the expected backend_nonce")]
    DpopNonceMismatch,
    /// DPoP token 'htu' claim mismatches with the expected uri
    #[error("DPoP token 'htu' claim mismatches with the expected uri")]
    DpopHtuMismatch,
    /// DPoP token 'htm' claim mismatches with the expected method
    #[error("DPoP token 'htm' claim mismatches with the expected method")]
    DpopHtmMismatch,
    /// DPoP proof has an unsupported algorithm
    #[error("DPoP proof has an unsupported algorithm")]
    UnsupportedAlgorithm,
    /// We have done something terribly wrong
    #[error("We have done something terribly wrong and it needs to be fixed")]
    ImplementationError,
}
