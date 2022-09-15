/// Wrapper over a [Result] with a [RustyJwtError] error
pub type RustyJwtResult<T> = Result<T, RustyJwtError>;

/// All errors which [crate::RustyJwtTools] might throw
#[derive(Debug, thiserror::Error)]
pub enum RustyJwtError {
    /// JWT error from `jwt-simple` crate
    #[error(transparent)]
    JwtSimpleError(#[from] jwt_simple::Error),
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
    /// Json error
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    /// Number conversion error
    #[error(transparent)]
    NumberError(#[from] core::num::TryFromIntError),
    /// Number parsing error
    #[error(transparent)]
    ParseIntError(#[from] core::num::ParseIntError),
    /// Invalid URL
    #[error("Invalid Htu '{0}' in DPoP token because {1}")]
    InvalidHtu(url::Url, &'static str),
    /// Invalid HTTP method
    #[error("Invalid Htm '{0}'")]
    InvalidHtm(String),
    /// Invalid DPoP proof jwk
    #[error("Invalid JWK in DPoP token")]
    InvalidDpopJwk,
    /// JWK thumbprint mismatches JWK in header
    #[error("JWK thumbprint mismatches JWK in header")]
    InvalidJwkThumbprint,
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
    TokenSubMismatch,
    /// JWT token is expired
    #[error("JWT token is expired")]
    TokenExpired,
    /// JWT token expiry is later than supplied threshold
    #[error("JWT token expiry is later than supplied threshold")]
    TokenLivesTooLong,
    /// JWT token token lacks a claim
    #[error("JWT token token lacks '{0}' claim")]
    MissingTokenClaim(&'static str),
    /// DPoP token 'nonce' claim mismatches with the expected [crate::prelude::BackendNonce]
    #[error("DPoP token 'nonce' claim mismatches with the expected backend_nonce")]
    DpopNonceMismatch,
    /// DPoP token 'chal' claim mismatches with the expected [crate::prelude::AcmeChallenge]
    #[error("DPoP token 'chal' claim mismatches with the expected challenge")]
    DpopChallengeMismatch,
    /// DPoP token 'htu' claim mismatches with the expected uri
    #[error("DPoP token 'htu' claim mismatches with the expected uri")]
    DpopHtuMismatch,
    /// DPoP token 'htm' claim mismatches with the expected method
    #[error("DPoP token 'htm' claim mismatches with the expected method")]
    DpopHtmMismatch,
    /// DPoP proof has an unsupported algorithm
    #[error("DPoP proof has an unsupported algorithm")]
    UnsupportedAlgorithm,
    /// Supplied backend keys have an invalid format
    #[error("Supplied backend keys have an invalid format because {0}")]
    InvalidBackendKeys(&'static str),
    /// see [crate::client_id::QualifiedClientId]
    #[error("Supplied client identifier is invalid")]
    InvalidClientId,
    /// We have done something terribly wrong
    #[error("We have done something terribly wrong and it needs to be fixed")]
    ImplementationError,
}
