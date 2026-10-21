/// Wrapper over a [Result] with a [RustyJwtError] error
pub type RustyJwtResult<T> = Result<T, RustyJwtError>;

/// All errors which [crate::RustyJwtTools] might throw
#[derive(Debug, thiserror::Error)]
pub enum RustyJwtError {
    /// JWT error from `jsonwebtoken` crate
    #[error(transparent)]
    JsonWebTokenError(#[from] jsonwebtoken::errors::Error),
    /// Invalid URL
    #[error(transparent)]
    UrlParseError(#[from] url::ParseError),
    /// Invalid UUID
    #[error(transparent)]
    UuidError(#[from] uuid::Error),
    /// UTF-8 parsing error
    #[error(transparent)]
    Utf8Error(#[from] core::str::Utf8Error),
    /// Invalid URL
    #[error("Invalid Htu '{0}' in DPoP token because {1}")]
    InvalidHtu(url::Url, &'static str),
    /// Invalid HTTP method
    #[error("Invalid Htm '{0}'")]
    InvalidHtm(String),
    /// The JWK in the token header doesn't match the algorithm or the expected key
    #[error("Invalid JWK in token header")]
    InvalidJwk,
    /// JWK thumbprint mismatches JWK in header
    #[error("JWK thumbprint mismatches JWK in header")]
    InvalidJwkThumbprint,
    /// JWT token 'iat' claim is in the future
    #[error("JWT token 'iat' claim is in the future")]
    TokenIssuedInFuture,
    /// JWT token 'nbf' claim is in the future
    #[error("JWT token 'nbf' claim is in the future")]
    TokenNotYetValid,
    /// JWT token verification failed
    #[error("JWT token verification failed because {0}")]
    InvalidToken(String),
    /// JWT token lacks a header field
    #[error("JWT token should have a '{0}' header field")]
    MissingTokenHeader(&'static str),
    /// JWT token 'typ' header field isn't the expected one
    #[error("JWT token should have a 'typ' header field equal to '{0}'")]
    InvalidTokenTyp(&'static str),
    /// JWT token 'sub' claim mismatches with the expected one
    #[error("JWT token 'sub' claim mismatches with the expected one")]
    TokenSubMismatch,
    /// JWT token 'iss' claim mismatches with the expected issuer
    #[error("JWT token 'iss' claim mismatches with the expected issuer")]
    TokenIssuerMismatch,
    /// JWT token is expired
    #[error("JWT token is expired")]
    TokenExpired,
    /// JWT token expiry is later than supplied threshold
    #[error("JWT token expiry is later than supplied threshold")]
    TokenLivesTooLong,
    /// JWT token token lacks a claim
    #[error("JWT token token lacks '{0}' claim")]
    MissingTokenClaim(&'static str),
    /// JWT token has an invalid "aud" claim
    #[error("JWT token has an invalid 'aud' claim")]
    InvalidAudience,
    /// DPoP token 'nonce' claim mismatches with the expected [crate::prelude::BackendNonce]
    #[error("DPoP token 'nonce' claim mismatches with the expected backend_nonce")]
    DpopNonceMismatch,
    /// DPoP token 'handle' claim mismatches with the expected handle
    #[error("DPoP token 'handle' claim mismatches with the expected handle")]
    DpopHandleMismatch,
    /// DPoP token display name claim mismatches with the expected handle
    #[error("DPoP token 'name' claim mismatches with the expected handle")]
    DpopDisplayNameMismatch,
    /// DPoP token 'team' claim mismatches with the expected team
    #[error("DPoP token 'team' claim mismatches with the expected team")]
    DpopTeamMismatch,
    /// JWT token 'chal' claim mismatches with the expected [crate::prelude::AcmeNonce]
    #[error("JWT token 'chal' claim mismatches with the expected challenge")]
    ChallengeMismatch,
    /// DPoP token 'htu' claim mismatches with the expected uri
    #[error("DPoP token 'htu' claim mismatches with the expected uri")]
    DpopHtuMismatch,
    /// DPoP token 'htm' claim mismatches with the expected method
    #[error("DPoP token 'htm' claim mismatches with the expected method")]
    DpopHtmMismatch,
    /// The DPoP proof embedded in an access token failed verification
    #[error("The DPoP proof in the access token is invalid: {0}")]
    InvalidDpopProof(Box<RustyJwtError>),
    /// Unsupported algorithm
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
    /// Supplied backend keys have an invalid format
    #[error("Supplied backend keys have an invalid format")]
    InvalidBackendKeys(#[source] jsonwebtoken::errors::Error),
    /// see [crate::prelude::ClientId]
    #[error("Supplied client identifier is invalid")]
    InvalidClientId,
    /// Verified a token with an unsupported wire-server API version
    #[error("Verified a token with an unsupported wire-server API version")]
    UnsupportedApiVersion,
    /// Verified a token with an unsupported scope
    #[error("Verified a token with an unsupported scope")]
    UnsupportedScope,
    /// Handle claim is in the wrong format
    #[error("Handle claim is in the wrong format")]
    InvalidHandle,
    /// Invalid identifier (client id or handle) scheme
    #[error("Invalid identifier scheme '{0}', should be 'wireapp'")]
    InvalidIdentifierScheme(String),
    /// We have done something terribly wrong
    #[error("We have done something terribly wrong and it needs to be fixed")]
    ImplementationError,
}
