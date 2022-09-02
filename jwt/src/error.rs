/// Wrapper over a [Result] with a [RustyJwtError] error
pub type RustyJwtResult<T> = Result<T, RustyJwtError>;

/// TODO
#[derive(Debug, thiserror::Error)]
pub enum RustyJwtError {
    /*/// TODO
    #[error(transparent)]
    JsonWebTokenError(#[from] jsonwebtoken::errors::Error),*/
    /// TODO
    #[error(transparent)]
    JwtSimpleError(#[from] jwt_simple::JWTError),
    /// TODO
    #[error(transparent)]
    JwtSimpleBubbleError(#[from] jwt_simple::Error),
    /// TODO
    #[error(transparent)]
    Utf8Error(#[from] core::str::Utf8Error),
}
