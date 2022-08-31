/// Wrapper over a [Result] with a [RustyJwtError] error
pub type RustyJwtResult<T> = Result<T, RustyJwtError>;

/// TODO
#[derive(Debug, thiserror::Error)]
pub enum RustyJwtError {
    /// TODO
    #[error(transparent)]
    JsonWebTokenError(#[from] jsonwebtoken::errors::Error),
}
