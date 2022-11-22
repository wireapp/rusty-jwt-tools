//! Generic crate for everything related to Jwt without any adherence to Dpop

pub use verify::{Verify, VerifyJwt, VerifyJwtHeader};

pub(crate) mod generate;
pub mod verify;

/// Generates a new jti
pub fn new_jti() -> String {
    uuid::Uuid::new_v4().to_string()
}
