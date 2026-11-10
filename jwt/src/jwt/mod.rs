//! Generic crate for everything related to Jwt without any adherence to Dpop

#[cfg(test)]
pub(crate) use claims::NOW_LEEWAY_SECONDS;
pub use claims::{Audiences, JwtClaims};
pub(crate) use verify::{ExpectedClaims, verify_jwt};

mod claims;
pub(crate) mod generate;
mod verify;

/// Generates a new jti
pub fn new_jti() -> String {
    uuid::Uuid::new_v4().to_string()
}
