//! Generic crate for everything related to Jwt without any adherence to Dpop

#[cfg(test)]
pub(crate) use claims::NOW_LEEWAY_SECONDS;
pub use claims::{Audiences, JwtClaims};
pub use verify::{ExpectedClaims, VerifyJwt};

mod claims;
pub(crate) mod generate;
pub mod verify;

/// Generates a new jti
pub fn new_jti() -> String {
    uuid::Uuid::new_v4().to_string()
}
