pub use verify::{Verify, VerifyJwt, VerifyJwtHeader};

pub(crate) mod generate;
pub(crate) mod verify;

pub fn new_jti() -> String {
    uuid::Uuid::new_v4().to_string()
}
