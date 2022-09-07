use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Dpop {}

impl Dpop {
    /// JWT header 'typ'
    pub const TYP: &'static str = "dpop+jwt";
    pub const DURATION: u64 = 90;

    fn new_jti() -> String {
        uuid::Uuid::new_v4().to_string()
    }
}

impl From<Dpop> for JWTClaims<Dpop> {
    fn from(dpop: Dpop) -> Self {
        let exp = Duration::from_days(Dpop::DURATION);
        let mut claims = Claims::with_custom_claims(dpop, exp);
        claims = claims.with_jwt_id(Dpop::new_jti());
        claims
    }
}
