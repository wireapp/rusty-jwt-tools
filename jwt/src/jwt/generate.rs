use jsonwebtoken::{EncodingKey, Header, jwk::Jwk};
use jwt_simple::claims::JWTClaims;
use serde::{Deserialize, Serialize};

use crate::prelude::*;

impl RustyJwtTools {
    /// Build a new generic JWT
    pub fn generate_jwt<T>(
        alg: JwsAlgorithm,
        mut header: Header,
        claims: JWTClaims<T>,
        kp: &Pem,
        with_jwk: bool,
    ) -> RustyJwtResult<String>
    where
        T: Serialize,
        for<'de> T: Deserialize<'de>,
    {
        let key = match alg {
            JwsAlgorithm::EdDSA => EncodingKey::from_ed_pem(kp.as_ref())?,
            JwsAlgorithm::ES256 | JwsAlgorithm::ES384 | JwsAlgorithm::ES512 => EncodingKey::from_ec_pem(kp.as_ref())?,
        };

        if with_jwk {
            let jwk = Jwk::from_encoding_key(&key, alg.into())?;
            header.jwk = Some(jwk);
        };

        Ok(jsonwebtoken::encode(&header, &claims, &key)?)
    }
}
