use jsonwebtoken::{Header, jwk::Jwk};
use serde::Serialize;

use crate::{jwt::JwtClaims, prelude::*};

impl RustyJwtTools {
    /// Build a new generic JWT
    pub fn generate_jwt<T>(
        alg: JwsAlgorithm,
        mut header: Header,
        claims: JwtClaims<T>,
        kp: &Pem,
        with_jwk: bool,
    ) -> RustyJwtResult<String>
    where
        T: Serialize,
    {
        let key = alg.encoding_key(kp)?;

        if with_jwk {
            let jwk = Jwk::from_encoding_key(&key, alg.into())?;
            header.jwk = Some(jwk);
        };

        Ok(jsonwebtoken::encode(&header, &claims, &key)?)
    }
}
