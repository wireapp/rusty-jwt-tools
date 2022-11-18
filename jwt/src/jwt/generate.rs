use crate::prelude::*;
use jwt_simple::prelude::*;

impl RustyJwtTools {
    /// Build a new generic JWT
    pub fn generate_jwt<T>(
        alg: JwsAlgorithm,
        header: JWTHeader,
        claims: JWTClaims<T>,
        kp: Pem,
    ) -> RustyJwtResult<String>
    where
        T: Serialize,
        for<'de> T: Deserialize<'de>,
    {
        use crate::jwk::TryIntoJwk as _;

        let with_jwk = |jwk: Jwk| KeyMetadata::default().with_public_key(jwk);
        match alg {
            JwsAlgorithm::Ed25519 => {
                let mut kp = Ed25519KeyPair::from_pem(kp.as_str())?;
                let jwk = kp.public_key().try_into_jwk()?;
                kp.attach_metadata(with_jwk(jwk))?;
                Ok(kp.sign_with_header(claims, header)?)
            }
            JwsAlgorithm::P256 => {
                let mut kp = ES256KeyPair::from_pem(kp.as_str())?;
                let jwk = kp.public_key().try_into_jwk()?;
                kp.attach_metadata(with_jwk(jwk))?;
                Ok(kp.sign_with_header(claims, header)?)
            }
            JwsAlgorithm::P384 => {
                let mut kp = ES384KeyPair::from_pem(kp.as_str())?;
                let jwk = kp.public_key().try_into_jwk()?;
                kp.attach_metadata(with_jwk(jwk))?;
                Ok(kp.sign_with_header(claims, header)?)
            }
        }
    }
}
