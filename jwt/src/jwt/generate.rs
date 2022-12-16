use crate::prelude::*;
use jwt_simple::prelude::*;

impl RustyJwtTools {
    /// Build a new generic JWT
    pub fn generate_jwt<T>(
        alg: JwsAlgorithm,
        header: JWTHeader,
        claims: Option<JWTClaims<T>>,
        kp: &Pem,
        with_jwk: bool,
    ) -> RustyJwtResult<String>
    where
        T: Serialize,
        for<'de> T: Deserialize<'de>,
    {
        use crate::jwk::TryIntoJwk as _;

        let with_jwk = |jwk: Jwk| {
            if with_jwk {
                KeyMetadata::default().with_public_key(jwk)
            } else {
                KeyMetadata::default()
            }
        };
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
