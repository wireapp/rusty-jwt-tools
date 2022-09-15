use jwt_simple::prelude::*;

use crate::prelude::*;

pub mod ecdsa;
pub mod eddsa;

pub trait TryIntoJwk {
    fn try_into_jwk(self) -> RustyJwtResult<Jwk>;
}

pub trait TryFromJwk
where
    Self: Sized,
{
    fn try_from_jwk(jwk: &Jwk) -> RustyJwtResult<Self>;
}

pub struct RustyJwk;

impl RustyJwk {
    #[inline]
    fn base64_url_encode(i: impl AsRef<[u8]>) -> String {
        base64::encode_config(i, base64::URL_SAFE_NO_PAD)
    }

    #[inline]
    fn base64_url_decode(i: impl AsRef<[u8]>) -> RustyJwtResult<Vec<u8>> {
        Ok(base64::decode_config(i, base64::URL_SAFE_NO_PAD)?)
    }

    fn common_parameters() -> CommonParameters {
        CommonParameters::default()
    }
}
