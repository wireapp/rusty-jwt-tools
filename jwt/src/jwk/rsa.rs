use jwt_simple::prelude::*;

use super::*;

impl TryIntoJwk for RS256PublicKey {
    fn try_into_jwk(self) -> RustyJwtResult<Jwk> {
        let c = self.to_components();
        let e = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(c.e);
        let n = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(c.n);
        Ok(Jwk {
            common: CommonParameters::default(),
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: RSAKeyType::RSA,
                e,
                n,
            }),
        })
    }
}

impl TryFromJwk for RS256PublicKey {
    fn try_from_jwk(jwk: &Jwk) -> RustyJwtResult<Self> {
        Ok(match &jwk.algorithm {
            AlgorithmParameters::RSA(RSAKeyParameters { e, n, .. }) => {
                let e = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(e)?;
                let n = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(n)?;
                RS256PublicKey::from_components(&n, &e)?
            }
            _ => return Err(RustyJwtError::InvalidDpopJwk),
        })
    }
}
