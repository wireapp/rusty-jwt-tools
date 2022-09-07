use elliptic_curve::sec1::ToEncodedPoint;
use jwt_simple::prelude::*;

use crate::{
    alg::{JwsEcAlgorithm, JwsEdAlgorithm},
    prelude::*,
};

pub trait TryIntoJwk {
    fn try_into_jwk(self) -> RustyJwtResult<Jwk>;
}

impl TryIntoJwk for Ed25519PublicKey {
    fn try_into_jwk(self) -> RustyJwtResult<Jwk> {
        let alg = JwsEdAlgorithm::Ed25519;
        let x = RustyJwk::base64_url_encode(self.to_bytes());
        Ok(Jwk {
            common: RustyJwk::common_parameters(),
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: alg.kty(),
                curve: alg.curve(),
                x,
            }),
        })
    }
}

impl TryIntoJwk for ES256PublicKey {
    fn try_into_jwk(self) -> RustyJwtResult<Jwk> {
        use std::str::FromStr as _;

        let alg = JwsEcAlgorithm::P256;
        // TODO: optimize
        let pk = self.to_pem()?;
        let points = elliptic_curve::PublicKey::<p256::NistP256>::from_str(pk.as_str())?
            .to_projective()
            .to_encoded_point(false);
        let x = RustyJwk::base64_url_encode(points.x().ok_or(RustyJwtError::ImplementationError)?);
        let y = RustyJwk::base64_url_encode(points.y().ok_or(RustyJwtError::ImplementationError)?);
        Ok(Jwk {
            common: RustyJwk::common_parameters(),
            algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: alg.curve(),
                x,
                y,
            }),
        })
    }
}

impl TryIntoJwk for ES384PublicKey {
    fn try_into_jwk(self) -> RustyJwtResult<Jwk> {
        use std::str::FromStr as _;

        let alg = JwsEcAlgorithm::P384;
        // TODO: optimize
        let pk = self.to_pem()?;
        let points = elliptic_curve::PublicKey::<p384::NistP384>::from_str(pk.as_str())?
            .to_projective()
            .to_encoded_point(false);
        let x = RustyJwk::base64_url_encode(points.x().ok_or(RustyJwtError::ImplementationError)?);
        let y = RustyJwk::base64_url_encode(points.y().ok_or(RustyJwtError::ImplementationError)?);
        Ok(Jwk {
            common: RustyJwk::common_parameters(),
            algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: alg.curve(),
                x,
                y,
            }),
        })
    }
}

pub struct RustyJwk;

impl RustyJwk {
    fn base64_url_encode(i: impl AsRef<[u8]>) -> String {
        base64::encode_config(i, base64::URL_SAFE_NO_PAD)
    }

    fn common_parameters() -> CommonParameters {
        CommonParameters::default()
        /*CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            ..Default::default()
        }*/
    }
}
