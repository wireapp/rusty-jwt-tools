use elliptic_curve::{
    sec1::{Coordinates, ToEncodedPoint},
    AffineXCoordinate,
};
use jwt_simple::prelude::*;

use crate::{
    alg::{JwsEcAlgorithm, JwsEdAlgorithm},
    prelude::*,
};

pub struct RustyJwk;

impl RustyJwk {
    pub fn new_jwk(alg: JwsAlgorithm, pk: String) -> RustyJwtResult<Jwk> {
        Ok(match alg {
            JwsAlgorithm::Ed25519 => Self::new_ed_jwk(alg.try_into()?, &pk)?,
            JwsAlgorithm::P256 | JwsAlgorithm::P384 => Self::new_ec_jwk(alg.try_into()?, &pk)?,
        })
    }

    fn new_ed_jwk(alg: JwsEdAlgorithm, pk: &str) -> RustyJwtResult<Jwk> {
        let x = match alg {
            JwsEdAlgorithm::Ed25519 => Self::base64_url_encode(Ed25519PublicKey::from_pem(pk)?.to_bytes()),
        };
        Ok(Jwk {
            common: Self::common_parameters(),
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: alg.kty(),
                curve: alg.curve(),
                x,
            }),
        })
    }

    fn new_ec_jwk(alg: JwsEcAlgorithm, pk: &str) -> RustyJwtResult<Jwk> {
        use std::str::FromStr as _;
        let (x, y) = match alg {
            JwsEcAlgorithm::P256 => {
                let points = elliptic_curve::PublicKey::<p256::NistP256>::from_str(pk)?
                    .to_projective()
                    .to_encoded_point(false);
                let x = Self::base64_url_encode(points.x().ok_or(RustyJwtError::ImplementationError)?);
                let y = Self::base64_url_encode(points.y().ok_or(RustyJwtError::ImplementationError)?);
                (x, y)
            }
            JwsEcAlgorithm::P384 => {
                let points = elliptic_curve::PublicKey::<p384::NistP384>::from_str(pk)?
                    .to_projective()
                    .to_encoded_point(false);
                let x = Self::base64_url_encode(points.x().ok_or(RustyJwtError::ImplementationError)?);
                let y = Self::base64_url_encode(points.y().ok_or(RustyJwtError::ImplementationError)?);
                (x, y)
            }
        };
        Ok(Jwk {
            common: Self::common_parameters(),
            algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: alg.curve(),
                x,
                y,
            }),
        })
    }

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
