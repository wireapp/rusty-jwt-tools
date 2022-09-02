use jwt_simple::prelude::*;

use crate::{JwsAlgorithm, RustyJwtResult};

pub struct RustyJwk;

impl RustyJwk {
    pub fn new_jwk(alg: JwsAlgorithm, pk: String) -> RustyJwtResult<Jwk> {
        Ok(match alg {
            JwsAlgorithm::Ed25519 => Self::new_ed25519_jwk(&pk),
            JwsAlgorithm::P256 => Self::new_p256_jwk(&pk),
        })
    }

    fn new_ed25519_jwk(pk: &str) -> Jwk {
        let pk = Ed25519PublicKey::from_pem(pk).unwrap();
        let x = base64::encode_config(pk.to_bytes(), base64::URL_SAFE_NO_PAD);
        let params = OctetKeyPairParameters {
            key_type: OctetKeyPairType::OctetKeyPair,
            curve: EdwardCurve::Ed25519,
            x,
        };
        Jwk {
            common: Self::common_parameters(),
            algorithm: AlgorithmParameters::OctetKeyPair(params),
        }
    }

    fn new_p256_jwk(pk: &str) -> Jwk {
        const P256_KEY_LENGTH: usize = 32;
        let pk = P256PublicKey::from_pem(pk).unwrap().to_bytes_uncompressed();
        let (x, y) = pk[1..].split_at(P256_KEY_LENGTH);
        let x = base64::encode_config(x, base64::URL_SAFE_NO_PAD);
        let y = base64::encode_config(&y[..P256_KEY_LENGTH], base64::URL_SAFE_NO_PAD);
        let params = EllipticCurveKeyParameters { key_type: EllipticCurveKeyType::EC, curve: EllipticCurve::P256, x, y };
        Jwk {
            common: Self::common_parameters(),
            algorithm: AlgorithmParameters::EllipticCurve(params),
        }
    }

    fn common_parameters() -> CommonParameters {
        CommonParameters::default()
        /*CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            ..Default::default()
        }*/
    }
}
