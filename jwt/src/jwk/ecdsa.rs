use jwt_simple::prelude::*;

use super::*;

impl TryIntoJwk for ES256PublicKey {
    fn try_into_jwk(self) -> RustyJwtResult<Jwk> {
        AnyEcPublicKey(JwsEcAlgorithm::P256, self.public_key().to_bytes_uncompressed()).try_into_jwk()
    }
}

impl TryFromJwk for ES256PublicKey {
    fn try_from_jwk(jwk: &Jwk) -> RustyJwtResult<Self> {
        Ok(match &jwk.algorithm {
            AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: EllipticCurve::P256,
                x,
                y,
            }) => {
                let x = RustyJwk::base64_url_decode(x.as_bytes())?;
                let y = RustyJwk::base64_url_decode(y.as_bytes())?;
                let point =
                    p256::EncodedPoint::from_affine_coordinates(x.as_slice().into(), y.as_slice().into(), false);
                ES256PublicKey::from_bytes(point.as_bytes())?
            }
            _ => return Err(RustyJwtError::InvalidDpopJwk),
        })
    }
}

impl TryIntoJwk for ES384PublicKey {
    fn try_into_jwk(self) -> RustyJwtResult<Jwk> {
        AnyEcPublicKey(JwsEcAlgorithm::P384, self.public_key().to_bytes_uncompressed()).try_into_jwk()
    }
}

impl TryFromJwk for ES384PublicKey {
    fn try_from_jwk(jwk: &Jwk) -> RustyJwtResult<Self> {
        Ok(match &jwk.algorithm {
            AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: EllipticCurve::P384,
                x,
                y,
            }) => {
                let x = RustyJwk::base64_url_decode(x.as_bytes())?;
                let y = RustyJwk::base64_url_decode(y.as_bytes())?;
                let point =
                    p384::EncodedPoint::from_affine_coordinates(x.as_slice().into(), y.as_slice().into(), false);
                ES384PublicKey::from_bytes(point.as_bytes())?
            }
            _ => return Err(RustyJwtError::InvalidDpopJwk),
        })
    }
}

/// For factorizing common elliptic curve operations
struct AnyEcPublicKey(JwsEcAlgorithm, Vec<u8>);

impl TryIntoJwk for AnyEcPublicKey {
    fn try_into_jwk(self) -> RustyJwtResult<Jwk> {
        let (x, y) = match self.0 {
            JwsEcAlgorithm::P256 => {
                let point = p256::EncodedPoint::from_bytes(self.1).map_err(RustyJwtError::Sec1Error)?;
                let x = RustyJwk::base64_url_encode(point.x().ok_or(RustyJwtError::ImplementationError)?);
                let y = RustyJwk::base64_url_encode(point.y().ok_or(RustyJwtError::ImplementationError)?);
                (x, y)
            }
            JwsEcAlgorithm::P384 => {
                let point = p384::EncodedPoint::from_bytes(self.1).map_err(RustyJwtError::Sec1Error)?;
                let x = RustyJwk::base64_url_encode(point.x().ok_or(RustyJwtError::ImplementationError)?);
                let y = RustyJwk::base64_url_encode(point.y().ok_or(RustyJwtError::ImplementationError)?);
                (x, y)
            }
        };
        Ok(Jwk {
            common: RustyJwk::common_parameters(),
            algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: self.0.kty(),
                curve: self.0.curve(),
                x,
                y,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use jwt_simple::prelude::*;
    use wasm_bindgen_test::*;

    use crate::test_utils::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_ec_keys)]
    #[test]
    fn should_convert_key_into_jwk(key: JwtEcKey) {
        match key.alg {
            JwsEcAlgorithm::P256 => {
                let pk = ES256PublicKey::from_pem(key.pk.as_str()).unwrap();
                let jwk = ES256PublicKey::try_into_jwk(pk).unwrap();
                let is_valid = |p: &EllipticCurveKeyParameters| {
                    p.key_type == EllipticCurveKeyType::EC && p.curve == EllipticCurve::P256
                };
                assert!(matches!(jwk.algorithm, AlgorithmParameters::EllipticCurve(p) if is_valid(&p)));
            }
            JwsEcAlgorithm::P384 => {
                let pk = ES384PublicKey::from_pem(key.pk.as_str()).unwrap();
                let jwk = ES384PublicKey::try_into_jwk(pk).unwrap();
                let is_valid = |p: &EllipticCurveKeyParameters| {
                    p.key_type == EllipticCurveKeyType::EC && p.curve == EllipticCurve::P384
                };
                assert!(matches!(jwk.algorithm, AlgorithmParameters::EllipticCurve(p) if is_valid(&p)));
            }
        }
    }

    #[apply(all_ec_keys)]
    #[test]
    fn should_convert_jwk_into_key(key: JwtEcKey) {
        match key.alg {
            JwsEcAlgorithm::P256 => {
                let original = ES256PublicKey::from_pem(key.pk.as_str()).unwrap();
                let jwk = original.clone().try_into_jwk().unwrap();
                let new_key = ES256PublicKey::try_from_jwk(&jwk).unwrap();
                assert_eq!(original.to_bytes(), new_key.to_bytes());
            }
            JwsEcAlgorithm::P384 => {
                let original = ES384PublicKey::from_pem(key.pk.as_str()).unwrap();
                let jwk = original.clone().try_into_jwk().unwrap();
                let new_key = ES384PublicKey::try_from_jwk(&jwk).unwrap();
                assert_eq!(original.to_bytes(), new_key.to_bytes());
            }
        }
    }

    #[apply(all_ec_keys)]
    #[test]
    fn should_fail_converting_jwk_into_key_when_wrong_size(key: JwtEcKey) {
        match key.alg {
            JwsEcAlgorithm::P256 => {
                let original = ES256PublicKey::from_pem(key.pk.as_str()).unwrap();
                let jwk = original.try_into_jwk().unwrap();
                // trying from the wrong key size
                let result = ES384PublicKey::try_from_jwk(&jwk);
                assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidDpopJwk));
            }
            JwsEcAlgorithm::P384 => {
                let original = ES384PublicKey::from_pem(key.pk.as_str()).unwrap();
                let jwk = original.try_into_jwk().unwrap();
                // trying from the wrong key size
                let result = ES256PublicKey::try_from_jwk(&jwk);
                assert!(matches!(result.unwrap_err(), RustyJwtError::InvalidDpopJwk));
            }
        }
    }
}
