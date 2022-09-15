use jwt_simple::prelude::*;

use super::*;

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

impl TryFromJwk for Ed25519PublicKey {
    fn try_from_jwk(jwk: &Jwk) -> RustyJwtResult<Self> {
        Ok(match &jwk.algorithm {
            AlgorithmParameters::OctetKeyPair(p) => {
                let x = RustyJwk::base64_url_decode(&p.x)?;
                Ed25519PublicKey::from_bytes(&x)?
            }
            _ => return Err(RustyJwtError::InvalidDpopJwk),
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

    #[apply(all_ed_keys)]
    #[test]
    fn should_convert_key_into_jwk(key: JwtEdKey) {
        match key.alg {
            JwsEdAlgorithm::Ed25519 => {
                let pk = Ed25519PublicKey::from_pem(key.pk.as_str()).unwrap();
                let jwk = Ed25519PublicKey::try_into_jwk(pk).unwrap();
                let is_valid = |p: &OctetKeyPairParameters| {
                    p.key_type == OctetKeyPairType::OctetKeyPair && p.curve == EdwardCurve::Ed25519
                };
                assert!(matches!(jwk.algorithm, AlgorithmParameters::OctetKeyPair(p) if is_valid(&p)));
            }
        }
    }

    #[apply(all_ed_keys)]
    #[test]
    fn should_convert_jwk_into_key(key: JwtEdKey) {
        match key.alg {
            JwsEdAlgorithm::Ed25519 => {
                let original = Ed25519PublicKey::from_pem(key.pk.as_str()).unwrap();
                let jwk = original.clone().try_into_jwk().unwrap();
                let new_key = Ed25519PublicKey::try_from_jwk(&jwk).unwrap();
                assert_eq!(original.to_bytes(), new_key.to_bytes())
            }
        }
    }
}
