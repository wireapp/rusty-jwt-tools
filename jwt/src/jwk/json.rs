use jwt_simple::prelude::{
    AlgorithmParameters, ES256PublicKey, ES384PublicKey, ES512PublicKey, Ed25519PublicKey, EdwardCurve, EllipticCurve,
    EllipticCurveKeyParameters, EllipticCurveKeyType, Jwk, OctetKeyPairParameters, OctetKeyPairType,
};

use crate::{
    jwk::TryFromJwk,
    prelude::{RustyJwtError, RustyJwtResult},
};

/// Parses a raw JWK Json serialized
pub fn parse_json_jwk(jwk: &[u8]) -> RustyJwtResult<Vec<u8>> {
    let jwk = serde_json::from_slice::<Jwk>(jwk)?;
    let pk = match jwk.algorithm {
        AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
            key_type, ref curve, ..
        }) if key_type == EllipticCurveKeyType::EC && curve == &EllipticCurve::P256 => {
            ES256PublicKey::try_from_jwk(&jwk)?.to_bytes()
        }
        AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
            key_type, ref curve, ..
        }) if key_type == EllipticCurveKeyType::EC && curve == &EllipticCurve::P384 => {
            ES384PublicKey::try_from_jwk(&jwk)?.to_bytes()
        }
        AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
            key_type, ref curve, ..
        }) if key_type == EllipticCurveKeyType::EC && curve == &EllipticCurve::P521 => {
            ES512PublicKey::try_from_jwk(&jwk)?.to_bytes()
        }
        AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
            key_type, ref curve, ..
        }) if key_type == OctetKeyPairType::OctetKeyPair && curve == &EdwardCurve::Ed25519 => {
            Ed25519PublicKey::try_from_jwk(&jwk)?.to_bytes()
        }
        _ => return Err(RustyJwtError::UnsupportedAlgorithm),
    };
    Ok(pk)
}
