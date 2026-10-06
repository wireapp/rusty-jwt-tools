use base64::Engine;
use rand::distr::{Alphanumeric, SampleString as _};
use serde::Serialize;

use crate::{jwt_key::JwtKey, prelude::JwsAlgorithm};

/// One hour in seconds
pub const HOUR: u64 = 60 * 60;
/// One day in seconds
pub const DAY: u64 = 24 * HOUR;

/// Returns a unix timestamp 5 seconds in the past
pub fn now() -> u64 {
    jsonwebtoken::get_current_timestamp() - 5
}

/// Builds a token with the given header fields and signs it with `key`, whatever `alg` says
///
/// `jsonwebtoken::encode` refuses to sign when `header.alg` doesn't match the key. Tests use
/// mismatching or unsupported algorithms on purpose, so the token is assembled and signed by hand.
pub fn forge_token(
    key: &JwtKey,
    alg: &str,
    typ: Option<&str>,
    jwk: Option<jsonwebtoken::jwk::Jwk>,
    claims: &impl Serialize,
) -> String {
    let header = jsonwebtoken::Header {
        alg: alg.parse().unwrap(),
        typ: typ.map(str::to_string),
        jwk,
        ..Default::default()
    };

    let encoding_key = match key.alg {
        JwsAlgorithm::ES256 | JwsAlgorithm::ES384 | JwsAlgorithm::ES512 => {
            jsonwebtoken::EncodingKey::from_ec_pem(key.kp.as_ref())
        }
        JwsAlgorithm::EdDSA => jsonwebtoken::EncodingKey::from_ed_pem(key.kp.as_ref()),
    }
    .expect("encoding key from pem");

    let b64 = |v: &[u8]| base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(v);
    let encoded_header = b64(&serde_json::to_vec(&header).unwrap());
    let encoded_claims = b64(&serde_json::to_vec(claims).unwrap());
    let message = format!("{encoded_header}.{encoded_claims}");
    let signature = jsonwebtoken::crypto::sign(message.as_bytes(), &encoding_key, key.alg.into()).unwrap();
    format!("{message}.{signature}")
}

pub fn rand_base64_str(size: usize) -> String {
    let challenge: String = Alphanumeric.sample_string(&mut rand::rng(), size);
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(challenge)
}

pub fn jwt_header(token: String) -> serde_json::Map<String, serde_json::Value> {
    jwt_part(token, 0)
}

pub fn jwt_claims(token: String) -> serde_json::Map<String, serde_json::Value> {
    jwt_part(token, 1)
}

fn jwt_part(token: String, part: usize) -> serde_json::Map<String, serde_json::Value> {
    let parts = token.split('.').collect::<Vec<&str>>();
    let claims = parts.get(part).unwrap();
    let claims = base64::prelude::BASE64_STANDARD_NO_PAD.decode(claims).unwrap();
    let claims = serde_json::from_slice::<serde_json::Value>(claims.as_slice()).unwrap();
    claims.as_object().unwrap().to_owned()
}
