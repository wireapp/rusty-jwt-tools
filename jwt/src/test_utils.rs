use josekit::jwk::KeyPair;
use jsonwebtoken::Algorithm;
pub use rstest::*;
pub use rstest_reuse::{self, *};

#[template]
#[export]
#[rstest(
    keys,
    case::EdDSA(crate::test_utils::ed_keys()),
    case::PS256(crate::test_utils::ec_keys(jsonwebtoken::Algorithm::ES256))
)]
#[allow(non_snake_case)]
pub fn all_keys(keys: JwtKeys) {}

pub struct JwtKeys {
    pub encoding: jsonwebtoken::EncodingKey,
    pub decoding: jsonwebtoken::DecodingKey,
    pub alg: Algorithm,
}

pub fn ed_keys() -> JwtKeys {
    let kp = curve25519_parser::generate_keypair(&mut rand::thread_rng()).unwrap();
    println!("{}", hex::encode(kp.private_der.as_slice()));
    // let privkey = include_bytes!("private_ed25519_key.pk8");
    // println!("{}", hex::encode(privkey));
    // let encoding = jsonwebtoken::EncodingKey::from_ed_der(kp.private_der.as_slice());
    // let encoding = jsonwebtoken::EncodingKey::from_ed_der(privkey);
    // let decoding = jsonwebtoken::DecodingKey::from_ed_der(kp.public_der.as_slice());
    // JwtKeys { encoding, decoding, alg: Algorithm::EdDSA }
    todo!()
}

pub fn ec_keys(alg: Algorithm) -> JwtKeys {
    let ecdsa_alg = match alg {
        Algorithm::ES256 => josekit::jws::ES256,
        _ => unimplemented!(),
    };
    let kp = ecdsa_alg.generate_key_pair().unwrap();
    let encoding = jsonwebtoken::EncodingKey::from_ec_der(kp.to_der_private_key().as_slice());
    let decoding = jsonwebtoken::DecodingKey::from_ec_der(kp.to_der_public_key().as_slice());
    JwtKeys {
        encoding,
        decoding,
        alg,
    }
}
