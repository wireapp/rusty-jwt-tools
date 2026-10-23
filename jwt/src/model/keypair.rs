use p256::{
    elliptic_curve::Generate as _,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
};
use zeroize::{Zeroize, Zeroizing};

use crate::prelude::*;

impl JwsAlgorithm {
    /// Generates a new key pair for this algorithm, PEM encoded
    pub fn generate_keypair(self) -> RustyJwtResult<Pem> {
        match self {
            Self::ES256 => to_pem(&p256::SecretKey::generate()),
            Self::ES384 => to_pem(&p384::SecretKey::generate()),
            Self::ES512 => to_pem(&p521::SecretKey::generate()),
            Self::EdDSA => {
                let mut seed = Zeroizing::new(ed25519_dalek::SecretKey::default());
                getrandom::fill(seed.as_mut_slice()).map_err(|_| RustyJwtError::ImplementationError)?;
                to_pem(&ed25519_dalek::SigningKey::from_bytes(&seed))
            }
        }
    }

    /// PEM encodes a raw private key of this algorithm
    ///
    /// For ECDSA, `bytes` is the big-endian scalar. For EdDSA, it is the 32 byte seed.
    pub fn keypair_from_bytes(self, bytes: &[u8]) -> RustyJwtResult<Pem> {
        match self {
            Self::ES256 => to_pem(&p256::SecretKey::from_slice(bytes).map_err(invalid_key)?),
            Self::ES384 => to_pem(&p384::SecretKey::from_slice(bytes).map_err(invalid_key)?),
            Self::ES512 => to_pem(&p521::SecretKey::from_slice(bytes).map_err(invalid_key)?),
            Self::EdDSA => to_pem(&ed25519_dalek::SigningKey::from_bytes(
                &bytes.try_into().map_err(invalid_key)?,
            )),
        }
    }

    /// Returns the raw private key of a PEM encoded key pair of this algorithm
    ///
    /// This is the inverse of [JwsAlgorithm::keypair_from_bytes].
    pub fn keypair_to_bytes(self, kp: &Pem) -> RustyJwtResult<Zeroizing<Vec<u8>>> {
        match self {
            Self::ES256 => key_bytes(kp, p256::SecretKey::to_bytes),
            Self::ES384 => key_bytes(kp, p384::SecretKey::to_bytes),
            Self::ES512 => key_bytes(kp, p521::SecretKey::to_bytes),
            Self::EdDSA => key_bytes(kp, ed25519_dalek::SigningKey::to_bytes),
        }
    }
}

/// PEM encodes a private key
fn to_pem(key: &impl EncodePrivateKey) -> RustyJwtResult<Pem> {
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|_| RustyJwtError::ImplementationError)?;
    Ok(pem.as_str().into())
}

/// Decodes a PEM encoded private key and returns its raw bytes, as returned by `to_bytes`
fn key_bytes<K, B>(kp: &Pem, to_bytes: impl FnOnce(&K) -> B) -> RustyJwtResult<Zeroizing<Vec<u8>>>
where
    K: DecodePrivateKey,
    B: AsRef<[u8]> + Zeroize,
{
    let key = K::from_pkcs8_pem(kp.as_str()).map_err(invalid_key)?;
    let bytes = Zeroizing::new(to_bytes(&key));
    Ok(Zeroizing::new(bytes.as_ref().to_vec()))
}

fn invalid_key<E>(_: E) -> RustyJwtError {
    RustyJwtError::InvalidPrivateKey
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test]
    fn keypair_should_survive_conversion_to_bytes_and_back() {
        for alg in [
            JwsAlgorithm::ES256,
            JwsAlgorithm::ES384,
            JwsAlgorithm::ES512,
            JwsAlgorithm::EdDSA,
        ] {
            let kp = alg.generate_keypair().unwrap();
            let bytes = alg.keypair_to_bytes(&kp).unwrap();
            assert_eq!(alg.keypair_from_bytes(&bytes).unwrap(), kp);
        }
    }
}
