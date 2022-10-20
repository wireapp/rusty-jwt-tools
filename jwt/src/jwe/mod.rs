use biscuit::{
    jwa::{Algorithm, EncryptionOptions},
    jwe::{Compact, RegisteredHeader},
    jwk::{AlgorithmParameters, CommonParameters, OctetKeyParameters, OctetKeyType, JWK},
    Empty,
};

use alg::JweAlgorithm;

use crate::prelude::*;

pub mod alg;

pub trait Rng: rand::RngCore + rand::CryptoRng {}

impl Rng for rand_chacha::ChaCha20Rng {}

impl RustyJwtTools {
    /// Encrypts a [payload] in a JWE with [Compact Serialization][2].
    ///
    /// Specified in [RFC 7516][1]
    ///
    /// # Arguments
    /// * `alg` - encryption algorithm (currently only AES-GCM)
    /// * `key` - encryption key (currently only AES-GCM). See [JweAlgorithm::key_length] for details about key length
    /// * `payload` - any data to encrypt. It does not necessarily have to be json.
    /// * `rng` - in case the platform's RNG is not secure enough you can supply your own
    ///
    /// [1]: https://www.rfc-editor.org/rfc/rfc7516.html#section-5.1
    /// [2]: https://www.rfc-editor.org/rfc/rfc7516.html#section-7.1
    pub fn jwe_encrypt(
        alg: JweAlgorithm,
        key: Vec<u8>,
        payload: Vec<u8>,
        rng: &mut Option<impl Rng>,
    ) -> RustyJwtResult<String> {
        // build the encryption key
        let key = Self::build_jwe_key(alg, key);

        // either the user trusts its platform entropy else it can reseed the PRNG
        let nonce = Self::generate_nonce(alg, rng)?;

        // JWE builder
        let jwe = Compact::new_decrypted(
            RegisteredHeader {
                cek_algorithm: alg.key_management_alg().into(),
                enc_algorithm: alg.into(),
                ..Default::default()
            }
            .into(),
            payload,
        );

        // all the cipher we are expected to use require some IV
        let enc_options = match alg {
            JweAlgorithm::AES128GCM | JweAlgorithm::AES256GCM => EncryptionOptions::AES_GCM { nonce },
        };

        // encrypt into a JWE
        let encrypted = jwe.encrypt(&key, &enc_options, rng)?;
        match encrypted {
            Compact::Encrypted(jwe) => Ok(jwe.encode()),
            Compact::Decrypted { .. } => Err(RustyJwtError::ImplementationError),
        }
    }

    /// TODO
    pub fn jwe_decrypt(alg: JweAlgorithm, key: Vec<u8>, jwe: &str) -> RustyJwtResult<Vec<u8>> {
        // first build the intermediate JWE struct
        let jwe: Compact<Vec<u8>, Empty> = Compact::new_encrypted(jwe);
        // then build the key
        let key = Self::build_jwe_key(alg, key);
        // decrypt the JWE and return the payload
        let decrypted = jwe.decrypt(&key, alg.key_management_alg().into(), alg.into())?;
        match decrypted {
            Compact::Decrypted { payload, .. } => Ok(payload),
            Compact::Encrypted(_) => Err(RustyJwtError::ImplementationError),
        }
    }

    fn build_jwe_key(alg: JweAlgorithm, key: Vec<u8>) -> JWK<Empty> {
        JWK {
            common: CommonParameters {
                algorithm: Some(Algorithm::ContentEncryption(alg.into())),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::OctetKey(OctetKeyParameters {
                key_type: OctetKeyType::Octet,
                value: key,
            }),
            additional: Default::default(),
        }
    }

    fn generate_nonce(alg: JweAlgorithm, rng: &mut Option<impl Rng>) -> RustyJwtResult<Vec<u8>> {
        use rand::{RngCore as _, SeedableRng as _};
        let mut nonce = vec![0u8; alg.iv_len()];
        rng.as_mut()
            .map(|r| r.try_fill_bytes(&mut nonce))
            .unwrap_or_else(|| rand_chacha::ChaCha20Rng::from_entropy().try_fill_bytes(&mut nonce))?;
        Ok::<_, RustyJwtError>(nonce)
    }
}

#[cfg(test)]
pub mod tests {
    use biscuit::jwe::Header;
    use rand::SeedableRng as _;
    use rand_chacha::ChaCha20Rng;
    use serde_json::{json, Value};
    use wasm_bindgen_test::*;

    use helpers::*;

    use crate::test_utils::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cipher)]
    #[wasm_bindgen_test]
    fn can_round_trip(key: JweKey) {
        let payload = "The true sign of intelligence is not knowledge but imagination.";
        let encrypted = RustyJwtTools::jwe_encrypt(
            key.alg,
            key.value.clone(),
            payload.as_bytes().to_vec(),
            &mut None::<ChaCha20Rng>,
        )
        .unwrap();
        assert_ne!(payload, &encrypted);
        let decrypted = RustyJwtTools::jwe_decrypt(key.alg, key.value, &encrypted).unwrap();
        assert_eq!(payload.as_bytes(), &decrypted);
    }

    mod encrypt {
        use super::*;

        #[apply(all_cipher)]
        #[wasm_bindgen_test]
        fn should_support_own_rng(key: JweKey) {
            let payload = "abcd";
            let rng = ChaCha20Rng::from_entropy();
            let jwe1 = RustyJwtTools::jwe_encrypt(
                key.alg,
                key.value.clone(),
                payload.as_bytes().to_vec(),
                &mut Some(rng.clone()),
            )
            .unwrap();
            let jwe2 =
                RustyJwtTools::jwe_encrypt(key.alg, key.value, payload.as_bytes().to_vec(), &mut Some(rng)).unwrap();
            assert_eq!(get_nonce(&jwe1), get_nonce(&jwe2));
            assert_eq!(get_tag(&jwe1), get_tag(&jwe2));
        }

        #[apply(all_cipher)]
        #[wasm_bindgen_test]
        fn should_support_own_rng_for_cek(key: JweKey) {
            let payload = "abcd";
            let rng = ChaCha20Rng::from_entropy();
            let jwe1 = RustyJwtTools::jwe_encrypt(
                key.alg,
                key.value.clone(),
                payload.as_bytes().to_vec(),
                &mut Some(rng.clone()),
            )
            .unwrap();
            let jwe2 =
                RustyJwtTools::jwe_encrypt(key.alg, key.value, payload.as_bytes().to_vec(), &mut Some(rng)).unwrap();
            assert_eq!(get_cek(&jwe1), get_cek(&jwe2))
        }

        #[apply(all_cipher)]
        #[wasm_bindgen_test]
        fn default_rng_should_be_secure_enough(key: JweKey) {
            const ROUNDS: usize = 1000;
            let payload = "abcd";
            for _ in 0..ROUNDS {
                let jwe1 = RustyJwtTools::jwe_encrypt(
                    key.alg,
                    key.value.clone(),
                    payload.as_bytes().to_vec(),
                    &mut None::<ChaCha20Rng>,
                )
                .unwrap();
                let jwe2 = RustyJwtTools::jwe_encrypt(
                    key.alg,
                    key.value.clone(),
                    payload.as_bytes().to_vec(),
                    &mut None::<ChaCha20Rng>,
                )
                .unwrap();
                // if nonce were deterministic this would fail
                assert_ne!(get_nonce(&jwe1), get_nonce(&jwe2));
            }
        }

        #[apply(all_cipher)]
        #[wasm_bindgen_test]
        fn header_should_comply_with_rfc7516(key: JweKey) {
            let rng = ChaCha20Rng::from_entropy();
            let jwe = RustyJwtTools::jwe_encrypt(key.alg, key.value.clone(), b"a".to_vec(), &mut Some(rng)).unwrap();
            let jwe = Compact::<Empty, Empty>::new_encrypted(&jwe).unwrap_encrypted();
            let header = jwe.parts.get(0).unwrap().str();
            let header = base64::decode_config(header, base64::URL_SAFE_NO_PAD).unwrap();
            let header = serde_json::from_slice::<Value>(&header).unwrap();
            let header = header.as_object().unwrap();
            assert_eq!(header["enc"].as_str().unwrap(), &key.alg.to_string());
            assert_eq!(
                header["alg"].as_str().unwrap(),
                &key.alg.key_management_alg().to_string()
            );
            assert_eq!(header["enc"].as_str().unwrap(), &key.alg.to_string());
            match key.alg {
                JweAlgorithm::AES128GCM | JweAlgorithm::AES256GCM => {
                    // https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.1
                    let iv = base64::decode_config(header["iv"].as_str().unwrap(), base64::URL_SAFE_NO_PAD).unwrap();
                    // always 96 bits for AES-GCM
                    assert_eq!(iv.len(), 96 / 8);
                    // https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.2
                    let tag = header["tag"].as_str().unwrap();
                    let tag = base64::decode_config(tag, base64::URL_SAFE_NO_PAD).unwrap();
                    assert_eq!(tag.len(), key.alg.tag_len());
                }
            }
        }
    }

    mod decrypt {
        use super::*;

        #[apply(all_cipher)]
        #[wasm_bindgen_test]
        fn should_fail_decrypting_with_wrong_key(key: JweKey) {
            let payload = "abcd";
            let jwe = RustyJwtTools::jwe_encrypt(
                key.alg,
                key.value,
                payload.as_bytes().to_vec(),
                &mut None::<ChaCha20Rng>,
            )
            .unwrap();
            // use a new random key
            let wrong_key = JweKey::new(key.alg);
            let result = RustyJwtTools::jwe_decrypt(wrong_key.alg, wrong_key.value, &jwe);
            assert!(matches!(result.unwrap_err(), RustyJwtError::JweError(_)));
        }

        #[apply(all_cipher)]
        #[wasm_bindgen_test]
        fn should_fail_decrypting_with_wrong_key_alg(key: JweKey) {
            let payload = "abcd";
            let jwe = RustyJwtTools::jwe_encrypt(
                key.alg,
                key.value,
                payload.as_bytes().to_vec(),
                &mut None::<ChaCha20Rng>,
            )
            .unwrap();
            // use a key of a different algorithm
            let wrong_key = match key.alg {
                JweAlgorithm::AES128GCM => JweKey::new(JweAlgorithm::AES256GCM),
                JweAlgorithm::AES256GCM => JweKey::new(JweAlgorithm::AES128GCM),
            };
            let result = RustyJwtTools::jwe_decrypt(wrong_key.alg, wrong_key.value, &jwe);
            assert!(matches!(
                result.unwrap_err(),
                RustyJwtError::JweError(biscuit::errors::Error::ValidationError(
                    biscuit::errors::ValidationError::WrongAlgorithmHeader
                ))
            ));
        }
    }

    #[cfg(not(target_family = "wasm"))]
    mod interop {
        use super::*;

        // because josekit generates 32 bytes nonce for Key Wrapping whereas biscuit expects 12 bytes
        #[ignore]
        #[apply(all_cipher)]
        #[test]
        fn should_roundtrip_with_josekit_encrypt(key: JweKey) {
            let payload = json!({"a": "b"});
            let jwe = josekit_encrypt(key.alg, key.value.clone(), payload.clone()).unwrap();
            let decrypted = RustyJwtTools::jwe_decrypt(key.alg, key.value, &jwe).unwrap();
            let decrypted = base64::decode_config(decrypted, base64::URL_SAFE_NO_PAD).unwrap();
            let decrypted = serde_json::from_slice::<Value>(&decrypted).unwrap();
            assert_eq!(payload, decrypted);
        }

        #[apply(all_cipher)]
        #[test]
        fn should_roundtrip_with_josekit_decrypt(key: JweKey) {
            let payload = json!({"a": "b"});
            let jwe = RustyJwtTools::jwe_encrypt(
                key.alg,
                key.value.clone(),
                serde_json::to_vec(&payload).unwrap(),
                &mut None::<ChaCha20Rng>,
            )
            .unwrap();
            let decrypted = josekit_decrypt(key.alg, key.value, jwe).unwrap();
            let decrypted = serde_json::from_str::<Value>(&decrypted).unwrap();
            assert_eq!(payload, decrypted);
        }

        fn josekit_encrypt(alg: JweAlgorithm, key: Vec<u8>, payload: Value) -> Result<String, josekit::JoseError> {
            let mut header = josekit::jwe::JweHeader::new();
            header.set_token_type("JWT");
            header.set_content_encryption(alg.to_string());
            header.set_nonce(RustyJwtTools::generate_nonce(alg, &mut None::<ChaCha20Rng>).unwrap());

            let payload = payload.as_object().unwrap().clone();
            let payload = josekit::jwt::JwtPayload::from_map(payload).unwrap();
            let encrypter = match alg {
                JweAlgorithm::AES128GCM => josekit::jwe::A128GCMKW.encrypter_from_bytes(&key),
                JweAlgorithm::AES256GCM => josekit::jwe::A256GCMKW.encrypter_from_bytes(&key),
            }
            .unwrap();
            josekit::jwt::encode_with_encrypter(&payload, &header, &encrypter)
        }

        fn josekit_decrypt(alg: JweAlgorithm, key: Vec<u8>, jwe: String) -> Result<String, josekit::JoseError> {
            let decrypter = match alg {
                JweAlgorithm::AES128GCM => josekit::jwe::A128GCMKW.decrypter_from_bytes(&key),
                JweAlgorithm::AES256GCM => josekit::jwe::A256GCMKW.decrypter_from_bytes(&key),
            }
            .unwrap();
            let (payload, _) = josekit::jwt::decode_with_decrypter(&jwe, &decrypter).unwrap();
            Ok(payload.to_string())
        }
    }

    mod helpers {
        use super::*;

        pub fn get_cek(jwe: &str) -> Vec<u8> {
            let jwe = Compact::<Empty, Empty>::new_encrypted(jwe);
            jwe.unwrap_encrypted().part(1).unwrap()
        }

        pub fn get_header(jwe: &str) -> Header<Empty> {
            let jwe = Compact::<Empty, Empty>::new_encrypted(jwe);
            jwe.unwrap_encrypted().part(0).unwrap()
        }

        pub fn get_nonce(jwe: &str) -> Vec<u8> {
            get_header(jwe).cek_algorithm.nonce.unwrap()
        }

        pub fn get_tag(jwe: &str) -> Vec<u8> {
            get_header(jwe).cek_algorithm.tag.unwrap()
        }
    }
}
