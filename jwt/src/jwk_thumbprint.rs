//! JWK thumbprint

use base64::Engine;
use jwt_simple::prelude::*;
use serde_json::{json, Value};
use sha2::Digest;

use crate::prelude::*;

/// Represents a [JWK thumbprint][1] represented according to [JWT Proof-of-Possession Key Semantics][2]
///
/// [1]: https://www.rfc-editor.org/rfc/rfc7638.html
/// [2]: https://www.rfc-editor.org/rfc/rfc7800.html
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(test, derive(Default))]
pub struct JwkThumbprint {
    /// JWK thumbprint
    #[serde(rename = "kid")]
    pub kid: String,
}

impl JwkThumbprint {
    /// generates a base64 encoded hash of a JWK
    pub fn generate(jwk: &Jwk, alg: HashAlgorithm) -> RustyJwtResult<Self> {
        let json = Self::compute_json(jwk);
        let json = serde_json::to_vec(&json)?;
        let kid = match alg {
            HashAlgorithm::SHA256 => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(json);
                let hash = &hasher.finalize()[..];
                base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(hash)
            }
            HashAlgorithm::SHA384 => {
                let mut hasher = sha2::Sha384::new();
                hasher.update(json);
                let hash = &hasher.finalize()[..];
                base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(hash)
            }
        };
        Ok(Self { kid })
    }

    /// Filters out some JWK fields and lexicographically order them as per [RFC 7638 Section 3.2][1]
    ///
    /// [1]: https://www.rfc-editor.org/rfc/rfc7638.html#section-3.2
    fn compute_json(jwk: &Jwk) -> Value {
        match jwk.algorithm.clone() {
            AlgorithmParameters::RSA(RSAKeyParameters { key_type, n, e }) => json!({
                "e": e,
                "kty": key_type,
                "n": n,
            }),
            AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters { key_type, curve, x, y }) => json!({
                "crv": curve,
                "kty": key_type,
                "x": x,
                "y": y,
            }),
            AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters { key_type, curve, x }) => json!({
                "crv": curve,
                "kty": key_type,
                "x": x,
            }),
            _ => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::jwk::RustyJwk;
    use crate::test_utils::*;

    use super::*;

    #[test]
    fn rfc_test() {
        let n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string();
        let jwk = Jwk {
            common: CommonParameters {
                public_key_use: None,
                key_operations: None,
                algorithm: Some("RS256".to_string()),
                key_id: Some("2011-04-29".to_string()),
                x509_url: None,
                x509_chain: None,
                x509_sha1_fingerprint: None,
                x509_sha256_fingerprint: None,
            },
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: RSAKeyType::RSA,
                n,
                e: "AQAB".to_string(),
            }),
        };
        let thumbprint = JwkThumbprint::generate(&jwk, HashAlgorithm::SHA256).unwrap();
        assert_eq!(&thumbprint.kid, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
    }

    mod test_vectors {
        use super::*;

        #[apply(all_hash)]
        #[test]
        fn rsa(hash: HashAlgorithm) {
            let e = "AQAB".to_string();
            let n = "3Ra1kbdyBFvCtL459VQMK8h8ry2wPJXlf3ZBzP5Lu6DPSLbmH_BXB4bVQ1MMo5hgQ0aIN6bw4Bb1qN-qUpKCr3a-TN3wfmYfjAl1Km-qYMpPPZliZyLKqx9_m0prClyffIBnYxZF04KQDHSkgqDxYywUqAKBlhu37RP0HFD7ZwPUdlv1DL_ep2zlm8CiWyvRe1kKpnvFqq6VLwOFia4eXenEwRE4GEDqj9PpmPCN6Bd-PvlBxI8GsWbl57pCXW6zsh3TV70b2rJDGEm06kORNvN5C_X_8U6lIVeCepeFDJKgyKH5lMhbV6uSl2-AX6TK0ARzvx3DQK16KRhO95RRQw".to_string();
            let jwk = Jwk {
                common: CommonParameters::default(),
                algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                    key_type: RSAKeyType::RSA,
                    n,
                    e,
                }),
            };
            let thumbprint = JwkThumbprint::generate(&jwk, hash).unwrap();
            match hash {
                HashAlgorithm::SHA256 => assert_eq!(&thumbprint.kid, "e-HDhEsEb24hxthgVnPrRXb1IBrsRzMkzrKqFfUTmqE"),
                HashAlgorithm::SHA384 => assert_eq!(
                    &thumbprint.kid,
                    "EcgQUf2ct-84eLYyH0o-leu6RJ46Lq_5jlCCEa5RlAPVcLXgHoh4Q0RnwFqRuk3y"
                ),
            }
        }

        #[apply(all_hash)]
        #[test]
        fn es256(hash: HashAlgorithm) {
            let x = "KKIwHE0jKHJXdzF3lEeIfRw0Vqf-S6YIjX6t6iSZPIE".to_string();
            let y = "Kng6pbKYmgw1MWCyaoXEbP3nYPpvs5yH7BYOhrivpe0".to_string();
            let jwk = Jwk {
                common: CommonParameters::default(),
                algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                    key_type: EllipticCurveKeyType::EC,
                    curve: EllipticCurve::P256,
                    x,
                    y,
                }),
            };
            let thumbprint = JwkThumbprint::generate(&jwk, hash).unwrap();
            match hash {
                HashAlgorithm::SHA256 => assert_eq!(&thumbprint.kid, "ESpNh4PQZO3u7Q1laesYlhHQfV7LBZKdKGfyyCY2YTU"),
                HashAlgorithm::SHA384 => assert_eq!(
                    &thumbprint.kid,
                    "tdNAT4Jr8cRlkxmgtYcum6EAGLWl6AXsflQs5izMSCY9gsFTD-cd5j1_vmev5_2X"
                ),
            }
        }

        #[apply(all_hash)]
        #[test]
        fn es384(hash: HashAlgorithm) {
            let x = "RMqa4EpWcufvQm7paEK6ptQNYrRUnHp11YtvzFcQf5dJ8fvITjstBTCoy0v0R8Ec".to_string();
            let y = "9b9PWo6wxew9QGyjTsRSXiz64N6Y2bLiiWALT47l7X8STVnER9kFLwtZ98CJOwE5".to_string();
            let jwk = Jwk {
                common: CommonParameters::default(),
                algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                    key_type: EllipticCurveKeyType::EC,
                    curve: EllipticCurve::P384,
                    x,
                    y,
                }),
            };
            let thumbprint = JwkThumbprint::generate(&jwk, hash).unwrap();
            match hash {
                HashAlgorithm::SHA256 => assert_eq!(&thumbprint.kid, "sBSdg6mJ9HqH-gMhbVsd6FYFm2Kl3-axd82pYlzxUFY"),
                HashAlgorithm::SHA384 => assert_eq!(
                    &thumbprint.kid,
                    "SDannkEbVekJlQtvocnp8oF38WVF23gEXj3tDqQnVlzJdinp2vgT-W-wbBN_wksO"
                ),
            }
        }

        #[apply(all_hash)]
        #[test]
        fn ed25519(hash: HashAlgorithm) {
            let x = "fe6kgFGhCGu7epAE3JK9Zv2NpQlAzb88ta58ktVA9mQ".to_string();
            let jwk = Jwk {
                common: CommonParameters::default(),
                algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                    key_type: OctetKeyPairType::OctetKeyPair,
                    curve: EdwardCurve::Ed25519,
                    x,
                }),
            };
            let thumbprint = JwkThumbprint::generate(&jwk, hash).unwrap();
            match hash {
                HashAlgorithm::SHA256 => assert_eq!(&thumbprint.kid, "UIaMEN16usO38HgRukG-HKGibaUtiITH5opS1qbnQiU"),
                HashAlgorithm::SHA384 => assert_eq!(
                    &thumbprint.kid,
                    "Ow8bJ-FJVEMr6XcEDsio9IYfeq8OpvIgJnsE-7vQs2rdk_sWnp4gGjxMxAqcEjMy"
                ),
            }
        }
    }

    #[apply(all_ciphersuites)]
    #[test]
    fn should_use_only_required_fields(ciphersuite: Ciphersuite) {
        let jwk = RustyJwk::rand_jwk(ciphersuite.key.alg);
        // we will compare a thumbprint of a JWK with ALL its optional fields and one with none
        // They should both be equal because optional fields should be filtered out
        let minimal = Jwk {
            common: CommonParameters::default(),
            algorithm: jwk.algorithm.clone(),
        };
        let maximal = Jwk {
            common: CommonParameters {
                public_key_use: Some(PublicKeyUse::Signature),
                key_operations: Some(vec![KeyOperations::DeriveKey, KeyOperations::Decrypt]),
                algorithm: Some(ciphersuite.key.alg.to_string()),
                key_id: Some(uuid::Uuid::new_v4().to_string()),
                x509_url: Some("https://wire.com".to_string()),
                x509_chain: Some(vec!["abc".to_string(), "def".to_string()]),
                x509_sha1_fingerprint: Some("gntu".to_string()),
                x509_sha256_fingerprint: Some("mtys".to_string()),
            },
            algorithm: jwk.algorithm,
        };
        assert_eq!(
            JwkThumbprint::generate(&minimal, ciphersuite.hash).unwrap(),
            JwkThumbprint::generate(&maximal, ciphersuite.hash).unwrap(),
        )
    }

    #[test]
    fn order() {
        // By default 'serde_json' does not activate its `preserve_order` feature which guarantees us
        // that json fields are lexicographically ordered as we want them to be.
        // This test is a guard against anyone activating the feature by mistake
        let jwk = Jwk {
            common: CommonParameters::default(),
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: RSAKeyType::RSA,
                n: "0vx7".to_string(),
                e: "AQAB".to_string(),
            }),
        };
        let json = JwkThumbprint::compute_json(&jwk);
        assert_eq!(
            json,
            json!({
                "e": "AQAB",
                "kty": "RSA",
                "n": "0vx7",
            })
        )
    }
}
