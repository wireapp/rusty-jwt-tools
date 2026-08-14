use std::{fmt::Formatter, str::FromStr};

use jsonwebtoken::Algorithm;
use jsonwebtoken::jwk::ThumbprintHash;

use crate::prelude::*;

/// Narrows the supported signature algorithms to the ones we define
#[derive(Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum JwsAlgorithm {
    /// ECDSA using P-256 and SHA-256
    ///
    /// Specified in [RFC 7518 Section 3.4: Digital Signature with ECDSA][1]
    ///
    /// [1]: https://tools.ietf.org/html/rfc7518#section-3.4
    ES256,
    /// ECDSA using P-384 and SHA-384
    ///
    /// Specified in [RFC 7518 Section 3.4: Digital Signature with ECDSA][1]
    ///
    /// [1]: https://tools.ietf.org/html/rfc7518#section-3.4
    ES384,
    /// ECDSA using P-521 and SHA-512
    ///
    /// Specified in [RFC 7518 Section 3.4: Digital Signature with ECDSA][1]
    ///
    /// [1]: https://tools.ietf.org/html/rfc7518#section-3.4
    ES512,
    /// EdDSA using Ed25519
    ///
    /// Specified in [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)][1] and
    /// [RFC 8037: CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption
    /// (JOSE)][2]
    ///
    /// [1]: https://tools.ietf.org/html/rfc8032
    /// [2]: https://tools.ietf.org/html/rfc8037
    EdDSA,
}

impl From<JwsAlgorithm> for jsonwebtoken::Algorithm {
    fn from(alg: JwsAlgorithm) -> Self {
        match alg {
            JwsAlgorithm::ES256 => Self::ES256,
            JwsAlgorithm::ES384 => Self::ES384,
            JwsAlgorithm::ES512 => Self::ES512,
            JwsAlgorithm::EdDSA => Self::EdDSA,
        }
    }
}

impl TryFrom<Algorithm> for JwsAlgorithm {
    type Error = RustyJwtError;

    fn try_from(value: Algorithm) -> Result<Self, Self::Error> {
        match value {
            Algorithm::ES256 => Ok(Self::ES256),
            Algorithm::ES384 => Ok(Self::ES384),
            Algorithm::ES512 => Ok(Self::ES512),
            Algorithm::EdDSA => Ok(Self::EdDSA),
            _ => Err(RustyJwtError::UnsupportedAlgorithm),
        }
    }
}

impl std::fmt::Display for JwsAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            JwsAlgorithm::ES256 => "ES256",
            JwsAlgorithm::ES384 => "ES384",
            JwsAlgorithm::ES512 => "ES512",
            JwsAlgorithm::EdDSA => "EdDSA",
        };
        write!(f, "{name}")
    }
}

impl TryFrom<&str> for JwsAlgorithm {
    type Error = RustyJwtError;

    fn try_from(alg: &str) -> Result<Self, Self::Error> {
        Ok(match alg {
            "ES256" => JwsAlgorithm::ES256,
            "ES384" => JwsAlgorithm::ES384,
            "ES512" => JwsAlgorithm::ES512,
            "EdDSA" => JwsAlgorithm::EdDSA,
            _ => return Err(RustyJwtError::UnsupportedAlgorithm),
        })
    }
}

#[cfg(test)]
impl JwsAlgorithm {
    /// Utility for listing all the JWA signature schemes not supported by this crate
    pub const UNSUPPORTED: [&'static str; 9] = [
        "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
    ];
}

/// Narrows the supported hashing algorithms to the ones we define
#[derive(Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum HashAlgorithm {
    /// SHA-256
    SHA256,
    /// SHA-384
    SHA384,
    /// SHA-512
    SHA512,
}

impl From<HashAlgorithm> for ThumbprintHash {
    fn from(value: HashAlgorithm) -> Self {
        match value {
            HashAlgorithm::SHA256 => ThumbprintHash::SHA256,
            HashAlgorithm::SHA384 => ThumbprintHash::SHA384,
            HashAlgorithm::SHA512 => ThumbprintHash::SHA512,
        }
    }
}

#[cfg(test)]
impl HashAlgorithm {
    pub fn values() -> [Self; 3] {
        [Self::SHA256, Self::SHA384, Self::SHA512]
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            HashAlgorithm::SHA256 => "SHA-256",
            HashAlgorithm::SHA384 => "SHA-384",
            HashAlgorithm::SHA512 => "SHA-512",
        };
        write!(f, "{name}")
    }
}

impl FromStr for HashAlgorithm {
    type Err = RustyJwtError;

    fn from_str(s: &str) -> RustyJwtResult<Self> {
        Ok(match s {
            "SHA-256" => Self::SHA256,
            "SHA-384" => Self::SHA384,
            "SHA-512" => Self::SHA512,
            _ => return Err(RustyJwtError::ImplementationError),
        })
    }
}

/// According to MLS defined ciphersuites
impl From<JwsAlgorithm> for HashAlgorithm {
    fn from(alg: JwsAlgorithm) -> Self {
        match alg {
            JwsAlgorithm::EdDSA | JwsAlgorithm::ES256 => Self::SHA256,
            JwsAlgorithm::ES384 => Self::SHA384,
            JwsAlgorithm::ES512 => Self::SHA512,
        }
    }
}
