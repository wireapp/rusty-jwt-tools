use std::fmt::Formatter;
use std::str::FromStr;

use jwt_simple::prelude::*;

use crate::prelude::*;

/// Narrows the supported signature algorithms to the ones we define
#[derive(Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum JwsAlgorithm {
    /// ECDSA using P-256 and SHA-256
    ///
    /// Specified in [RFC 7518 Section 3.4: Digital Signature with ECDSA][1]
    ///
    /// [1]: https://tools.ietf.org/html/rfc7518#section-3.4
    P256,
    /// ECDSA using P-384 and SHA-384
    ///
    /// Specified in [RFC 7518 Section 3.4: Digital Signature with ECDSA][1]
    ///
    /// [1]: https://tools.ietf.org/html/rfc7518#section-3.4
    P384,
    /// ECDSA using P-521 and SHA-512
    ///
    /// Specified in [RFC 7518 Section 3.4: Digital Signature with ECDSA][1]
    ///
    /// [1]: https://tools.ietf.org/html/rfc7518#section-3.4
    P521,
    /// EdDSA using Ed25519
    ///
    /// Specified in [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)][1] and
    /// [RFC 8037: CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)][2]
    ///
    /// [1]: https://tools.ietf.org/html/rfc8032
    /// [2]: https://tools.ietf.org/html/rfc8037
    Ed25519,
}

impl std::fmt::Display for JwsAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            JwsAlgorithm::P256 => "ES256",
            JwsAlgorithm::P384 => "ES384",
            JwsAlgorithm::P521 => "ES512",
            JwsAlgorithm::Ed25519 => "EdDSA",
        };
        write!(f, "{name}")
    }
}

impl TryFrom<&str> for JwsAlgorithm {
    type Error = RustyJwtError;

    fn try_from(alg: &str) -> Result<Self, Self::Error> {
        Ok(match alg {
            "ES256" => JwsAlgorithm::P256,
            "ES384" => JwsAlgorithm::P384,
            "ES512" => JwsAlgorithm::P521,
            "EdDSA" => JwsAlgorithm::Ed25519,
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

/// Supported elliptic curve algorithms
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum JwsEcAlgorithm {
    /// P-256
    P256,
    /// P-384
    P384,
    /// P-521
    P521,
}

impl JwsEcAlgorithm {
    /// For JWK 'crv' field
    pub fn curve(&self) -> EllipticCurve {
        match self {
            JwsEcAlgorithm::P256 => EllipticCurve::P256,
            JwsEcAlgorithm::P384 => EllipticCurve::P384,
            JwsEcAlgorithm::P521 => EllipticCurve::P521,
        }
    }

    /// For JWK 'crv' field
    pub fn kty(&self) -> EllipticCurveKeyType {
        EllipticCurveKeyType::EC
    }
}

impl TryFrom<JwsAlgorithm> for JwsEcAlgorithm {
    type Error = RustyJwtError;

    fn try_from(alg: JwsAlgorithm) -> RustyJwtResult<Self> {
        match alg {
            JwsAlgorithm::P256 => Ok(Self::P256),
            JwsAlgorithm::P384 => Ok(Self::P384),
            JwsAlgorithm::P521 => Ok(Self::P521),
            JwsAlgorithm::Ed25519 => Err(RustyJwtError::ImplementationError),
        }
    }
}

impl From<JwsEcAlgorithm> for JwsAlgorithm {
    fn from(alg: JwsEcAlgorithm) -> Self {
        match alg {
            JwsEcAlgorithm::P256 => Self::P256,
            JwsEcAlgorithm::P384 => Self::P384,
            JwsEcAlgorithm::P521 => Self::P521,
        }
    }
}

/// Supported edward curve algorithms
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum JwsEdAlgorithm {
    /// Ed25519
    Ed25519,
}

impl JwsEdAlgorithm {
    /// For JWK 'crv' field
    pub fn curve(&self) -> EdwardCurve {
        match self {
            JwsEdAlgorithm::Ed25519 => EdwardCurve::Ed25519,
        }
    }

    /// For JWK 'crv' field
    pub fn kty(&self) -> OctetKeyPairType {
        OctetKeyPairType::OctetKeyPair
    }
}

impl TryFrom<JwsAlgorithm> for JwsEdAlgorithm {
    type Error = RustyJwtError;

    fn try_from(alg: JwsAlgorithm) -> RustyJwtResult<Self> {
        match alg {
            JwsAlgorithm::Ed25519 => Ok(Self::Ed25519),
            JwsAlgorithm::P256 | JwsAlgorithm::P384 | JwsAlgorithm::P521 => Err(RustyJwtError::ImplementationError),
        }
    }
}

impl From<JwsEdAlgorithm> for JwsAlgorithm {
    fn from(alg: JwsEdAlgorithm) -> Self {
        match alg {
            JwsEdAlgorithm::Ed25519 => Self::Ed25519,
        }
    }
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
            JwsAlgorithm::Ed25519 | JwsAlgorithm::P256 => Self::SHA256,
            JwsAlgorithm::P384 => Self::SHA384,
            JwsAlgorithm::P521 => Self::SHA512,
        }
    }
}
