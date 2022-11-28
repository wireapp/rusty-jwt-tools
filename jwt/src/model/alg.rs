use jwt_simple::prelude::*;
use std::fmt::Formatter;

use crate::prelude::*;

/// Narrows the supported signature algorithms to the ones we define
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
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
    /// EdDSA using Ed25519
    ///
    /// Specified in [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)][1] and
    /// [RFC 8037: CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)][2]
    ///
    /// [1]: https://tools.ietf.org/html/rfc8032
    /// [2]: https://tools.ietf.org/html/rfc8037
    Ed25519,
}

impl ToString for JwsAlgorithm {
    fn to_string(&self) -> String {
        match self {
            JwsAlgorithm::P256 => "ES256",
            JwsAlgorithm::P384 => "ES384",
            JwsAlgorithm::Ed25519 => "EdDSA",
        }
        .to_string()
    }
}

impl TryFrom<&str> for JwsAlgorithm {
    type Error = RustyJwtError;

    fn try_from(alg: &str) -> Result<Self, Self::Error> {
        Ok(match alg {
            "ES256" => JwsAlgorithm::P256,
            "ES384" => JwsAlgorithm::P384,
            "EdDSA" => JwsAlgorithm::Ed25519,
            _ => return Err(RustyJwtError::UnsupportedAlgorithm),
        })
    }
}

#[cfg(test)]
impl JwsAlgorithm {
    /// Utility for listing all the JWA signature schemes not supported by this crate
    pub const UNSUPPORTED: [&'static str; 10] = [
        "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES512",
    ];
}

/// Supported elliptic curve algorithms
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum JwsEcAlgorithm {
    /// P-256
    P256,
    /// P-384
    P384,
}

impl JwsEcAlgorithm {
    /// For JWK 'crv' field
    pub fn curve(&self) -> EllipticCurve {
        match self {
            JwsEcAlgorithm::P256 => EllipticCurve::P256,
            JwsEcAlgorithm::P384 => EllipticCurve::P384,
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
            JwsAlgorithm::Ed25519 => Err(RustyJwtError::ImplementationError),
        }
    }
}

impl From<JwsEcAlgorithm> for JwsAlgorithm {
    fn from(alg: JwsEcAlgorithm) -> Self {
        match alg {
            JwsEcAlgorithm::P256 => Self::P256,
            JwsEcAlgorithm::P384 => Self::P384,
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
            JwsAlgorithm::P256 | JwsAlgorithm::P384 => Err(RustyJwtError::ImplementationError),
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
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HashAlgorithm {
    /// SHA-256
    SHA256,
    /// SHA-384
    SHA384,
}

#[cfg(test)]
impl HashAlgorithm {
    pub fn values() -> [Self; 2] {
        [Self::SHA256, Self::SHA384]
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            HashAlgorithm::SHA256 => "SHA-256",
            HashAlgorithm::SHA384 => "SHA-384",
        };
        write!(f, "{name}")
    }
}
