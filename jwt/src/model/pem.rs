use crate::prelude::*;

/// UTF-8 String in the PEM (Privacy-Enhanced Mail) format
///
/// Specified in [RFC 7468: Textual Encodings of PKIX, PKCS, and CMS Structures][1]
///
/// [1]: https://tools.ietf.org/html/rfc7468
#[derive(Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Pem(String);

impl std::fmt::Debug for Pem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pem(<redacted>)")
    }
}

impl Pem {
    /// Borrows the PEM as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Borrows the PEM as bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<String> for Pem {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for Pem {
    fn from(s: &str) -> Self {
        s.to_string().into()
    }
}

impl<'a> TryFrom<&'a [u8]> for Pem {
    type Error = RustyJwtError;

    fn try_from(value: &'a [u8]) -> RustyJwtResult<Self> {
        Ok(core::str::from_utf8(value)?.into())
    }
}
