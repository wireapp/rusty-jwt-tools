use std::fmt::{Display, Formatter};

use crate::prelude::*;

/// UTF-8 String in the PEM (Privacy-Enhanced Mail) format
///
/// Specified in [RFC 7468: Textual Encodings of PKIX, PKCS, and CMS Structures][1]
///
/// [1]: https://tools.ietf.org/html/rfc7468
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Pem(String);

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

impl std::ops::Deref for Pem {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for Pem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
