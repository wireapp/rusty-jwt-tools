use serde::{Deserialize, Serialize};

use crate::prelude::*;

/// Nonce generated by the acme server.
/// Also called `challenge`, it is used for authentication challenge
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AcmeChallenge(String);

impl From<String> for AcmeChallenge {
    fn from(challenge: String) -> Self {
        Self(challenge)
    }
}

impl From<&str> for AcmeChallenge {
    fn from(challenge: &str) -> Self {
        challenge.to_string().into()
    }
}

impl TryFrom<&[u8]> for AcmeChallenge {
    type Error = RustyJwtError;

    fn try_from(value: &[u8]) -> RustyJwtResult<Self> {
        Ok(Self::from(core::str::from_utf8(value)?))
    }
}

impl std::ops::Deref for AcmeChallenge {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
impl AcmeChallenge {
    pub fn rand() -> Self {
        Self(crate::test_utils::rand_str(32))
    }
}

#[cfg(test)]
impl Default for AcmeChallenge {
    fn default() -> Self {
        Self("okAJ33Ym/XS2qmmhhh7aWSbBlYy4Ttm1EysqW8I/9ng".to_string())
    }
}

/// Nonce generated by [wire-server](https://github.com/wireapp/wire-server)
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackendNonce(String);

impl BackendNonce {
    /// From bytes
    pub fn try_from_bytes(bytes: &[u8]) -> RustyJwtResult<Self> {
        Ok(core::str::from_utf8(bytes)?.into())
    }
}

impl From<String> for BackendNonce {
    fn from(nonce: String) -> Self {
        Self(nonce)
    }
}

impl From<&str> for BackendNonce {
    fn from(nonce: &str) -> Self {
        Self(nonce.to_string())
    }
}

#[cfg(test)]
impl<'a> From<&'a [u8]> for BackendNonce {
    fn from(s: &'a [u8]) -> Self {
        String::from_utf8(s.to_vec()).unwrap().into()
    }
}

impl std::ops::Deref for BackendNonce {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
impl BackendNonce {
    pub fn rand() -> Self {
        Self(crate::test_utils::rand_str(32))
    }
}

#[cfg(test)]
impl Default for BackendNonce {
    fn default() -> Self {
        Self("WE88EvOBzbqGerznM+2P/AadVf7374y0cH19sDSZA2A".to_string())
    }
}
