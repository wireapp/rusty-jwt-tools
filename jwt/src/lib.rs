#![doc = include_str ! ("../../README.md")]
#![allow(dead_code, unused_imports, unused_variables)]
#![deny(missing_docs)]
#![allow(clippy::single_component_path_imports)]
extern crate core;

#[cfg(test)]
use rstest_reuse;

#[cfg(test)]
#[macro_use]
pub mod test_utils;
// both imports above have to be defined at the beginning of the crate for rstest to work

mod alg;
mod dpop;
mod error;
mod generate_dpop_access_token;
mod generate_dpop_token;
mod jwk;
mod nonce;
mod verify_dpop_token;

/// Prelude
pub mod prelude {
    pub use alg::JwsAlgorithm;
    pub use error::{RustyJwtError, RustyJwtResult};
    pub use nonce::{AcmeChallenge, BackendNonce};

    pub use super::ClientId;
    pub use super::Pem;
    pub use super::RustyJwtTools;
    use super::*;
}

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

impl From<Pem> for String {
    fn from(p: Pem) -> Self {
        p.0
    }
}

impl std::ops::Deref for Pem {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Unique user handle
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ClientId(String);

impl From<String> for ClientId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<ClientId> for String {
    fn from(p: ClientId) -> Self {
        p.0
    }
}

impl std::ops::Deref for ClientId {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Provides helpers for creating a validating DPoP (Demonstrating Proof of Possession) JWT
///
/// Specified in [OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)][1]
///
/// [1]: https://www.ietf.org/archive/id/draft-ietf-oauth-dpop-08.html
pub struct RustyJwtTools;

/// TODO
pub const SAMPLE_TOKEN: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// TODO
pub const DPOP_TOKEN: &str = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg";
