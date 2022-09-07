#![doc = include_str ! ("../../README.md")]
#![allow(dead_code, unused_imports, unused_variables)]
#![deny(missing_docs)]
#![allow(clippy::single_component_path_imports)]
extern crate core;

#[cfg(test)]
use rstest_reuse;

pub use error::{RustyJwtError, RustyJwtResult};

#[cfg(test)]
#[macro_use]
pub mod test_utils;
// both imports above have to be defined at the beginning of the crate for rstest to work

mod dpop;
mod error;
mod generate_dpop_access_token;
mod generate_dpop_token;
mod jwk;
mod verify_dpop_token;

/// TODO
#[derive(Debug, Copy, Clone)]
pub enum JwsAlgorithm {
    /// TODO
    P256,
    /// TODO
    Ed25519,
}

impl ToString for JwsAlgorithm {
    fn to_string(&self) -> String {
        match self {
            JwsAlgorithm::P256 => "ES256",
            JwsAlgorithm::Ed25519 => "EdDSA",
        }
        .to_string()
    }
}

/// TODO
pub struct RustyJwtTools;

/// TODO
pub const SAMPLE_TOKEN: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// TODO
pub const DPOP_TOKEN: &str = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg";
