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

mod dpop;
mod error;
mod generate_dpop_access_token;
mod generate_dpop_token;
mod verify_dpop_token;

/// TODO
pub struct RustyJwtTools;

/// TODO
pub const SAMPLE_TOKEN: &'static str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
