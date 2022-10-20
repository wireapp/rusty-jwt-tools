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

mod access;
mod dpop;
mod error;
mod introspect;
mod jkt;
mod jwe;
mod jwk;
mod jwt;
mod model;
mod oidc;

/// Prelude
pub mod prelude {
    pub use dpop::{Dpop, Htm, Htu};
    pub use error::{RustyJwtError, RustyJwtResult};
    pub use jwe::alg::JweAlgorithm;
    pub use model::{
        alg::{HashAlgorithm, JwsAlgorithm, JwsEcAlgorithm, JwsEdAlgorithm},
        client_id::QualifiedClientId,
        nonce::{AcmeChallenge, BackendNonce},
        pem::Pem,
        pk::AnyPublicKey,
    };

    pub use super::RustyJwtTools;
    use super::*;
}

/// Provides helpers for creating a validating DPoP (Demonstrating Proof of Possession) JWT
///
/// Specified in [OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)][1]
///
/// [1]: https://www.ietf.org/archive/id/draft-ietf-oauth-dpop-11.html
#[derive(Debug)]
pub struct RustyJwtTools;
