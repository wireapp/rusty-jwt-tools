//! # Rusty JWT Tools
//!
//! A collection of JWT utilities.
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
#[cfg(feature = "jwe")]
mod jwe;
pub mod jwk;
pub mod jwk_thumbprint;
pub mod jwt;
mod model;

/// Prelude
pub mod prelude {
    pub use dpop::{Dpop, Htm, Htu};
    pub use error::{RustyJwtError, RustyJwtResult};
    pub use jwk::json::parse_json_jwk;

    pub use jwk_thumbprint::JwkThumbprint;
    pub use model::{
        alg::{HashAlgorithm, JwsAlgorithm, JwsEcAlgorithm, JwsEdAlgorithm},
        client_id::ClientId,
        handle::{Handle, QualifiedHandle},
        nonce::{AcmeNonce, BackendNonce},
        pem::Pem,
        pk::AnyPublicKey,
        team::Team,
    };

    #[cfg(feature = "jwe")]
    pub use jwe::alg::JweAlgorithm;

    #[cfg(feature = "test-utils")]
    pub use jwk::generate_jwk;

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
