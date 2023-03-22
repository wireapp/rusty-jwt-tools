#![doc = include_str ! ("../../README.md")]
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
mod oidc;

/// Prelude
pub mod prelude {
    pub use dpop::{Dpop, Htm, Htu};
    pub use error::{RustyJwtError, RustyJwtResult};
    pub use jwk_thumbprint::JwkThumbprint;
    pub use model::{
        alg::{HashAlgorithm, JwsAlgorithm, JwsEcAlgorithm, JwsEdAlgorithm},
        client_id::ClientId,
        nonce::{AcmeNonce, BackendNonce},
        pem::Pem,
        pk::AnyPublicKey,
    };
    pub use oidc::{
        context::Context,
        credential::RustyCredential,
        datetime::{iso8601, Datetime},
        id::Id,
        issuer::{Issuer, IssuerData},
        presentation::RustyPresentation,
        proof::{Proof, ProofPurpose, ProofValue},
        util::ObjectOrArray,
        CredentialSubject, JsonObject,
    };

    #[cfg(feature = "jwe")]
    pub use jwe::alg::JweAlgorithm;

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
