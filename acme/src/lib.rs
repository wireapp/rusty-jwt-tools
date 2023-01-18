mod account;
mod authz;
mod certificate;
mod chall;
mod directory;
#[cfg(any(test, feature = "docker"))]
mod docker;
mod error;
mod finalize;
mod identifier;
mod jws;
mod order;

/// Prelude
pub mod prelude {
    pub use super::RustyAcme;
    use super::*;
    pub use account::AcmeAccount;
    pub use chall::AcmeChallenge;
    pub use error::{RustyAcmeError, RustyAcmeResult};
    pub use identifier::AcmeIdentifier;
    pub use jws::AcmeJws;

    pub use directory::AcmeDirectory;
    #[cfg(all(feature = "docker", not(target_family = "wasm")))]
    pub use docker::*;
}

pub struct RustyAcme;
