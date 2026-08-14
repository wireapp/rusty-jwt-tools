//! JWK thumbprint

use jsonwebtoken::jwk::Jwk;
use serde::{Deserialize, Serialize};

use crate::prelude::*;

/// Represents a [JWK thumbprint][1] represented according to [JWT Proof-of-Possession Key Semantics][2]
///
/// [1]: https://www.rfc-editor.org/rfc/rfc7638.html
/// [2]: https://www.rfc-editor.org/rfc/rfc7800.html
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(test, derive(Default))]
pub struct JwkThumbprint {
    /// JWK thumbprint
    #[serde(rename = "kid")]
    pub kid: String,
}

impl JwkThumbprint {
    /// generates a base64 encoded hash of a JWK
    pub fn generate(jwk: &Jwk, alg: HashAlgorithm) -> RustyJwtResult<Self> {
        let kid = jwk.thumbprint(alg.into())?;
        Ok(Self { kid })
    }
}
