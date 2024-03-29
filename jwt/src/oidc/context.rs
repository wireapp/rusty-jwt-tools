use serde::{Deserialize, Serialize};
use url::Url;

use crate::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
/// see https://www.w3.org/TR/json-ld11/#the-context
pub enum Context {
    /// A JSON-LD context expressed as a Url.
    Url(Url),
    /// A JSON-LD context expressed as a JSON object.
    Obj(JsonObject),
}

impl Context {
    /// Default context for a Verifiable Credential
    pub const CREDENTIAL: &'static str = "https://www.w3.org/2018/credentials/v1";
}

impl From<Url> for Context {
    fn from(u: Url) -> Self {
        Self::Url(u)
    }
}

impl TryFrom<&str> for Context {
    type Error = RustyJwtError;

    fn try_from(u: &str) -> RustyJwtResult<Self> {
        Ok(Url::parse(u)?.into())
    }
}
