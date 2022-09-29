use crate::oidc::prelude::*;
use serde::{Deserialize, Serialize};
use url::Url;

/// An identifier representing the issuer of a [`Credential`][crate::credential::Credential].
///
/// [More Info](https://www.w3.org/TR/vc-data-model/#issuer)
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Issuer {
    /// A credential issuer expressed as a Url.
    Url(Url),
    /// A credential issuer expressed as a JSON object.
    Obj(IssuerData),
}

impl From<Url> for Issuer {
    fn from(u: Url) -> Self {
        Self::Url(u)
    }
}

#[cfg(test)]
impl Default for Issuer {
    fn default() -> Self {
        Self::Url(Url::parse("https://example.edu/issuers/14").unwrap())
    }
}

/// A [`Credential`][crate::credential::Credential] issuer in object form.
///
/// [More Info](https://www.w3.org/TR/vc-data-model/#issuer)
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct IssuerData {
    /// A Url identifying the credential issuer.
    #[serde(rename = "id")]
    pub id: Id,
    /// Additional properties of the credential issuer.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub properties: Option<JsonObject>,
}
