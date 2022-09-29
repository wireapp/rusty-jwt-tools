use crate::oidc::prelude::*;
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

#[cfg_attr(test, derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RustyPresentation {
    /// The JSON-LD context(s) applicable to the `Presentation`.
    #[serde(rename = "@context")]
    pub context: ObjectOrArray<Context>,
    /// A unique `URI` that may be used to identify the `Presentation`.
    #[serde(rename = "id")]
    pub id: Id,
    /// The entity that generated the `Presentation`.
    #[serde(rename = "holder")]
    pub holder: Id,
    /// One or more URIs defining the type of the `Presentation`.
    #[serde(rename = "type")]
    pub types: ObjectOrArray<String>,
    /// Credential(s) expressing the claims of the `Presentation`.
    #[serde(rename = "verifiableCredential")]
    pub verifiable_credential: ObjectOrArray<RustyCredential>,
    /// Proof(s) used to verify a `Presentation`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
    /// Extra claims merged using [RFC 6902: Json Patch](https://www.rfc-editor.org/rfc/rfc6902)
    #[serde(skip)]
    pub extra: Option<Value>,
}

impl RustyPresentation {
    pub fn try_json_serialize(&self) -> RustyJwtResult<Value> {
        let mut json = serde_json::to_value(self)?;
        if let Some(extra) = &self.extra {
            // TODO: fix, highly inefficient
            let patch = serde_json::to_string(extra).unwrap();
            let p: json_patch::Patch = serde_json::from_str(&patch).unwrap();
            json_patch::patch(&mut json, &p).unwrap();
        }
        Ok(json)
    }
}
