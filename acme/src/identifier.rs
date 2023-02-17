use crate::prelude::*;
use rusty_jwt_tools::prelude::*;

/// Represent an identifier in an ACME Order
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum AcmeIdentifier {
    WireappId(String),
}

impl AcmeIdentifier {
    pub fn try_new(display_name: String, domain: String, client_id: ClientId, handle: String) -> RustyAcmeResult<Self> {
        let client_id = client_id.to_subject();
        let identifier = WireIdentifier {
            display_name,
            domain,
            client_id,
            handle,
        };
        let identifier = serde_json::to_string(&identifier)?;
        Ok(Self::WireappId(identifier))
    }

    pub fn to_wire_identifier(self) -> RustyAcmeResult<WireIdentifier> {
        Ok(match self {
            AcmeIdentifier::WireappId(id) => serde_json::from_str(id.as_str())?,
        })
    }

    /// ACME protocol imposes this to be a json string while we need it to be a json object so
    /// we serialize it to json like this which is simpler than implementing a serde Visitor
    pub fn to_json(&self) -> RustyAcmeResult<String> {
        Ok(serde_json::to_string(self)?)
    }
}

#[cfg(test)]
impl Default for AcmeIdentifier {
    fn default() -> Self {
        Self::WireappId(String::default())
    }
}

#[derive(Default, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(test, derive(Clone))]
pub struct WireIdentifier {
    #[serde(rename = "name")]
    pub display_name: String,
    #[serde(rename = "domain")]
    pub domain: String,
    #[serde(rename = "client-id")]
    pub client_id: String,
    #[serde(rename = "handle")]
    pub handle: String,
}
