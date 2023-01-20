use crate::prelude::RustyAcmeResult;
use rusty_jwt_tools::prelude::ClientId;

/// Represent an identifier in an ACME Order
#[derive(Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(test, derive(Clone))]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum AcmeIdentifier {
    WireappId(String),
}

impl AcmeIdentifier {
    pub fn try_new(display_name: String, domain: String, client_id: ClientId, handle: String) -> RustyAcmeResult<Self> {
        let client_id = client_id.to_subject();
        let identifier = WireIdentifier {
            name: display_name,
            domain,
            client_id,
            handle,
        };
        let identifier = serde_json::to_string(&identifier)?;
        Ok(Self::WireappId(identifier))
    }

    pub fn wire_identifier(self) -> RustyAcmeResult<WireIdentifier> {
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
#[serde(rename_all = "kebab-case")]
pub struct WireIdentifier {
    pub name: String,
    pub domain: String,
    pub client_id: String,
    pub handle: String,
}
