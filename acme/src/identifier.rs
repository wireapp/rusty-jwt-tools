/// /// Represent an identifier in an ACME Order
#[derive(Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(test, derive(Clone))]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum AcmeIdentifier {
    Dns(String),
}

impl AcmeIdentifier {
    pub fn value(&self) -> &str {
        match self {
            Self::Dns(host) => host,
        }
    }
}

impl std::str::FromStr for AcmeIdentifier {
    type Err = crate::error::RustyAcmeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::Dns(url::Host::parse(s)?.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test]
    fn can_deserialize_rfc_sample() {
        let rfc_sample = json!({ "type": "dns", "value": "example.org" });
        assert!(serde_json::from_value::<AcmeIdentifier>(rfc_sample).is_ok());
    }
}
