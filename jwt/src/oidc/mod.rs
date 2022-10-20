use ::std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/*pub use identity_credential::{
    credential::{Credential as VerifiableCredential, CredentialBuilder as VerifiableCredentialBuilder},
    presentation::{Presentation as VerifiablePresentation, PresentationBuilder as VerifiablePresentationBuilder},
};*/
mod context;
mod credential;
mod datetime;
mod id;
mod issuer;
mod presentation;
mod proof;
mod util;

pub mod prelude {
    pub use super::{
        context::Context,
        credential::RustyCredential,
        datetime::{iso8601, Datetime},
        id::Id,
        issuer::{Issuer, IssuerData},
        presentation::RustyPresentation,
        proof::Proof,
        util::ObjectOrArray,
        CredentialSubject, JsonObject,
    };
}

pub type JsonObject = BTreeMap<String, Value>;

#[cfg_attr(test, derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CredentialSubject {
    /// Arbitrary data
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra_claims: Option<Value>,
}

#[cfg(test)]
pub mod tests {
    use serde_json::{json, Value};
    use url::Url;
    use wasm_bindgen_test::*;

    use crate::oidc::proof::{ProofPurpose, ProofValue};

    use super::prelude::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    #[test]
    fn should_serialize_sample() {
        let expected = serde_json::from_str::<Value>(include_str!("../../tests/resources/sample-oidc.json")).unwrap();
        let credential_1 = RustyCredential {
            context: vec![
                Context::CREDENTIAL.try_into().unwrap(),
                "https://openid.net/2014/openid-connect-core/v1".try_into().unwrap(),
                "https://www.w3.org/2006/vcard/ns".try_into().unwrap(),
            ]
            .into(),
            id: Some(Url::parse("https://idp.example.com/credentials/1872").unwrap()),
            types: vec![
                "VerifiableCredential".to_string(),
                "ImUserIdentityCredential".to_string(),
            ]
            .into(),
            issuer: Issuer::Obj(IssuerData {
                id: "dns:idp.example.com".into(),
                properties: None,
            }),
            issuance_date: time::macros::datetime!(2022-06-19 15:30:16 UTC).into(),
            proof: Some(Proof {
                typ: Proof::ED25519_TYPE.to_string(),
                created: Some(time::macros::datetime!(2022-06-19 15:30:15 UTC).into()),
                value: ProofValue::Jws("LedhVWaZvgklWAsPlGU4aEOuxPgXD16-aL5X7RNAyoXRvHPzYAqH8a3..Yot9dpKNuhWim2EwZUk-rmM876Xex_Con_HGseAqR6o".to_string()),
                purpose: Some(ProofPurpose::AssertionMethod),
                method: "https://idp.example.com/keys/Ed25519/sha256:wF6oONwUJSa3oi8vyBEG8S2CiZANGTN_8ZNXf4RYdyQ".to_string(),
                domain: None,
                expires: None,
                challenge: None,
            }),
            ..Default::default()
        };
        let credential_2 = RustyCredential {
            context: vec![
                Context::CREDENTIAL.try_into().unwrap(),
                "https://ietf.org/2022/oauth/MlsClientCredential/v1".try_into().unwrap(),
            ]
            .into(),
            id: Some(Url::parse("https://im.example.com/credentials/9829381").unwrap()),
            types: vec!["VerifiableCredential".to_string(), "MlsClientIdCredential".to_string()].into(),
            issuer: Issuer::Obj(IssuerData {
                id: "dns:im.example.com".into(),
                properties: None,
            }),
            issuance_date: time::macros::datetime!(2022-09-08 19:23:24 UTC).into(),
            proof: Some(Proof {
                typ: Proof::ED25519_TYPE.to_string(),
                created: Some(time::macros::datetime!(2021-03-19 15:30:15 UTC).into()),
                value: ProofValue::Jws("N8xYGopY8_2wJYuhFX5QMuvMBjzHPJqp06w73UL53BBdhxP9QxtqxTAk..jZrTdfr4kMkCOYhLoFG2L7roGZFmDzVSecfzNwf36lk".to_string()),
                purpose: Some(ProofPurpose::AssertionMethod),
                method: "https://im.example.com/keys/Ed25519/sha256:uZx-Zx68PzlMsd2PgslEWBCF-BDyjMUdVDbZhnCZIls".to_string(),
                domain: None,
                expires: None,
                challenge: None,
            }),
            ..Default::default()
        };
        let patch = json!([
            { "op": "replace", "path": "/verifiableCredential/0/credentialSubject", "value": {
                "sub": "im:%40a_smith@example.com",
                "name": "Smith, Alice (Allie)",
                "preferred_username": "@a_smith@example.com",
                "fn": "Alice M. Smith",
                "hasOrganizationName": "Example Corp",
                "hasOrganizationalUnit": "Engineering",
                "hasInstantMessage": "im:%40a_smith@example.com"
            } },
            { "op": "replace", "path": "/verifiableCredential/1/credentialSubject", "value": {
                "sub": "im:SvPfLlwBQi-6oddVRrkqpw/04c7@example.com"
            } },
        ]);
        let actual = RustyPresentation {
            id: "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5".into(),
            holder: "im:SvPfLlwBQi-6oddVRrkqpw/04c7@example.com".into(),
            context: vec![Context::CREDENTIAL.try_into().unwrap()].into(),
            types: vec!["VerifiablePresentation".to_string()].into(),
            verifiable_credential: vec![credential_1, credential_2].into(),
            proof: Some(Proof {
                typ: Proof::ED25519_TYPE.to_string(),
                value: ProofValue::Jws("eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..UIVpxg5CEOSrQtvpse2svUhgzM3iCZOvcJ-XjwNNd0o".to_string()),
                method: "urn:ietf:params:oauth:jwk-thumbprint:sha-256:mJafqNxZWNAIkaDGPlNyhccFSAqnRjhyA3FJNm0f8I8".to_string(),
                created: Some(time::macros::datetime!(2022-09-22 11:10:04 UTC).into()),
                expires: None,
                challenge: Some("Es6R6R4yI66_yw0d4ulfFQ".to_string()),
                domain: Some("im:SvPfLlwBQi-6oddVRrkqpw/04c7@example.com".to_string()),
                purpose: Some(ProofPurpose::Authentication)
            }),
            extra: Some(patch),
        };
        let actual = actual.try_json_serialize().unwrap();
        assert_eq!(actual, expected);
    }

    #[wasm_bindgen_test]
    #[test]
    fn should_merge_extra_claims() {
        let patch = json!([
            { "op": "add", "path": "/extra", "value": {
                "str": "a",
                "array": ["a"],
                "json": {
                    "a": "b"
                }
            } },
        ]);
        let presentation = RustyPresentation {
            extra: Some(patch),
            ..Default::default()
        };
        let json = presentation.try_json_serialize().unwrap();
        let actual = json.as_object().unwrap().get("extra").unwrap();
        assert_eq!(
            actual,
            &json!({
                "str": "a",
                "array": ["a"],
                "json": {
                    "a": "b"
                }
            })
        );
    }
}
