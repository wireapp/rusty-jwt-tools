use serde::{Deserialize, Serialize};
use url::Url;

use crate::oidc::prelude::*;

#[cfg_attr(test, derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
/// Verifiable credential
pub struct RustyCredential {
    /// The JSON-LD context(s) applicable to the `Credential`.
    #[serde(rename = "@context")]
    pub context: ObjectOrArray<Context>,
    /// A unique `URI` that may be used to identify the `Credential`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Url>,
    /// One or more URIs defining the type of the `Credential`.
    #[serde(rename = "type")]
    pub types: ObjectOrArray<String>,
    /// Proof(s) used to verify a `Presentation`
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
    /// A reference to the issuer of the `Credential`.
    pub issuer: Issuer,
    /// A timestamp of when the `Credential` becomes valid.
    #[serde(rename = "issuanceDate", with = "iso8601")]
    pub issuance_date: Datetime,
    /// A timestamp of when the `Credential` should no longer be considered valid.
    #[serde(
        rename = "expirationDate",
        with = "iso8601::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub expiration_date: Option<Datetime>,
    /// Proof(s) used to verify a `Credential`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}
