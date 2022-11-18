use serde::{Deserialize, Serialize};

use crate::oidc::prelude::*;

/// A digital signature.
///
/// For field definitions see: [the W3C Security Vocabulary specification](https://w3c-ccg.github.io/security-vocab/).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    #[serde(rename = "type")]
    /// Proof's type
    pub typ: String,
    #[serde(flatten)]
    /// Proof's value
    pub value: ProofValue,
    #[serde(rename = "verificationMethod")]
    /// Proof's verification method
    pub method: String,
    /// When the proof was generated.
    #[serde(with = "iso8601::option", skip_serializing_if = "Option::is_none")]
    pub created: Option<Datetime>,
    /// When the proof expires.
    #[serde(with = "iso8601::option", skip_serializing_if = "Option::is_none")]
    pub expires: Option<Datetime>,
    /// Challenge from a proof requester to mitigate replay attacks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    /// Domain for which a proof is valid to mitigate replay attacks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Purpose for which the proof was generated.
    #[serde(rename = "proofPurpose", skip_serializing_if = "Option::is_none")]
    pub purpose: Option<ProofPurpose>,
}

impl Proof {
    /// Proof type with an Ed25519 signature
    pub const ED25519_TYPE: &'static str = "Ed25519Signature2018";
}

/// A DID Document proof value with a dynamic JSON field name.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum ProofValue {
    /// An empty signature value.
    #[serde(skip)]
    None,
    /// A signature value with the property name `jws`.
    #[serde(rename = "jws")]
    Jws(String),
    /// A signature value with the property name `proofValue`.
    #[serde(rename = "proofValue")]
    Proof(String),
    /// A signature value with the property name `signatureValue`.
    #[serde(rename = "signatureValue")]
    Signature(String),
}

/// Associates a purpose with a [Proof].
///
/// See the [W3C Security Vocabulary description](https://w3c-ccg.github.io/security-vocab/#proofPurpose).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProofPurpose {
    /// Purpose is to assert a claim.
    /// See the [W3C Security Vocabulary description](https://www.w3.org/TR/did-core/#assertion).
    #[serde(rename = "assertionMethod")]
    AssertionMethod,
    /// Purpose is to authenticate the signer.
    /// See the [W3C Security Vocabulary description](https://www.w3.org/TR/did-core/#authentication).
    #[serde(rename = "authentication")]
    Authentication,
}
