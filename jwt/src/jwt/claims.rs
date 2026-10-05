use coarsetime::{Clock, Duration, UnixTimeStamp};
use serde::{Deserialize, Serialize};

use crate::prelude::*;

/// A set of JWT claims: the registered claims from [RFC 7519 Section 4.1][1] plus application-defined `custom` ones
///
/// [1]: https://www.rfc-editor.org/rfc/rfc7519#section-4.1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims<T> {
    /// Time the claims were created at
    #[serde(
        rename = "iat",
        default,
        skip_serializing_if = "Option::is_none",
        with = "unix_timestamp"
    )]
    pub issued_at: Option<UnixTimeStamp>,
    /// Time the claims expire at
    #[serde(
        rename = "exp",
        default,
        skip_serializing_if = "Option::is_none",
        with = "unix_timestamp"
    )]
    pub expires_at: Option<UnixTimeStamp>,
    /// Time the claims will be invalid until
    #[serde(
        rename = "nbf",
        default,
        skip_serializing_if = "Option::is_none",
        with = "unix_timestamp"
    )]
    pub invalid_before: Option<UnixTimeStamp>,
    /// Issuer
    #[serde(rename = "iss", default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Subject
    #[serde(rename = "sub", default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Audience
    #[serde(rename = "aud", default, skip_serializing_if = "Option::is_none")]
    pub audiences: Option<Audiences>,
    /// JWT identifier
    #[serde(rename = "jti", default, skip_serializing_if = "Option::is_none")]
    pub jwt_id: Option<String>,
    /// Nonce
    #[serde(rename = "nonce", default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Custom (application-defined) claims
    #[serde(flatten)]
    pub custom: T,
}

impl<T> JwtClaims<T> {
    /// Creates claims issued now and expiring in `valid_for`, all other registered claims being empty
    pub fn new(custom: T, valid_for: Duration) -> Self {
        let now = Clock::now_since_epoch();
        Self {
            issued_at: Some(now),
            expires_at: Some(now + valid_for),
            invalid_before: Some(now),
            issuer: None,
            subject: None,
            audiences: None,
            jwt_id: None,
            nonce: None,
            custom,
        }
    }
}

/// The 'aud' claim, which [RFC 7519 Section 4.1.3][1] allows to be either a single string or an array of strings
///
/// [1]: https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audiences {
    /// A single audience
    AsString(String),
    /// Multiple audiences
    AsList(Vec<String>),
}

impl Audiences {
    /// Returns the single audience, failing when there is more or less than one
    pub fn into_string(self) -> RustyJwtResult<String> {
        match self {
            Self::AsString(audience) => Ok(audience),
            Self::AsList(audiences) => match <[String; 1]>::try_from(audiences) {
                Ok([audience]) => Ok(audience),
                Err(_) => Err(RustyJwtError::InvalidAudience),
            },
        }
    }
}

/// (De)serializes a [UnixTimeStamp] as a JWT [NumericDate][1], i.e. seconds since the UNIX epoch
///
/// [1]: https://www.rfc-editor.org/rfc/rfc7519#section-2
mod unix_timestamp {
    use coarsetime::UnixTimeStamp;
    use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer};

    pub fn serialize<S: Serializer>(timestamp: &Option<UnixTimeStamp>, serializer: S) -> Result<S::Ok, S::Error> {
        timestamp.map(|t| t.as_secs()).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<UnixTimeStamp>, D::Error> {
        // NumericDate may contain a fractional part
        let secs = Option::<f64>::deserialize(deserializer)?;
        Ok(secs.map(|secs| UnixTimeStamp::from_secs(secs as u64)))
    }
}
