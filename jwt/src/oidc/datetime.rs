//! In [revision 1.1 of Verifiable Credential](https://w3c.github.io/vc-data-model/#revision-history)
//! date-time went from [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) to
//! [XSD datetime](https://www.w3.org/TR/xmlschema11-2/#dateTime).
//!
//! As the specification says ["The ·value space· of dateTime is closely related to the dates and times described in ISO 8601"](https://www.w3.org/TR/xmlschema-2/#dateTime)
//! so we are going to use ISO 8601 format for the moment even though we might have later on to implement
//! our own parser.
//!
//! NB: there are currently no crate available for supporting xsd:datetime

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Datetime(time::OffsetDateTime);

impl From<time::OffsetDateTime> for Datetime {
    fn from(dt: time::OffsetDateTime) -> Self {
        Self(dt)
    }
}

#[cfg(test)]
impl Datetime {
    pub fn now_utc() -> Self {
        Self(time::OffsetDateTime::now_utc())
    }
}

#[cfg(test)]
impl Default for Datetime {
    fn default() -> Self {
        Self::now_utc()
    }
}

/// Wrapping `time` serializer to accommodate our newtype
pub mod iso8601 {
    use super::*;
    use serde::{Deserializer, Serializer};
    use time::format_description::well_known;

    // naively try to stick to 'xsd:datetime'
    pub(crate) const SERDE_CONFIG: well_known::iso8601::EncodedConfig = well_known::iso8601::Config::DEFAULT
        .set_year_is_six_digits(false)
        .set_time_precision(well_known::iso8601::TimePrecision::Second {
            decimal_digits: std::num::NonZeroU8::new(0),
        })
        .encode();

    pub fn serialize<S: Serializer>(datetime: &Datetime, serializer: S) -> Result<S::Ok, S::Error> {
        // time::serde::iso8601::serialize(&datetime.0, serializer)
        time::serde::rfc3339::serialize(&datetime.0, serializer)
        // datetime.0.format(&well_known::Iso8601::<SERDE_CONFIG>).unwrap().serialize(serializer)
    }

    pub fn deserialize<'a, D: Deserializer<'a>>(deserializer: D) -> Result<Datetime, D::Error> {
        // time::serde::iso8601::deserialize(deserializer).map(Datetime)
        time::serde::rfc3339::deserialize(deserializer).map(Datetime)
    }

    pub mod option {
        use super::*;

        pub fn serialize<S: Serializer>(option: &Option<Datetime>, serializer: S) -> Result<S::Ok, S::Error> {
            // option.as_ref().map(|odt| odt.0.format(&well_known::Iso8601::<SERDE_CONFIG>)).transpose().unwrap().serialize(serializer)
            // time::serde::iso8601::option::serialize(&option.as_ref().map(|d| d.0), serializer)
            time::serde::rfc3339::option::serialize(&option.as_ref().map(|d| d.0), serializer)
        }

        /// Deserialize an [`Option<Datetime>`] from its ISO 8601 representation.
        pub fn deserialize<'a, D: Deserializer<'a>>(deserializer: D) -> Result<Option<Datetime>, D::Error> {
            // time::serde::iso8601::option::deserialize(deserializer).map(|r| r.map(Datetime))
            time::serde::rfc3339::option::deserialize(deserializer).map(|r| r.map(Datetime))
        }
    }
}
