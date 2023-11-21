use crate::prelude::{ClientId, RustyJwtError, RustyJwtResult};

/// A unique human-friendly identifier for a user e.g. `beltram_wire`
#[derive(Debug, Clone, Eq, PartialEq, derive_more::From, derive_more::Into, derive_more::Deref)]
pub struct Handle(String);

impl Handle {
    /// Present in front of the handle. It's '@' URL encoded
    pub const PREFIX: &'static str = "%40";

    /// Converts the handle into i.e. `{handle}` => `im:wireapp=%40{handle}@{domain}`
    pub fn to_qualified(&self, domain: &str) -> QualifiedHandle {
        QualifiedHandle(format!("{}{}{}@{domain}", ClientId::URI_PREFIX, Self::PREFIX, self.0))
    }
}

impl TryFrom<QualifiedHandle> for Handle {
    type Error = RustyJwtError;

    fn try_from(qh: QualifiedHandle) -> RustyJwtResult<Self> {
        let trimmed = qh
            .trim_start_matches(ClientId::URI_PREFIX)
            .trim_start_matches(Self::PREFIX);
        let Some((handle, _)) = trimmed.rsplit_once('@') else {
            return Err(RustyJwtError::InvalidHandle);
        };
        Ok(handle.into())
    }
}

impl From<&str> for Handle {
    fn from(s: &str) -> Self {
        s.to_string().into()
    }
}

impl TryFrom<&[u8]> for Handle {
    type Error = RustyJwtError;

    fn try_from(value: &[u8]) -> RustyJwtResult<Self> {
        Ok(core::str::from_utf8(value)?.into())
    }
}

#[cfg(test)]
impl Default for Handle {
    fn default() -> Self {
        "beltram_wire".into()
    }
}

/// A unique human-friendly identifier for a user e.g. `im:wireapp=%40beltram_wire@wire.com`
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize, derive_more::Deref)]
pub struct QualifiedHandle(String);

impl TryFrom<String> for QualifiedHandle {
    type Error = RustyJwtError;

    fn try_from(s: String) -> RustyJwtResult<Self> {
        let prefix = const_format::concatcp!(ClientId::URI_PREFIX, Handle::PREFIX);
        let starts_with_prefix = s.starts_with(prefix);
        let contains_at = s.contains('@');
        if !starts_with_prefix || !contains_at {
            Err(RustyJwtError::InvalidHandle)
        } else {
            Ok(Self(s))
        }
    }
}
impl TryFrom<&str> for QualifiedHandle {
    type Error = RustyJwtError;

    fn try_from(s: &str) -> RustyJwtResult<Self> {
        s.to_string().try_into()
    }
}

#[cfg(test)]
impl Default for QualifiedHandle {
    fn default() -> Self {
        Handle::default().to_qualified("wire.com")
    }
}
