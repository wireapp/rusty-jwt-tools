use biscuit::jwa::{ContentEncryptionAlgorithm, KeyManagementAlgorithm};

/// Narrows the supported encryption algorithms to the ones we define
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum JweAlgorithm {
    /// AES-GCM using 128-bit key
    ///
    /// Specified in [RFC 7518 Section 5.3: Content Encryption with AES GCM][1]
    ///
    /// [1]: https://www.rfc-editor.org/rfc/rfc7518#section-5.3
    AES128GCM,
    /// AES-GCM using 256-bit key
    ///
    /// Specified in [RFC 7518 Section 5.3: Content Encryption with AES GCM][1]
    ///
    /// [1]: https://www.rfc-editor.org/rfc/rfc7518#section-5.3
    AES256GCM,
}

impl JweAlgorithm {
    /// Maps to a key wrapping algorithm
    pub const fn key_management_alg(&self) -> JweKeyManagementAlgorithm {
        match self {
            Self::AES128GCM => JweKeyManagementAlgorithm::AES128GCMKW,
            Self::AES256GCM => JweKeyManagementAlgorithm::AES256GCMKW,
        }
    }

    /// Returns encryption key expected length
    pub const fn key_length(&self) -> usize {
        match self {
            JweAlgorithm::AES128GCM => 128 / 8,
            // same for ChaCha20-Poly1305
            JweAlgorithm::AES256GCM => 256 / 8,
        }
    }

    /// Returns IV (initialization vector) length
    /// Currently, it is always 96 bits for AES-GCM (and also for ChaCha20-Poly1305 which might be supported later)
    pub const fn iv_len(&self) -> usize {
        // 12 bytes
        const IV_LEN: usize = 96 / 8;
        IV_LEN
    }

    /// AEAD tag length
    /// Currently, it is always 128 bits for AES-GCM (and also for ChaCha20-Poly1305 which might be supported later)
    /// see [RFC7518][1]
    ///
    /// [1]: https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.2
    pub const fn tag_len(&self) -> usize {
        // 12 bytes
        const TAG_LEN: usize = 128 / 8;
        TAG_LEN
    }
}

impl From<JweAlgorithm> for ContentEncryptionAlgorithm {
    fn from(a: JweAlgorithm) -> Self {
        match a {
            JweAlgorithm::AES128GCM => Self::A128GCM,
            JweAlgorithm::AES256GCM => Self::A256GCM,
        }
    }
}

impl ToString for JweAlgorithm {
    fn to_string(&self) -> String {
        match self {
            Self::AES128GCM => "A128GCM",
            Self::AES256GCM => "A256GCM",
        }
        .to_string()
    }
}

/// Algorithms for key management as defined in [RFC7518][1]
///
/// [1]: https://www.rfc-editor.org/rfc/rfc7518#4
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum JweKeyManagementAlgorithm {
    /// Key wrapping with AES GCM using 128-bit key
    ///
    /// Specified in [RFC 7518 Section 4.4: Key Wrapping with AES Key Wrap][1]
    ///
    /// [1]: https://www.rfc-editor.org/rfc/rfc7518#section-4.4
    AES128GCMKW,
    /// Key wrapping with AES GCM using 256-bit key
    ///
    /// Specified in [RFC 7518 Section 4.4: Key Wrapping with AES Key Wrap][1]
    ///
    /// [1]: https://www.rfc-editor.org/rfc/rfc7518#section-4.4
    AES256GCMKW,
}

impl From<JweKeyManagementAlgorithm> for KeyManagementAlgorithm {
    fn from(kma: JweKeyManagementAlgorithm) -> Self {
        match kma {
            JweKeyManagementAlgorithm::AES128GCMKW => Self::A128GCMKW,
            JweKeyManagementAlgorithm::AES256GCMKW => Self::A256GCMKW,
        }
    }
}

impl ToString for JweKeyManagementAlgorithm {
    fn to_string(&self) -> String {
        match self {
            Self::AES128GCMKW => "A128GCMKW",
            Self::AES256GCMKW => "A256GCMKW",
        }
        .to_string()
    }
}
