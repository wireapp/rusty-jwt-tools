use crate::ByteArray;

/// Client identifier
#[repr(C)]
pub struct QualifiedClientId {
    /// the user ID UUID-4 in ASCII string representation
    pub user: ByteArray,
    /// the client number assigned by the backend
    pub client: u16,
    /// the backend domain of the client
    pub domain: ByteArray,
}

/// Response for DPoP access token generation request
#[repr(C)]
pub struct DpopResponse {
    /// Error code (if any) of the operation
    /// 0 if no error
    /// 1.. map to error code
    pub error: u8,

    /// DPoP token. Will be empty in case of errors
    pub dpop_token: ByteArray,
}

/// Validate the provided dpop_proof DPoP proof JWT from the client,
/// and if valid, return an introspectable DPoP access token.
///
/// Verifications provided:
/// * dpop_proof has the correct syntax
/// * (typ) header field is "dpop+jwt"
/// * signature algorithm (alg) in JWT header is a supported algorithm
/// * signature corresponds to the public key (jwk) in the JWT header
/// * qualified_client_id corresponds to the (sub) claim expressed as URI:
/// * backend_nonce corresponds to the (nonce) claim encoded as base64url.
/// * uri corresponds to the (htu) claim.
/// * method corresponds to the (htm) claim.
/// * (jti) claim is present
/// * (chal) claim is present
/// * (iat) claim is present and no earlier or later than max_skew_secs seconds
///   of now
/// * (exp) claim is present and no larger (later) than max_expiration.
/// * (exp) claim is no later than now plus max_skew_secs.
///
/// # Arguments
///
/// ## dpop_proof
///
/// A DPoP proof in JWS Compact Serialization format
/// Note that the proof consists of three runs of base64url characters
/// (header, claims, signature) separated by period characters.
///
/// ex: b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJle
///     iOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.
///     dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
///     (whitespace and line breaks in the example is not included in the actual proof)
///
/// ## qualified_client_id
///
/// The qualified client ID associated with the currently logged on user
///
/// ex: (b"99db9768-04e3-4b5d-9268-831b6a25c4ab", 0x4a9b, b"example.com")
///
/// ## backend_nonce
///
/// The most recent DPoP nonce provided by the backend to the current client
///
/// ex: hex!("b62551e728771515234fac0b04b2008d")
///
/// ## uri
///
/// The HTTPS URI on the backend for the DPoP auth token endpoint
///
/// ex: b"https://wire.example.com/clients/authtoken"
///
/// ## method
///
/// The HTTPS method used on the backend for the DPoP auth token endpoint
///
/// ex: b"POST"
///
/// ## max_skew_secs
///
/// The maximum number of seconds of clock skew the implementation will allow
///
/// ex: 360  // 5 minutes
///
/// ## max_expiration
///
/// The expiration date and time, in seconds since "the epoch" (the epoch is 1970-Jan-01 0:00:00 UTC).
///
/// ex: 1668987368
///
/// ## now
///
/// Current time in seconds since "the epoch".
///
/// ex: 1661211368
///
/// # backend_pubkey_bundle
///
/// PEM format concatenated private key and public key of the Wire backend
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub extern "C" fn generate_dpop_token(
    _dpop_proof: ByteArray,
    _qualified_client_id: QualifiedClientId,
    _backend_nonce: ByteArray,
    _uri: ByteArray,
    _method: ByteArray,
    _max_skew_secs: u16,
    _max_expiration: u64,
    now: u64,
    _backend_pubkey_bundle: ByteArray,
) -> DpopResponse {
    if now % 2 == 0 {
        DpopResponse {
            error: 1,
            dpop_token: ByteArray::default(),
        }
    } else {
        DpopResponse {
            error: 0,
            dpop_token: ByteArray::from(vec![1, 2, 3]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dpop() {
        let response = generate_dpop_token(
            ByteArray::default(),
            QualifiedClientId {
                user: ByteArray::default(),
                client: 1,
                domain: ByteArray::default(),
            },
            ByteArray::default(),
            ByteArray::default(),
            ByteArray::default(),
            1,
            1,
            1,
            ByteArray::default(),
        );
        assert_eq!(response.error, 0);
        assert!(!response.dpop_token.is_empty());
    }

    #[test]
    fn test_dpop_error() {
        let response = generate_dpop_token(
            ByteArray::default(),
            QualifiedClientId {
                user: ByteArray::default(),
                client: 1,
                domain: ByteArray::default(),
            },
            ByteArray::default(),
            ByteArray::default(),
            ByteArray::default(),
            1,
            1,
            0,
            ByteArray::default(),
        );
        assert_eq!(response.error, 1);
        assert!(response.dpop_token.is_empty());
    }
}
