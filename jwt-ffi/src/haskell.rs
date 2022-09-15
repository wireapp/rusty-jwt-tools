use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
};

use rusty_jwt_tools::prelude::*;

pub struct RustyJwtToolsFfi;

impl RustyJwtToolsFfi {
    /// see [RustyJwtTools::generate_dpop_access_token]
    #[no_mangle]
    pub extern "C" fn generate_dpop_access_token(
        dpop_proof: *const c_char,
        user: *const c_char,
        client_id: u16,
        domain: *const c_char,
        backend_nonce: *const c_char,
        uri: *const c_char,
        method: *const c_char,
        max_skew_secs: u16,
        max_expiration: u64,
        _now: u64,
        backend_keys: *const c_char,
    ) -> *const HsResult<String> {
        // TODO: remove unwrap
        let dpop = unsafe { CStr::from_ptr(dpop_proof).to_bytes() };
        let dpop = core::str::from_utf8(dpop);
        let user = unsafe { CStr::from_ptr(user).to_bytes() };
        let domain = unsafe { CStr::from_ptr(domain).to_bytes() };
        let client_id = QualifiedClientId::try_from_raw_parts(user, client_id, domain);
        let backend_nonce = BackendNonce::try_from_bytes(unsafe { CStr::from_ptr(backend_nonce).to_bytes() });
        let uri = unsafe { CStr::from_ptr(uri).to_bytes() }.try_into();
        let method = unsafe { CStr::from_ptr(method).to_bytes() }.try_into();
        let backend_kp = unsafe { CStr::from_ptr(backend_keys).to_bytes() }.try_into();
        // TODO: change in API
        let hash_algorithm = HashAlgorithm::SHA256;

        if let (Ok(dpop), Ok(client_id), Ok(nonce), Ok(uri), Ok(method), Ok(kp)) =
            (dpop, client_id, backend_nonce, uri, method, backend_kp)
        {
            let res = RustyJwtTools::generate_access_token(
                dpop,
                client_id,
                nonce,
                uri,
                method,
                max_skew_secs,
                max_expiration,
                kp,
                hash_algorithm,
            )
            .map_err(HsError::from);
            return Box::into_raw(Box::new(res));
        }
        Box::into_raw(Box::new(Err(HsError::ImplementationError)))
    }

    #[no_mangle]
    pub extern "C" fn get_error(ptr: *const HsResult<String>) -> *const u8 {
        let result = unsafe {
            assert!(!ptr.is_null());
            &*ptr
        };

        match result {
            Ok(_) => std::ptr::null_mut(),
            Err(e) => &(*e as u8),
        }
    }

    #[no_mangle]
    pub extern "C" fn get_token(ptr: *const HsResult<String>) -> *const c_char {
        let result = unsafe {
            assert!(!ptr.is_null());
            &*ptr
        };

        match result {
            Ok(value) => {
                // we have to convert this into a ('\0' terminated!) C string
                if let Ok(value) = CString::new(value.as_str()) {
                    value.into_raw()
                } else {
                    std::ptr::null_mut()
                }
            }
            Err(_) => std::ptr::null_mut(),
        }
    }

    /// Frees the allocated [RustyJwtResult] used for returning the result.
    /// This has to be called from haskell
    #[no_mangle]
    pub extern "C" fn free_dpop_access_token(ptr: *mut RustyJwtResult<String>) {
        if ptr.is_null() {
            return;
        }
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

pub type HsResult<T> = Result<T, HsError>;

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
#[allow(dead_code)]
pub enum HsError {
    /// Unmapped error
    UnknownError = 1,
    /// Error at FFI boundary, probably related to raw pointer
    FfiError = 2,
    /// We messed up in rusty-jwt-tools
    ImplementationError = 3,
    /// DPoP token has an invalid syntax
    InvalidDpopSyntax = 4,
    /// DPoP header "typ" is not "dpop+jwt"
    InvalidDpopTyp = 5,
    /// DPoP signature algorithm (alg) in JWT header is not a supported algorithm (ES256, ES384, Ed25519)
    UnsupportedDpopAlgorithm = 6,
    /// DPoP signature does not correspond to the public key (jwk) in the JWT header
    InvalidDpopSignature = 7,
    /// [client_id] does not correspond to the (sub) claim expressed as URI
    ClientIdMismatch = 8,
    /// [backend_nonce] does not correspond to the (nonce) claim in DPoP token (base64url encoded)
    BackendNonceMismatch = 9,
    /// [uri] does not correspond to the (htu) claim in DPoP token
    InvalidHtu = 10,
    /// [method] does not correspond to the (htm) claim in DPoP token
    InvalidHtm = 11,
    /// (jti) claim is absent in DPoP token
    MissingJti = 12,
    /// (chal) claim is absent in DPoP token
    MissingChallenge = 13,
    /// (iat) claim is absent in DPoP token
    MissingIat = 14,
    /// (iat) claim in DPoP token is not earlier of now (with [max_skew_secs] leeway)
    InvalidIat = 15,
    /// (exp) claim is absent in DPoP token
    MissingExp = 16,
    /// (exp) claim in DPoP token is larger than supplied [max_expiration]
    ExpMismatch = 17,
    /// (exp) claim in DPoP token is sooner than now (with [max_skew_secs] leeway)
    Expired = 18,
}

impl From<RustyJwtError> for HsError {
    fn from(e: RustyJwtError) -> Self {
        match e {
            RustyJwtError::InvalidHtu(_, _) => HsError::InvalidHtu,
            RustyJwtError::InvalidHtm(_) => HsError::InvalidHtm,
            RustyJwtError::InvalidDpopJwk => HsError::InvalidDpopSyntax,
            RustyJwtError::InvalidDpopTyp => HsError::InvalidDpopTyp,
            RustyJwtError::UnsupportedAlgorithm => HsError::UnsupportedDpopAlgorithm,
            RustyJwtError::InvalidToken(_) => HsError::InvalidDpopSignature,
            RustyJwtError::TokenSubMismatch => HsError::ClientIdMismatch,
            RustyJwtError::DpopNonceMismatch => HsError::BackendNonceMismatch,
            RustyJwtError::MissingTokenClaim("jti") => HsError::MissingJti,
            RustyJwtError::MissingTokenClaim("chal") => HsError::MissingChallenge,
            RustyJwtError::MissingTokenClaim("iat") => HsError::MissingIat,
            RustyJwtError::MissingTokenClaim("exp") => HsError::MissingExp,
            RustyJwtError::InvalidDpopIat => HsError::InvalidIat,
            RustyJwtError::TokenLivesTooLong => HsError::ExpMismatch,
            RustyJwtError::TokenExpired => HsError::Expired,
            RustyJwtError::ImplementationError => HsError::ImplementationError,
            _ => HsError::UnknownError,
        }
    }
}
