use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
};

use rusty_jwt_tools::prelude::*;

struct RustyJwtToolsFfi;

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
        now: u64,
        backend_keys: *const c_char,
    ) -> *const RustyJwtResult<String> {
        let dpop_proof = unsafe { CStr::from_ptr(dpop_proof).to_bytes() };
        let user = unsafe { CStr::from_ptr(user).to_bytes() };
        let domain = unsafe { CStr::from_ptr(domain).to_bytes() };
        let backend_nonce = unsafe { CStr::from_ptr(backend_nonce).to_bytes() };
        let uri = unsafe { CStr::from_ptr(uri).to_bytes() };
        let method = unsafe { CStr::from_ptr(method).to_bytes() };
        let backend_keys = unsafe { CStr::from_ptr(backend_keys).to_bytes() };

        let res = RustyJwtTools::generate_dpop_access_token(
            dpop_proof,
            user,
            client_id,
            domain,
            backend_nonce,
            uri,
            method,
            max_skew_secs,
            max_expiration,
            now,
            backend_keys,
        );
        Box::into_raw(Box::new(res))
    }

    #[no_mangle]
    pub extern "C" fn get_error(ptr: *const RustyJwtResult<String>) -> *const u8 {
        let result = unsafe {
            assert!(!ptr.is_null());
            &*ptr
        };

        match result {
            Ok(_) => std::ptr::null_mut(),
            Err(e) => {
                let hs_err = HsError::from(e);
                &(hs_err as u8)
            }
        }
    }

    #[no_mangle]
    pub extern "C" fn get_token(ptr: *const RustyJwtResult<String>) -> *const c_char {
        let result = unsafe {
            assert!(!ptr.is_null());
            &*ptr
        };

        match result {
            Ok(value) => {
                // we have to convert this into a (null terminated!) C string
                CString::new(value.clone()).unwrap().into_raw()
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

#[derive(Debug)]
#[repr(u8)]
#[allow(dead_code, clippy::enum_variant_names)]
pub enum HsError {
    /// Indicates Haskell consumer there's no error and it can safely consume the response
    NoError = 0,
    /// Unmapped error
    UnknownError = 1,
    /// Error at FFI boundary, probably related to raw pointer
    FfiError = 2,
    /// We messed up in rusty-jwt-tools
    ImplementationError = 3,
    /// DPoP token has an invalid syntax
    DpopSyntaxError = 4,
    /// DPoP header "typ" is not "dpop+jwt"
    DpopTypError = 5,
    /// DPoP signature algorithm (alg) in JWT header is not a supported algorithm (ES256, ES384, Ed25519)
    DpopUnsupportedAlgorithmError = 6,
    /// DPoP signature does not correspond to the public key (jwk) in the JWT header
    DpopInvalidSignatureError = 7,
    /// [client_id] does not correspond to the (sub) claim expressed as URI
    ClientIdMismatchError = 8,
    /// [backend_nonce] does not correspond to the (nonce) claim in DPoP token (base64url encoded)
    BackendNonceMismatchError = 9,
    /// [uri] does not correspond to the (htu) claim in DPoP token
    HtuMismatchError = 10,
    /// method does not correspond to the (htm) claim in DPoP token
    HtmMismatchError = 11,
    /// (jti) claim is absent in DPoP token
    MissingJtiError = 12,
    /// (chal) claim is absent in DPoP token
    MissingChallengeError = 13,
    /// (iat) claim is absent in DPoP token
    MissingIatError = 14,
    /// (iat) claim in DPoP token is not earlier of now (with [max_skew_secs] leeway)
    IatError = 15,
    /// (exp) claim is absent in DPoP token
    MissingExpError = 16,
    /// (exp) claim in DPoP token is larger than supplied [max_expiration]
    ExpMismatchError = 17,
    /// (exp) claim in DPoP token is sooner than now (with [max_skew_secs] leeway)
    ExpError = 18,
}

impl From<&RustyJwtError> for HsError {
    fn from(e: &RustyJwtError) -> Self {
        match e {
            RustyJwtError::HtuError(_, _) => HsError::HtuMismatchError,
            RustyJwtError::ImplementationError => HsError::ImplementationError,
            _ => HsError::UnknownError,
        }
    }
}
