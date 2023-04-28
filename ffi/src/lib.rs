#![cfg(not(target_family = "wasm"))]
#![warn(dead_code)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! We only declare here intermediate FFI representation with raw types. But we do not generate
//! all the bindings and wrappers here.
//! * Haskell: we expose a C-FFI and [wire-server](https://github.com/wireapp/wire-server) will
//! maintain the Haskell wrapper
//! * WASM: we handle bindings here but we let [core-crypto](https://github.com/wireapp/core-crypto)
//! maintain the Typescript wrapper
//! * Android/iOS: we just expose raw types and let [core-crypto](https://github.com/wireapp/core-crypto)
//! generate the bindings and wrappers

use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
    str::FromStr,
};

use rusty_jwt_tools::prelude::*;

pub struct RustyJwtToolsFfi;

impl RustyJwtToolsFfi {
    /// see [RustyJwtTools::generate_dpop_access_token]
    #[no_mangle]
    pub extern "C" fn generate_dpop_access_token(
        dpop_proof: *const c_char,
        user: *const c_char,
        client_id: u64,
        domain: *const c_char,
        backend_nonce: *const c_char,
        uri: *const c_char,
        method: *const c_char,
        max_skew_secs: u16,
        max_expiration: u64,
        _now: u64,
        backend_keys: *const c_char,
    ) -> *const HsResult<String> {
        let dpop = unsafe { CStr::from_ptr(dpop_proof).to_bytes() };
        let dpop = core::str::from_utf8(dpop);
        let user = unsafe { CStr::from_ptr(user) };
        let Some(user) = std::str::from_utf8(user.to_bytes()).ok()
            .and_then(|s| uuid::Uuid::from_str(s).ok()) else {
            return Box::into_raw(Box::new(Err(HsError::InvalidUserId)))
        };
        let domain = unsafe { CStr::from_ptr(domain).to_bytes() };
        let client_id = ClientId::try_from_raw_parts(user.as_ref(), client_id, domain);
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
                &client_id,
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
    pub extern "C" fn get_error(ptr: *const HsResult<String>) -> u8 {
        let result = unsafe {
            assert!(!ptr.is_null());
            &*ptr
        };

        match result {
            Err(e) => *e as u8,
            _ => 0,
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

    /// Frees the allocated [HsResult] used for returning the result.
    /// This has to be called from haskell
    #[no_mangle]
    pub extern "C" fn free_dpop_access_token(ptr: *mut HsResult<String>) {
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
    /// userId supplied across the FFI is invalid
    InvalidUserId = 19,
    /// Client DPoP token "nbf" claim is in the future
    NotYetValid = 20,
}

impl From<RustyJwtError> for HsError {
    fn from(e: RustyJwtError) -> Self {
        match e {
            RustyJwtError::InvalidHtu(_, _) => Self::InvalidHtu,
            RustyJwtError::InvalidHtm(_) => Self::InvalidHtm,
            RustyJwtError::InvalidDpopJwk => Self::InvalidDpopSyntax,
            RustyJwtError::InvalidDpopTyp => Self::InvalidDpopTyp,
            RustyJwtError::UnsupportedAlgorithm => Self::UnsupportedDpopAlgorithm,
            RustyJwtError::InvalidToken(_) => Self::InvalidDpopSignature,
            RustyJwtError::TokenSubMismatch => Self::ClientIdMismatch,
            RustyJwtError::DpopNonceMismatch => Self::BackendNonceMismatch,
            RustyJwtError::MissingTokenClaim("jti") => Self::MissingJti,
            RustyJwtError::MissingTokenClaim("chal") => Self::MissingChallenge,
            RustyJwtError::MissingTokenClaim("iat") => Self::MissingIat,
            RustyJwtError::MissingTokenClaim("exp") => Self::MissingExp,
            RustyJwtError::InvalidDpopIat => Self::InvalidIat,
            RustyJwtError::DpopNotYetValid => Self::NotYetValid,
            RustyJwtError::TokenLivesTooLong => Self::ExpMismatch,
            RustyJwtError::TokenExpired => Self::Expired,
            RustyJwtError::ImplementationError => Self::ImplementationError,
            _ => Self::UnknownError,
        }
    }
}
