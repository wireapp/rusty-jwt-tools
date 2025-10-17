#![cfg(not(target_family = "wasm"))]
#![warn(dead_code)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! We only declare here intermediate FFI representation with raw types. But we do not generate
//! all the bindings and wrappers here.
//! * Haskell: we expose a C-FFI and [wire-server](https://github.com/wireapp/wire-server) will
//!   maintain the Haskell wrapper
//! * WASM: we handle bindings here but we let [core-crypto](https://github.com/wireapp/core-crypto)
//!   maintain the Typescript wrapper
//! * Android/iOS: we just expose raw types and let [core-crypto](https://github.com/wireapp/core-crypto)
//!   generate the bindings and wrappers

use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
    str::FromStr,
};

use rusty_jwt_tools::prelude::*;

pub struct RustyJwtToolsFfi;

impl RustyJwtToolsFfi {
    /// see [RustyJwtTools::generate_access_token]
    ///
    /// ## Safety
    ///
    /// This function accepts several C-style string pointers as parameters.
    /// Each of them must abide by the following restrictions for safe usage:
    ///
    /// Safety
    ///
    /// - The memory pointed to by `ptr` must contain a valid nul terminator at the end of the string.
    /// - `ptr` must be valid for reads of bytes up to and including the nul terminator. This means in particular:
    ///     - The entire memory range of this `CStr` must be contained within a single allocated object!
    ///     - `ptr` must be non-null even for a zero-length cstr.
    ///     - The memory referenced by the returned CStr must not be mutated for the duration of lifetime 'a.
    /// - The nul terminator must be within `isize::MAX` from `ptr`
    #[unsafe(no_mangle)]
    pub extern "C" fn generate_dpop_access_token(
        dpop_proof: *const c_char,
        user: *const c_char,
        client_id: u64,
        handle: *const c_char,
        display_name: *const c_char,
        team: *const c_char,
        domain: *const c_char,
        backend_nonce: *const c_char,
        uri: *const c_char,
        method: *const c_char,
        max_skew_secs: u16,
        max_expiration: u64,
        _now: u64,
        backend_keys: *const c_char,
        // api_version: u32,
        // expiry_secs: u64,
    ) -> *const HsResult<String> {
        // TODO: setting default values for now. Do it properly later
        let api_version = 5;
        let expiry_secs = 360;

        // SAFETY: safe if the rules in the function signature are all followed for `dpop_proof`
        let dpop = unsafe { CStr::from_ptr(dpop_proof).to_bytes() };
        let dpop = core::str::from_utf8(dpop);
        // SAFETY: safe if the rules in the function signature are all followed for `user`
        let user = unsafe { CStr::from_ptr(user) };
        let Some(user) = std::str::from_utf8(user.to_bytes())
            .ok()
            .and_then(|s| uuid::Uuid::from_str(s).ok())
        else {
            return Box::into_raw(Box::new(Err(HsError::InvalidUserId)));
        };
        // SAFETY: safe if the rules in the function signature are all followed for `domain`
        let domain = unsafe { CStr::from_ptr(domain).to_bytes() };
        // SAFETY: safe if the rules in the function signature are all followed for `team`
        let team = unsafe { CStr::from_ptr(team).to_bytes() }.try_into();
        let client_id = ClientId::try_from_raw_parts(user.as_ref(), client_id, domain);
        // SAFETY: safe if the rules in the function signature are all followed for `handle`
        let handle: Result<Handle, _> = unsafe { CStr::from_ptr(handle).to_bytes() }.try_into();
        // SAFETY: safe if the rules in the function signature are all followed for `display_name`
        let display_name = unsafe { CStr::from_ptr(display_name).to_bytes() };
        let display_name = core::str::from_utf8(display_name);
        // SAFETY: safe if the rules in the function signature are all followed for `backend_nonce`
        let backend_nonce = BackendNonce::try_from_bytes(unsafe { CStr::from_ptr(backend_nonce).to_bytes() });
        // SAFETY: safe if the rules in the function signature are all followed for `uri`
        let uri = unsafe { CStr::from_ptr(uri).to_bytes() }.try_into();
        // SAFETY: safe if the rules in the function signature are all followed for `method`
        let method = unsafe { CStr::from_ptr(method).to_bytes() }.try_into();
        // SAFETY: safe if the rules in the function signature are all followed for `backend_keys`
        let backend_kp = unsafe { CStr::from_ptr(backend_keys).to_bytes() }.try_into();
        // TODO: change in API
        let hash_algorithm = HashAlgorithm::SHA256;
        let expiry = core::time::Duration::from_secs(expiry_secs);

        if let (
            Ok(dpop),
            Ok(client_id),
            Ok(handle),
            Ok(display_name),
            Ok(team),
            Ok(nonce),
            Ok(uri),
            Ok(method),
            Ok(kp),
        ) = (
            dpop,
            client_id,
            handle,
            display_name,
            team,
            backend_nonce,
            uri,
            method,
            backend_kp,
        ) {
            let handle = match handle.try_to_qualified(&client_id.domain).map_err(HsError::from) {
                Ok(handle) => handle,
                Err(e) => return Box::into_raw(Box::new(Err(e))),
            };
            let res = RustyJwtTools::generate_access_token(
                dpop,
                &client_id,
                handle,
                display_name,
                team,
                nonce,
                uri,
                method,
                max_skew_secs,
                max_expiration,
                kp,
                hash_algorithm,
                api_version,
                expiry,
            )
            .map_err(HsError::from);
            return Box::into_raw(Box::new(res));
        }
        Box::into_raw(Box::new(Err(HsError::ImplementationError)))
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_error(ptr: *const HsResult<String>) -> u8 {
        // SAFETY: safe because if the pointer is null we panic before dereferencing it
        let result = unsafe {
            assert!(!ptr.is_null());
            &*ptr
        };

        match result {
            Err(e) => *e as u8,
            _ => 0,
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_token(ptr: *const HsResult<String>) -> *const c_char {
        // SAFETY: safe because if the pointer is null we panic before dereferencing it
        let result = unsafe {
            assert!(!ptr.is_null());
            &*ptr
        };

        match result {
            Ok(value) => {
                // we have to convert this into a ('\0' terminated!) C string
                match CString::new(value.as_str()) {
                    Ok(value) => value.into_raw(),
                    _ => std::ptr::null_mut(),
                }
            }
            Err(_) => std::ptr::null_mut(),
        }
    }

    /// Frees the allocated [HsResult] used for returning the result.
    /// This has to be called from haskell
    #[unsafe(no_mangle)]
    pub extern "C" fn free_dpop_access_token(ptr: *mut HsResult<String>) {
        if ptr.is_null() {
            return;
        }
        // SAFETY: safe because if the pointer is null we don't arrive at this point
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
    /// `client_id` does not correspond to the (sub) claim expressed as URI
    ClientIdMismatch = 8,
    /// `backend_nonce` does not correspond to the (nonce) claim in DPoP token (base64url encoded)
    BackendNonceMismatch = 9,
    /// `uri` does not correspond to the (htu) claim in DPoP token
    InvalidHtu = 10,
    /// `method` does not correspond to the (htm) claim in DPoP token
    InvalidHtm = 11,
    /// (jti) claim is absent in DPoP token
    MissingJti = 12,
    /// (chal) claim is absent in DPoP token
    MissingChallenge = 13,
    /// (iat) claim is absent in DPoP token
    MissingIat = 14,
    /// (iat) claim in DPoP token is not earlier of now (with `max_skew_secs` leeway)
    InvalidIat = 15,
    /// (exp) claim is absent in DPoP token
    MissingExp = 16,
    /// (exp) claim in DPoP token is larger than supplied `max_expiration`
    ExpMismatch = 17,
    /// (exp) claim in DPoP token is sooner than now (with `max_skew_secs` leeway)
    Expired = 18,
    /// userId supplied across the FFI is invalid
    InvalidUserId = 19,
    /// Client DPoP token "nbf" claim is in the future
    NotYetValid = 20,
    /// Bubbling up errors
    JwtSimpleError = 21,
    /// Bubbling up errors
    RandError = 22,
    /// Bubbling up errors
    Sec1Error = 23,
    /// Bubbling up errors
    UrlParseError = 24,
    /// Bubbling up errors
    UuidError = 25,
    /// Bubbling up errors
    Utf8Error = 26,
    /// Bubbling up errors
    Base64DecodeError = 27,
    /// Bubbling up errors
    JsonError = 28,
    /// Bubbling up errors
    InvalidJwkThumbprint = 31,
    /// Bubbling up errors
    MissingDpopHeader = 32,
    /// Bubbling up errors
    MissingIssuer = 33,
    /// Bubbling up errors
    DpopChallengeMismatch = 34,
    /// Bubbling up errors
    DpopHtuMismatch = 35,
    /// Bubbling up errors
    DpopHtmMismatch = 36,
    /// Bubbling up errors
    InvalidBackendKeys = 37,
    /// Bubbling up errors
    InvalidClientId = 38,
    /// Bubbling up errors
    UnsupportedApiVersion = 39,
    /// Bubbling up errors
    UnsupportedScope = 40,
    /// Client handle does not match the supplied handle
    DpopHandleMismatch = 41,
    /// Client team does not match the supplied team
    DpopTeamMismatch = 42,
    /// Client display name does not match the supplied display name
    DpopDisplayNameMismatch = 43,
}

impl From<RustyJwtError> for HsError {
    fn from(e: RustyJwtError) -> Self {
        match e {
            RustyJwtError::InvalidHtu(..) => Self::InvalidHtu,
            RustyJwtError::InvalidHtm(_) => Self::InvalidHtm,
            RustyJwtError::InvalidDpopJwk => Self::InvalidDpopSyntax,
            RustyJwtError::InvalidDpopTyp => Self::InvalidDpopTyp,
            RustyJwtError::UnsupportedAlgorithm => Self::UnsupportedDpopAlgorithm,
            RustyJwtError::InvalidToken(_) => Self::InvalidDpopSignature,
            RustyJwtError::TokenSubMismatch => Self::ClientIdMismatch,
            RustyJwtError::DpopNonceMismatch => Self::BackendNonceMismatch,
            RustyJwtError::DpopHandleMismatch => Self::DpopHandleMismatch,
            RustyJwtError::DpopTeamMismatch => Self::DpopTeamMismatch,
            RustyJwtError::MissingTokenClaim("jti") => Self::MissingJti,
            RustyJwtError::MissingTokenClaim("chal") => Self::MissingChallenge,
            RustyJwtError::MissingTokenClaim("iat") => Self::MissingIat,
            RustyJwtError::MissingTokenClaim("exp") => Self::MissingExp,
            RustyJwtError::InvalidDpopIat => Self::InvalidIat,
            RustyJwtError::DpopNotYetValid => Self::NotYetValid,
            RustyJwtError::TokenLivesTooLong => Self::ExpMismatch,
            RustyJwtError::TokenExpired => Self::Expired,
            RustyJwtError::ImplementationError => Self::ImplementationError,
            RustyJwtError::JwtSimpleError(_) => Self::JwtSimpleError,
            RustyJwtError::Sec1Error(_) => Self::Sec1Error,
            RustyJwtError::UrlParseError(_) => Self::UrlParseError,
            RustyJwtError::UuidError(_) => Self::UuidError,
            RustyJwtError::Utf8Error(_) => Self::Utf8Error,
            RustyJwtError::Base64DecodeError(_) => Self::Base64DecodeError,
            RustyJwtError::JsonError(_) => Self::JsonError,
            RustyJwtError::InvalidJwkThumbprint => Self::InvalidJwkThumbprint,
            RustyJwtError::MissingDpopHeader(_) => Self::MissingDpopHeader,
            RustyJwtError::MissingIssuer => Self::MissingIssuer,
            RustyJwtError::DpopChallengeMismatch => Self::DpopChallengeMismatch,
            RustyJwtError::DpopHtuMismatch => Self::DpopHtuMismatch,
            RustyJwtError::DpopHtmMismatch => Self::DpopHtmMismatch,
            RustyJwtError::InvalidBackendKeys(_) => Self::InvalidBackendKeys,
            RustyJwtError::InvalidClientId => Self::InvalidClientId,
            RustyJwtError::UnsupportedApiVersion => Self::UnsupportedApiVersion,
            RustyJwtError::UnsupportedScope => Self::UnsupportedScope,
            RustyJwtError::DpopDisplayNameMismatch => Self::DpopDisplayNameMismatch,
            _ => Self::UnknownError,
        }
    }
}
