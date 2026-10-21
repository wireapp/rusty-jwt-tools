#![cfg(not(target_family = "wasm"))]
#![warn(dead_code)]
#![expect(clippy::not_unsafe_ptr_arg_deref)]

//! This crate exposes API needed to generate DPoP access tokens in foreign code.
//!
//! The primary user is [wire-server](https://github.com/wireapp/wire-server), which
//! uses it to generate an access token for the purpose of validating a 'wire-dpop-01'
//! ACME challenge, as implemented in [Smallstep CA](https://github.com/smallstep/certificates).
//!
//! The bindings comprise the following functions:
//! - generate_dpop_access_token
//! - free_dpop_access_token
//! - get_error
//! - get_token

use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
    str::FromStr,
};

use rusty_jwt_tools::prelude::*;

pub struct RustyJwtToolsFfi;

// Expiration time for the access token. Note that the token will actually be valid for more
// than this due to NOW_LEEWAY_SECONDS subtracted from the actual time of issuance.
// I.e. we will end up with
//
//                NOW_LEEWAY_SECONDS                ACCESS_TOKEN_EXPIRY
//     |--------------------------------------|---------------------------|
//
//    iat                              time of issuance                  exp
//    nbf
//
const ACCESS_TOKEN_EXPIRY: std::time::Duration = std::time::Duration::from_secs(360);

// The value of the `api_version` claim in the access token.
//
// The claim doesn't seem to be meaningfully used by the Smallstep ACME server
// (well, apart from the server expecting it to be there). Ideally, we would
// not add this claim when creating the access token, but we cannot do that
// without also modifying the Smallstep ACME server to remove the mention of
// this claim.
const ACCESS_TOKEN_API_VERSION: u32 = 5;

impl RustyJwtToolsFfi {
    /// see [RustyJwtTools::generate_access_token]
    ///
    /// If any input is invalid, the returned [HsResult] holds the error for the first invalid
    /// input. A null pointer yields [HsError::FfiError].
    ///
    /// ## Safety
    ///
    /// This function accepts several C-style string pointers as parameters.
    /// Each of them must either be null or abide by the following restrictions for safe usage:
    ///
    /// - The memory pointed to by the pointer must contain a valid nul terminator at the end of the string.
    /// - The pointer must be valid for reads of bytes up to and including the nul terminator. This means in particular:
    ///     - The entire memory range of the string must be contained within a single allocated object!
    ///     - The memory must not be mutated for the duration of this call.
    /// - The nul terminator must be within `isize::MAX` from the pointer
    #[unsafe(no_mangle)]
    pub extern "C" fn generate_dpop_access_token(
        dpop_proof: *const c_char,
        user_id: *const c_char,
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
        backend_keys: *const c_char,
    ) -> *const HsResult<CString> {
        /// Borrows the bytes of a C string, without the nul terminator
        ///
        /// # Safety
        ///
        /// `ptr` must either be null or abide by the rules of [CStr::from_ptr]
        unsafe fn c_str_bytes<'a>(ptr: *const c_char) -> HsResult<&'a [u8]> {
            if ptr.is_null() {
                return Err(HsError::FfiError);
            }
            // SAFETY: `ptr` is non-null and the caller guarantees the remaining rules of `CStr::from_ptr`
            Ok(unsafe { CStr::from_ptr(ptr) }.to_bytes())
        }

        let generate = || -> HsResult<CString> {
            // SAFETY: safe if the rules in the function signature are all followed for `dpop_proof`
            let dpop = unsafe { c_str_bytes(dpop_proof) }?;
            let dpop = core::str::from_utf8(dpop).map_err(RustyJwtError::from)?;
            // SAFETY: safe if the rules in the function signature are all followed for `user_id`
            let user_id = unsafe { c_str_bytes(user_id) }?;
            let user_id = core::str::from_utf8(user_id)
                .ok()
                .and_then(|s| uuid::Uuid::from_str(s).ok())
                .ok_or(HsError::InvalidUserId)?;
            // SAFETY: safe if the rules in the function signature are all followed for `domain`
            let domain = unsafe { c_str_bytes(domain) }?;
            let client_id = ClientId::try_from_raw_parts(user_id.as_ref(), client_id, domain)?;
            // SAFETY: safe if the rules in the function signature are all followed for `handle`
            let handle = Handle::try_from(unsafe { c_str_bytes(handle) }?)?;
            let handle = handle.try_to_qualified(&client_id.domain)?;
            // SAFETY: safe if the rules in the function signature are all followed for `display_name`
            let display_name = unsafe { c_str_bytes(display_name) }?;
            let display_name = core::str::from_utf8(display_name).map_err(RustyJwtError::from)?;
            // SAFETY: safe if the rules in the function signature are all followed for `team`
            let team = Team::try_from(unsafe { c_str_bytes(team) }?)?;
            // SAFETY: safe if the rules in the function signature are all followed for `backend_nonce`
            let backend_nonce = BackendNonce::try_from_bytes(unsafe { c_str_bytes(backend_nonce) }?)?;
            // SAFETY: safe if the rules in the function signature are all followed for `uri`
            let uri = Htu::try_from(unsafe { c_str_bytes(uri) }?)?;
            // SAFETY: safe if the rules in the function signature are all followed for `method`
            let method = Htm::try_from(unsafe { c_str_bytes(method) }?)?;
            // SAFETY: safe if the rules in the function signature are all followed for `backend_keys`
            let backend_kp = Pem::try_from(unsafe { c_str_bytes(backend_keys) }?)?;
            // TODO: change in API
            let hash_algorithm = HashAlgorithm::SHA256;

            let token = RustyJwtTools::generate_access_token(
                dpop,
                &client_id,
                handle,
                display_name,
                team,
                backend_nonce,
                uri,
                method,
                max_skew_secs,
                max_expiration,
                backend_kp,
                hash_algorithm,
                ACCESS_TOKEN_API_VERSION,
                ACCESS_TOKEN_EXPIRY,
            )?;
            // a JWS compact serialization never contains a nul byte
            CString::new(token).map_err(|_| HsError::ImplementationError)
        };
        Box::into_raw(Box::new(generate()))
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_error(ptr: *const HsResult<CString>) -> u8 {
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

    /// Returns the access token as a nul-terminated C string, or null in case of an error.
    ///
    /// The returned string is owned by the [HsResult] and must not be freed by the caller.
    /// It is only valid until [Self::free_dpop_access_token] is called on `ptr`, so callers
    /// must copy it before that.
    #[unsafe(no_mangle)]
    pub extern "C" fn get_token(ptr: *const HsResult<CString>) -> *const c_char {
        // SAFETY: safe because if the pointer is null we panic before dereferencing it
        let result = unsafe {
            assert!(!ptr.is_null());
            &*ptr
        };

        match result {
            Ok(token) => token.as_ptr(),
            Err(_) => std::ptr::null(),
        }
    }

    /// Frees the allocated [HsResult] used for returning the result.
    /// This has to be called from haskell
    #[unsafe(no_mangle)]
    pub extern "C" fn free_dpop_access_token(ptr: *mut HsResult<CString>) {
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
    JsonWebTokenError = 21,
    /// Bubbling up errors
    UrlParseError = 24,
    /// Bubbling up errors
    UuidError = 25,
    /// Bubbling up errors
    Utf8Error = 26,
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
            RustyJwtError::InvalidJwk => Self::InvalidDpopSyntax,
            RustyJwtError::InvalidTokenTyp(_) => Self::InvalidDpopTyp,
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
            RustyJwtError::TokenIssuedInFuture => Self::InvalidIat,
            RustyJwtError::TokenNotYetValid => Self::NotYetValid,
            RustyJwtError::TokenLivesTooLong => Self::ExpMismatch,
            RustyJwtError::TokenExpired => Self::Expired,
            RustyJwtError::ImplementationError => Self::ImplementationError,
            RustyJwtError::JsonWebTokenError(_) => Self::JsonWebTokenError,
            RustyJwtError::UrlParseError(_) => Self::UrlParseError,
            RustyJwtError::UuidError(_) => Self::UuidError,
            RustyJwtError::Utf8Error(_) => Self::Utf8Error,
            RustyJwtError::InvalidJwkThumbprint => Self::InvalidJwkThumbprint,
            RustyJwtError::MissingTokenHeader(_) => Self::MissingDpopHeader,
            RustyJwtError::MissingTokenClaim("iss") => Self::MissingIssuer,
            RustyJwtError::ChallengeMismatch => Self::DpopChallengeMismatch,
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
