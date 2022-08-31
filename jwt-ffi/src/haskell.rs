use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use rusty_jwt_tools::RustyJwtTools;

struct RustyJwtToolsFfi;

impl RustyJwtToolsFfi {
    #[no_mangle]
    pub extern "C" fn generate_dpop_access_token(
        dpop_proof: *const c_char,
        user: *const c_char,
        client: u16,
        domain: *const c_char,
        backend_nonce: *const c_char,
        uri: *const c_char,
        method: *const c_char,
        max_skew_secs: u16,
        expiration: u64,
        now: u64,
        backend_keys: *const c_char,
    ) -> *mut c_char {
        let dpop_proof = unsafe { CStr::from_ptr(dpop_proof).to_bytes() };
        let user = unsafe { CStr::from_ptr(user).to_bytes() };
        let domain = unsafe { CStr::from_ptr(domain).to_bytes() };
        let backend_nonce = unsafe { CStr::from_ptr(backend_nonce).to_bytes() };
        let uri = unsafe { CStr::from_ptr(uri).to_bytes() };
        let method = unsafe { CStr::from_ptr(method).to_bytes() };
        let backend_keys = unsafe { CStr::from_ptr(backend_keys).to_bytes() };

        let token = RustyJwtTools::generate_dpop_access_token(
            dpop_proof,
            user,
            client,
            domain,
            backend_nonce,
            uri,
            method,
            max_skew_secs,
            expiration,
            now,
            backend_keys,
        ).unwrap();
        CString::new(token).unwrap().into_raw()
    }

    #[no_mangle]
    pub extern "C" fn free_dpop_access_token(ptr: *mut c_char) {
        unsafe {
            if ptr.is_null() {
                return;
            }
            CString::from_raw(ptr)
        };
    }
}
