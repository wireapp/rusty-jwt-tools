use lazy_static::lazy_static;

pub(crate) mod alg;
pub(crate) mod client_id;
pub(crate) mod handle;
pub(crate) mod nonce;
pub(crate) mod pem;
pub(crate) mod pk;
pub(crate) mod team;

// Only way to have something resembling a url builder
lazy_static! {
    static ref DEFAULT_URL: url::Url = const_format::concatcp!(client_id::ClientId::URI_SCHEME, "example.com")
        .parse()
        .unwrap();
}
