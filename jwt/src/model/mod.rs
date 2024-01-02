use lazy_static::lazy_static;

pub mod alg;
pub mod client_id;
pub mod handle;
pub mod nonce;
pub mod pem;
pub mod pk;
pub mod team;

// Only way to have something resembling a url builder
lazy_static! {
    static ref DEFAULT_URL: url::Url = const_format::concatcp!(client_id::ClientId::URI_SCHEME, "example.com")
        .parse()
        .unwrap();
}
