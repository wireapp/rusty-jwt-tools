use std::sync::LazyLock;

pub(crate) mod alg;
pub(crate) mod client_id;
pub(crate) mod handle;
pub(crate) mod nonce;
pub(crate) mod pem;
pub(crate) mod pk;
pub(crate) mod team;

// Only way to have something resembling a url builder
static DEFAULT_URL: LazyLock<url::Url> = LazyLock::new(|| {
    const_format::concatcp!(client_id::ClientId::URI_SCHEME, "example.com")
        .parse()
        .unwrap()
});
