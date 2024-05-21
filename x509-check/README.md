# x509-check

Wrapper on top of [rust-pki](https://github.com/carl-wallace/rust-pki). It lives in a separate crate because it might
change for unrelated reasons. It mostly deals with X509 certificates validation (signature, expiry, extensions etc..)
and
revocation with CRLs.
