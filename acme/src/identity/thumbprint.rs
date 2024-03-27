use crate::{
    error::CertificateError,
    prelude::{RustyAcmeError, RustyAcmeResult},
};
use jwt_simple::prelude::*;
use rusty_jwt_tools::{
    jwk::TryIntoJwk,
    prelude::{HashAlgorithm, JwkThumbprint, JwsAlgorithm},
};
use x509_cert::spki::SubjectPublicKeyInfoOwned;

/// Used to compute the MLS thumbprint of a Basic Credential
pub fn compute_raw_key_thumbprint(
    sign_alg: JwsAlgorithm,
    hash_alg: HashAlgorithm,
    signature_public_key: &[u8],
) -> RustyAcmeResult<String> {
    let jwk = match sign_alg {
        JwsAlgorithm::Ed25519 => Ed25519PublicKey::from_bytes(signature_public_key)?.try_into_jwk()?,
        JwsAlgorithm::P256 => ES256PublicKey::from_bytes(signature_public_key)?.try_into_jwk()?,
        JwsAlgorithm::P384 => ES384PublicKey::from_bytes(signature_public_key)?.try_into_jwk()?,
        JwsAlgorithm::P521 => return Err(RustyAcmeError::NotSupported),
    };
    let thumbprint = JwkThumbprint::generate(&jwk, hash_alg)?;
    Ok(thumbprint.kid)
}

/// See: https://datatracker.ietf.org/doc/html/rfc8037#appendix-A.3
pub(crate) fn try_compute_jwk_canonicalized_thumbprint(
    cert: &x509_cert::TbsCertificate,
    hash_alg: HashAlgorithm,
) -> RustyAcmeResult<String> {
    let jwk = try_into_jwk(&cert.subject_public_key_info)?;
    let thumbprint = JwkThumbprint::generate(&jwk, hash_alg)?;
    Ok(thumbprint.kid)
}

fn try_into_jwk(spki: &SubjectPublicKeyInfoOwned) -> RustyAcmeResult<Jwk> {
    let oid = oid_registry::Oid::new(std::borrow::Cow::Borrowed(spki.algorithm.oid.as_bytes()));

    // cannot pattern match oid_registry::Oid because it contains a Cow<'_>
    if oid == oid_registry::OID_SIG_ED25519 {
        Ok(Ed25519PublicKey::from_bytes(spki.subject_public_key.raw_bytes())?.try_into_jwk()?)
    } else if oid == oid_registry::OID_SIG_ECDSA_WITH_SHA256 {
        Ok(ES256PublicKey::from_bytes(spki.subject_public_key.raw_bytes())?.try_into_jwk()?)
    } else if oid == oid_registry::OID_SIG_ECDSA_WITH_SHA384 {
        Ok(ES384PublicKey::from_bytes(spki.subject_public_key.raw_bytes())?.try_into_jwk()?)
    } else {
        Err(RustyAcmeError::InvalidCertificate(CertificateError::InvalidPublicKey))
    }
}
