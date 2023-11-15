use super::IdentityStatus;

pub(crate) fn extract_status(cert: &x509_cert::TbsCertificate) -> IdentityStatus {
    if is_revoked(cert) {
        IdentityStatus::Revoked
    } else if !is_time_valid(cert) {
        IdentityStatus::Expired
    } else {
        IdentityStatus::Valid
    }
}

fn is_time_valid(cert: &x509_cert::TbsCertificate) -> bool {
    // 'not_before' < now < 'not_after'
    let x509_cert::time::Validity { not_before, not_after } = cert.validity;

    let now = fluvio_wasm_timer::SystemTime::now();
    let Ok(now) = now.duration_since(fluvio_wasm_timer::UNIX_EPOCH) else {
        return false;
    };

    let is_nbf = now >= not_before.to_unix_duration();
    let is_naf = now < not_after.to_unix_duration();
    is_nbf && is_naf
}

// TODO
fn is_revoked(_cert: &x509_cert::TbsCertificate) -> bool {
    false
}
