use certval::buffer_to_hex;
use certval::name_to_string;
use certval::PDVCertificate;
use certval::PathValidationStatus;
use certval::RevocationStatusCache;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

#[derive(Clone, Copy)]
struct StatusAndTime {
    status: PathValidationStatus, // Valid or Revoked
    time: u64,
}

type CacheMap = BTreeMap<(String, String), StatusAndTime>;

#[derive(Default)]
pub struct RevocationCache {
    cache_map: Arc<Mutex<CacheMap>>,
}

impl RevocationStatusCache for RevocationCache {
    fn get_status(&self, cert: &PDVCertificate, time_of_interest: u64) -> PathValidationStatus {
        let name = name_to_string(&cert.decoded_cert.tbs_certificate.issuer);
        let serial = buffer_to_hex(cert.decoded_cert.tbs_certificate.serial_number.as_bytes());

        let Ok(cache_map) = self.cache_map.lock() else {
            return PathValidationStatus::RevocationStatusNotDetermined;
        };

        if let Some(status_and_time) = cache_map.get(&(name, serial)) {
            if status_and_time.time > time_of_interest {
                return status_and_time.status;
            }
        }

        PathValidationStatus::RevocationStatusNotDetermined
    }

    fn add_status(&self, cert: &PDVCertificate, next_update: u64, status: PathValidationStatus) {
        if status != PathValidationStatus::Valid && status != PathValidationStatus::CertificateRevoked {
            return;
        }

        let name = name_to_string(&cert.decoded_cert.tbs_certificate.issuer);
        let serial = buffer_to_hex(cert.decoded_cert.tbs_certificate.serial_number.as_bytes());

        let Ok(mut cache_map) = self.cache_map.lock() else {
            return;
        };

        let status_and_time = StatusAndTime {
            status,
            time: next_update,
        };

        cache_map
            .entry((name, serial))
            .and_modify(|old_status_and_time| {
                if old_status_and_time.time < next_update {
                    *old_status_and_time = status_and_time;
                }
            })
            .or_insert_with(|| status_and_time);
    }
}
