#![allow(dead_code)]

use certval::{
    check_revocation, get_validation_status, populate_5280_pki_environment, set_forbid_self_signed_ee,
    set_require_ta_store, set_time_of_interest, validate_path_rfc5280,
    validator::{path_validator::check_validity, PDVCertificate},
    verify_signatures, CertSource, CertVector, CertificationPathResults, CertificationPathSettings,
    ExtensionProcessing, TaSource, EXTS_OF_INTEREST,
};

use x509_cert::der::{Decode, DecodePem, Encode};
use x509_cert::ext::pkix::AuthorityKeyIdentifier;

use crate::{revocation::cache::RevocationCache, RustyX509CheckError, RustyX509CheckResult};
use crl_store::CrlStore;

mod cache;
mod crl_info;
mod crl_store;
mod misc;

#[derive(Default)]
pub struct PkiEnvironmentParams<'a> {
    /// Intermediate CAs and cross-signed CAs
    pub intermediates: &'a [x509_cert::Certificate],
    /// Trust Anchor roots
    pub trust_roots: &'a [x509_cert::anchor::TrustAnchorChoice],
    /// CRLs to add to the revocation check
    pub crls: &'a [x509_cert::crl::CertificateList],
    /// Time of interest for CRL verfication. If not provided, will default to current UNIX epoch
    pub time_of_interest: Option<u64>,
}

pub struct PkiEnvironment {
    pe: certval::environment::PkiEnvironment,
    toi: u64,
}

impl std::ops::Deref for PkiEnvironment {
    type Target = certval::environment::PkiEnvironment;

    fn deref(&self) -> &Self::Target {
        &self.pe
    }
}

impl std::ops::DerefMut for PkiEnvironment {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.pe
    }
}

impl std::fmt::Debug for PkiEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkiEnvironment")
            .field("pe", &"[OPAQUE]")
            .field("toi", &self.toi)
            .finish()
    }
}

// TODO: extract CRL URI from cert

fn check_cpr(cpr: CertificationPathResults) -> RustyX509CheckResult<()> {
    if let Some(validation_status) = get_validation_status(&cpr) {
        match validation_status {
            certval::PathValidationStatus::Valid => Ok(()),
            // No CRL is available, this is fine
            certval::PathValidationStatus::RevocationStatusNotDetermined
            | certval::PathValidationStatus::RevocationStatusNotAvailable => Ok(()),
            validation_status => Err(RustyX509CheckError::CertValError(certval::Error::PathValidation(
                validation_status,
            ))),
        }
    } else {
        Err(RustyX509CheckError::CannotDetermineVerificationStatus)
    }
}

impl PkiEnvironment {
    pub fn decode_pem_cert(pem: String) -> RustyX509CheckResult<x509_cert::Certificate> {
        Ok(x509_cert::Certificate::from_pem(pem)?)
    }

    pub fn decode_der_crl(crl_der: Vec<u8>) -> RustyX509CheckResult<x509_cert::crl::CertificateList> {
        Ok(x509_cert::crl::CertificateList::from_der(&crl_der)?)
    }

    pub fn extract_ski_aki_from_cert(cert: &x509_cert::Certificate) -> RustyX509CheckResult<(String, Option<String>)> {
        let cert = PDVCertificate::try_from(cert.clone())?;

        let ski = cert
            .get_extension(&const_oid::db::rfc5912::ID_CE_SUBJECT_KEY_IDENTIFIER)?
            .ok_or(RustyX509CheckError::MissingSki)?;
        let ski = match ski {
            certval::PDVExtension::SubjectKeyIdentifier(ski) => hex::encode(ski.0.as_bytes()),
            _ => return Err(RustyX509CheckError::ImplementationError),
        };

        let aki = cert
            .get_extension(&const_oid::db::rfc5912::ID_CE_AUTHORITY_KEY_IDENTIFIER)?
            .and_then(|ext| match ext {
                certval::PDVExtension::AuthorityKeyIdentifier(AuthorityKeyIdentifier { key_identifier, .. }) => {
                    key_identifier.as_ref()
                }
                _ => None,
            })
            .map(|ki| hex::encode(ki.as_bytes()));

        Ok((ski, aki))
    }

    pub fn encode_cert_to_der(cert: &x509_cert::Certificate) -> RustyX509CheckResult<Vec<u8>> {
        Ok(cert.to_der()?)
    }

    pub fn encode_crl_to_der(crl: &x509_cert::crl::CertificateList) -> RustyX509CheckResult<Vec<u8>> {
        Ok(crl.to_der()?)
    }

    /// Initializes a certval PkiEnvironment using the provided params
    pub fn init(params: PkiEnvironmentParams) -> RustyX509CheckResult<PkiEnvironment> {
        let toi = if let Some(toi) = params.time_of_interest {
            toi
        } else {
            fluvio_wasm_timer::SystemTime::now()
                .duration_since(fluvio_wasm_timer::SystemTime::UNIX_EPOCH)
                .map_err(|_| RustyX509CheckError::CannotDetermineCurrentTime)?
                .as_secs()
        };

        let mut cps = CertificationPathSettings::new();
        set_time_of_interest(&mut cps, toi);

        // Make a Certificate source for intermediate CA certs
        let mut cert_source = CertSource::new();
        for (i, cert) in params.intermediates.iter().enumerate() {
            cert_source.push(certval::CertFile {
                filename: format!("Intermediate CA #{i} [{}]", cert.tbs_certificate.subject),
                bytes: cert.to_der()?,
            });
        }

        cert_source.initialize(&cps)?;

        // Make a TrustAnchor source
        let mut trust_anchors = TaSource::new();
        for (i, root) in params.trust_roots.iter().enumerate() {
            trust_anchors.push(certval::CertFile {
                filename: format!("TrustAnchor #{i}"),
                bytes: root.to_der()?,
            });
        }

        trust_anchors.initialize()?;

        let revocation_cache = RevocationCache::default();

        // Make a CRL source
        let crl_source = CrlStore::from(params.crls);
        crl_source.index_crls(toi)?;

        let mut pe = certval::environment::PkiEnvironment::default();
        populate_5280_pki_environment(&mut pe);
        pe.add_trust_anchor_source(Box::new(trust_anchors));
        pe.add_crl_source(Box::new(crl_source));
        pe.add_revocation_cache(Box::new(revocation_cache));

        cert_source.find_all_partial_paths(&pe, &cps);

        pe.add_certificate_source(Box::new(cert_source));

        Ok(Self { pe, toi })
    }

    /// Overrides TIME_OF_INTEREST for certificate verifications based on a moment in the past or future
    pub fn set_time_of_interest(&mut self, toi: u64) {
        self.toi = toi;
    }

    /// Updates the TIME_OF_INTEREST for certificate checks to be `now`
    pub fn refresh_time_of_interest(&mut self) -> RustyX509CheckResult<()> {
        self.set_time_of_interest(
            fluvio_wasm_timer::SystemTime::now()
                .duration_since(fluvio_wasm_timer::SystemTime::UNIX_EPOCH)
                .map_err(|_| RustyX509CheckError::CannotDetermineCurrentTime)?
                .as_secs(),
        );

        Ok(())
    }

    pub fn validate_trust_anchor_cert(&self, cert: &x509_cert::Certificate) -> RustyX509CheckResult<()> {
        let mut cps = CertificationPathSettings::default();
        set_time_of_interest(&mut cps, self.toi);

        let mut cert = PDVCertificate::try_from(cert.clone())?;
        cert.parse_extensions(EXTS_OF_INTEREST);
        let mut paths = vec![];
        self.pe.get_paths_for_target(&self.pe, &cert, &mut paths, 0, self.toi)?;

        // if paths.is_empty() {
        //     return Err(RustyX509CheckError::CertValError(certval::Error::PathValidation(
        //         certval::PathValidationStatus::NoPathsFound,
        //     )));
        // }

        for path in &mut paths {
            let mut cpr = CertificationPathResults::new();
            let _ = check_validity(&self.pe, &cps, path, &mut cpr);
            check_cpr(cpr)?;
            let mut cpr = CertificationPathResults::new();
            let _ = verify_signatures(&self.pe, &cps, path, &mut cpr);
            check_cpr(cpr)?;
        }

        Ok(())
    }

    pub fn validate_crl(&self, crl: &x509_cert::crl::CertificateList) -> RustyX509CheckResult<()> {
        let spki_list = if let Ok(ta) = self.pe.get_trust_anchor_by_name(&crl.tbs_cert_list.issuer) {
            vec![certval::source::ta_source::get_subject_public_key_info_from_trust_anchor(&ta.decoded_ta)]
        } else {
            self.pe
                .get_cert_by_name(&crl.tbs_cert_list.issuer)
                .into_iter()
                .map(|c| &c.decoded_cert.tbs_certificate.subject_public_key_info)
                .collect()
        };

        for spki in spki_list {
            if self
                .pe
                .verify_signature_message(
                    &self.pe,
                    &crl.tbs_cert_list.to_der()?,
                    crl.signature.raw_bytes(),
                    &crl.signature_algorithm,
                    spki,
                )
                .is_ok()
            {
                return Ok(());
            }
        }

        Err(RustyX509CheckError::CertValError(certval::Error::Unrecognized))
    }

    fn validate_cert_internal(
        &self,
        end_identity_cert: &x509_cert::Certificate,
        perform_revocation_check: bool,
    ) -> RustyX509CheckResult<()> {
        let mut cps = CertificationPathSettings::default();
        set_time_of_interest(&mut cps, self.toi);
        set_require_ta_store(&mut cps, true);
        set_forbid_self_signed_ee(&mut cps, true);

        let mut end_identity_cert = PDVCertificate::try_from(end_identity_cert.clone())?;
        end_identity_cert.parse_extensions(EXTS_OF_INTEREST);

        let mut paths = vec![];
        self.pe
            .get_paths_for_target(&self.pe, &end_identity_cert, &mut paths, 0, self.toi)?;

        if paths.is_empty() {
            return Err(RustyX509CheckError::CertValError(certval::Error::PathValidation(
                certval::PathValidationStatus::NoPathsFound,
            )));
        }

        for path in &mut paths {
            let mut cpr = CertificationPathResults::new();
            let _ = validate_path_rfc5280(&self.pe, &cps, path, &mut cpr);
            check_cpr(cpr)?;
            if perform_revocation_check {
                let mut cpr = CertificationPathResults::new();
                let _ = check_revocation(&self.pe, &cps, path, &mut cpr);
                check_cpr(cpr)?;
            }
        }

        Ok(())
    }

    #[inline]
    pub fn validate_cert(&self, end_identity_cert: &x509_cert::Certificate) -> RustyX509CheckResult<()> {
        self.validate_cert_internal(end_identity_cert, false)
    }

    #[inline]
    pub fn validate_cert_and_revocation(&self, end_identity_cert: &x509_cert::Certificate) -> RustyX509CheckResult<()> {
        self.validate_cert_internal(end_identity_cert, true)
    }
}
