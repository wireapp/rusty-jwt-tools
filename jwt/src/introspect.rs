use chrono::{TimeZone, Utc};
use jwt_simple::prelude::*;
use oauth2::{basic::BasicTokenType, ExtraTokenFields};

use crate::{access::Access as RustyAccess, jwt::verify::jwt_error_mapping, prelude::*};

pub type IntrospectResponse = oauth2::StandardTokenIntrospectionResponse<RustyAccess, BasicTokenType>;

/// Handles all things related to token introspection
///
/// Specified in [RFC 7662: OAuth 2.0 Token Introspection][1]
///
/// [1]: https://www.rfc-editor.org/rfc/rfc7662.html
pub struct RustyIntrospect;

impl ExtraTokenFields for RustyAccess {}

impl RustyIntrospect {
    pub fn introspect_response(
        access_token: &str,
        pk: AnyPublicKey,
        leeway: u16,
    ) -> RustyJwtResult<IntrospectResponse> {
        let verifications = Some(VerificationOptions {
            time_tolerance: Some(UnixTimeStamp::from_secs(leeway as u64)),
            ..Default::default()
        });
        let claims = pk
            .verify_token::<RustyAccess>(access_token, verifications)
            .map_err(jwt_error_mapping)?;
        let active = true;
        let mut response = IntrospectResponse::new(active, claims.custom);
        response.set_jti(claims.jwt_id);
        response.set_sub(claims.subject);
        response.set_token_type(Some(BasicTokenType::Bearer));
        response.set_exp(claims.expires_at.map(Self::to_chrono_dt).transpose()?);
        response.set_iat(claims.issued_at.map(Self::to_chrono_dt).transpose()?);
        Ok(response)
    }

    fn to_chrono_dt(timestamp: UnixTimeStamp) -> RustyJwtResult<chrono::DateTime<Utc>> {
        let secs = i64::try_from(timestamp.as_secs())?;
        Ok(Utc.timestamp(secs, 0))
    }
}

#[cfg(test)]
mod tests {

    use crate::test_utils::*;

    use super::*;

    #[test]
    fn should_have_valid_response() {
        let hash = HashAlgorithm::SHA256;
        let key = JwtKey::new_key(JwsAlgorithm::P256);
        let challenge = AcmeChallenge::rand();
        let dpop = Dpop {
            challenge,
            ..Default::default()
        };
        let nonce = BackendNonce::rand();
        let client_id = QualifiedClientId::alice();
        let htu = Htu::default();
        let htm = Htm::default();
        let backend_keys = key.create_another();

        let dpop = RustyJwtTools::generate_dpop_token(key.alg, key.kp, dpop, nonce.clone(), client_id).unwrap();

        let access_token = RustyJwtTools::generate_access_token(
            &dpop,
            client_id,
            nonce,
            htu,
            htm,
            5,
            2136351646,
            backend_keys.kp,
            hash,
        )
        .unwrap();

        let pk = AnyPublicKey::from((backend_keys.alg, &backend_keys.pk));
        let claims = pk.verify_token::<RustyAccess>(&access_token, None).unwrap();

        let response = RustyIntrospect::introspect_response(&access_token, pk, 5).unwrap();

        use oauth2::TokenIntrospectionResponse as _;
        assert!(response.active());
        assert!(response.scopes().is_none());
        assert!(response.client_id().is_none());
        assert!(response.username().is_none());

        assert_eq!(response.token_type(), Some(&BasicTokenType::Bearer));

        let exp = claims.expires_at.unwrap().as_secs() as i64;
        let exp_range = (exp - 1)..(exp + 1);
        assert!(exp_range.contains(&response.exp().unwrap().timestamp()));

        let iat = claims.issued_at.unwrap().as_secs() as i64;
        let iat_range = (iat - 1)..(iat + 1);
        assert!(iat_range.contains(&response.iat().unwrap().timestamp()));

        assert!(response.nbf().is_none());
        assert_eq!(response.sub(), claims.subject.as_deref());
        assert!(response.aud().is_none());
        assert!(response.iss().is_none());
        assert_eq!(response.jti(), claims.jwt_id.as_deref());
    }
}
