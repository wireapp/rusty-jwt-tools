use jsonwebtoken::{Algorithm, EncodingKey, Header};

use crate::{dpop::Dpop, error::RustyJwtResult};

use super::RustyJwtTools;

impl RustyJwtTools {
    /// Validate the provided [dpop_proof] DPoP proof JWT from the client, and if valid, return an
    /// introspectable DPoP access token.
    ///
    /// Verifications:
    /// * [dpop_proof] has the correct syntax
    /// * (typ) header field is "dpop+jwt"
    /// * signature algorithm (alg) in JWT header is a supported algorithm
    /// * signature corresponds to the public key (jwk) in the JWT header
    /// * qualified_client_id corresponds to the (sub) claim expressed as URI:
    /// * backend_nonce corresponds to the (nonce) claim encoded as base64url.
    /// * uri corresponds to the (htu) claim.
    /// * method corresponds to the (htm) claim.
    /// * (jti) claim is present
    /// * (chal) claim is present
    /// * (iat) claim is present and no earlier or later than max_skew_secs seconds   of now
    /// * (exp) claim is present and no larger (later) than max_expiration.
    /// * (exp) claim is no later than now plus max_skew_secs.
    ///
    /// # Arguments
    /// * `dpop_proof` - JWS Compact Serialization format Note that the proof consists of three runs
    /// of base64url characters (header, claims, signature) separated by period characters.
    /// ex: b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" (whitespace in the example is not included in the actual proof)
    /// * `user` - user ID UUID-4 in ASCII string representation
    /// * `client` - client number assigned by the backend
    /// * `domain` - backend domain of the client
    /// * `backend_nonce` - The most recent DPoP nonce provided by the backend to the current client ex: hex!("b62551e728771515234fac0b04b2008d")
    /// * `uri` - The HTTPS URI on the backend for the DPoP auth token endpoint ex: "https://wire.example.com/clients/authtoken"
    /// * `method` - The HTTPS method used on the backend for the DPoP auth token endpoint ex: b"POST"
    /// * `max_skew_secs` - The maximum number of seconds of clock skew the implementation will allow ex: 360 (5 min)
    /// * `expiration` - The expiration date and time, in seconds since epoch ex: 1668987368
    /// * `now` - Current time in seconds since epoch ex: 1661211368
    /// * `backend_keys` - PEM format concatenated private key and public key of the Wire backend
    pub fn generate_dpop_access_token<'a>(
        _dpop_proof: &'a [u8],
        _user: &'a [u8],
        _client: u16,
        _domain: &'a [u8],
        _backend_nonce: &'a [u8],
        _uri: &'a [u8],
        _method: &'a [u8],
        _max_skew_secs: u16,
        _expiration: u64,
        _now: u64,
        _backend_keys: &'a [u8],
    ) -> RustyJwtResult<String> {
        /*let headers = Self::create_header(alg);
        Ok(jsonwebtoken::encode(&headers, &dpop, &signature_key)?)*/
        Ok(super::SAMPLE_TOKEN.to_string())
    }

    fn create_header(alg: Algorithm) -> Header {
        let mut header = Header::new(alg);
        header.typ = None;
        header
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::Validation;
    use wasm_bindgen_test::*;

    use crate::{dpop::Dpop, test_utils::*};

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    mod headers {
        use super::*;

        #[test]
        fn sample() {
            let keys: JwtKeys = ed_keys();
            // let token = RustyJwtTools::generate_dpop_access_token(keys.alg, &Dpop::default(), &keys.encoding, 0).unwrap();
        }

        /*#[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_dpop_typ(keys: JwtKeys) {
            let token =
                RustyJwtTools::generate_dpop_access_token(keys.alg, &Dpop::default(), &keys.encoding, 0).unwrap();
            let jwt = jsonwebtoken::decode::<Dpop>(&token, &keys.decoding, &Validation::default()).unwrap();
            assert_eq!(jwt.header.typ, Some("dpop+jwt".to_string()));
        }

        #[apply(all_keys)]
        #[wasm_bindgen_test]
        fn should_have_alg(keys: JwtKeys) {
            let token =
                RustyJwtTools::generate_dpop_access_token(keys.alg, &Dpop::default(), &keys.encoding, 0).unwrap();
            let jwt = jsonwebtoken::decode::<Dpop>(&token, &keys.decoding, &Validation::default()).unwrap();
            assert_eq!(jwt.header.alg, keys.alg);
        }*/
    }
}
