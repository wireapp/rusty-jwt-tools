use base64::Engine;
use rand::distr::{Alphanumeric, SampleString as _};
use jwt_simple::prelude::*;

pub fn now() -> UnixTimeStamp {
    use web_time::{SystemTime, UNIX_EPOCH};
    let now = UnixTimeStamp::from_secs(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
    now - Duration::from_secs(5)
}

pub fn rand_base64_str(size: usize) -> String {
    let challenge: String = Alphanumeric.sample_string(&mut rand::rng(), size);
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(challenge)
}

pub fn jwt_header(token: String) -> serde_json::Map<String, serde_json::Value> {
    jwt_part(token, 0)
}

pub fn jwt_claims(token: String) -> serde_json::Map<String, serde_json::Value> {
    jwt_part(token, 1)
}

fn jwt_part(token: String, part: usize) -> serde_json::Map<String, serde_json::Value> {
    let parts = token.split('.').collect::<Vec<&str>>();
    let claims = parts.get(part).unwrap();
    let claims = base64::prelude::BASE64_STANDARD_NO_PAD.decode(claims).unwrap();
    let claims = serde_json::from_slice::<serde_json::Value>(claims.as_slice()).unwrap();
    claims.as_object().unwrap().to_owned()
}
