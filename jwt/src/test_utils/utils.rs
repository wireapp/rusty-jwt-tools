use jwt_simple::prelude::*;

pub fn now() -> UnixTimeStamp {
    use fluvio_wasm_timer::{SystemTime, UNIX_EPOCH};
    let now = UnixTimeStamp::from_secs(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
    now - Duration::from_secs(5)
}

pub fn rand_str(size: usize) -> String {
    use rand::distributions::{Alphanumeric, DistString};
    let challenge: String = Alphanumeric.sample_string(&mut rand::thread_rng(), size);
    base64::encode_config(challenge, base64::URL_SAFE_NO_PAD)
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
    let claims = base64::decode(claims).unwrap();
    let claims = serde_json::from_slice::<serde_json::Value>(claims.as_slice()).unwrap();
    claims.as_object().unwrap().to_owned()
}
