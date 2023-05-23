use base64::Engine;
use hyper::{Body, Method, Request, Response, StatusCode};

use rusty_jwt_tools::prelude::*;

use crate::utils::wire_server::oidc::handle_callback_google;
use crate::utils::{
    ctx::ctx_get,
    rand_base64_str,
    wire_server::oidc::{handle_callback, handle_login},
};

// simulates wire-server database
static mut PREVIOUS_NONCE: &str = "";

pub async fn wire_api(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let path = req.uri().path();
    let paths = path.split('/').filter(|p| !p.is_empty()).collect::<Vec<&str>>();
    let header = |k: &str| {
        req.headers()
            .get(k)
            .and_then(|d| d.to_str().ok())
            .and_then(|v| base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(v).ok())
            .and_then(|v| String::from_utf8(v).ok())
            .unwrap_or_else(|| panic!("No header '{k}'"))
    };
    Ok(match (req.method(), paths.as_slice()) {
        (&Method::GET, ["clients", "token", "nonce"]) => {
            let nonce = rand_base64_str(32);
            let previous_nonce = Box::leak(Box::new(nonce.clone()));
            unsafe {
                PREVIOUS_NONCE = previous_nonce;
            }
            Response::builder().status(StatusCode::OK).body(nonce.into()).unwrap()
        }
        (&Method::POST, ["clients", device_id, "access-token"]) => {
            let dpop = header("dpop");
            // fetch back the nonce we have generated at previous state
            let backend_nonce: BackendNonce = unsafe { PREVIOUS_NONCE.into() };

            let client_id = ctx_get("client-id").unwrap();
            let client_id = ClientId::try_from_uri(&client_id).unwrap();

            // verify this tests has a valid API handler expecting the right deviceId encoding
            let received_device_id = u64::from_str_radix(device_id, 16).unwrap();
            assert_eq!(received_device_id, client_id.device_id);

            let body = generate_access_token(&dpop, client_id, backend_nonce);
            let body = serde_json::to_vec(&body).unwrap().into();
            Response::builder().status(StatusCode::OK).body(body).unwrap()
        }
        (&Method::GET, ["login"]) => handle_login(req).await?,
        (&Method::GET, ["callback"]) => handle_callback(req).await?,
        (&Method::GET, ["callback-google"]) => handle_callback_google(req).await?,
        _ => not_found(),
    })
}

fn generate_access_token(dpop: &str, client_id: ClientId, nonce: BackendNonce) -> serde_json::Value {
    let backend_kp: Pem = ctx_get("backend-kp").unwrap().into();
    let hash_alg: HashAlgorithm = ctx_get("hash-alg").unwrap().parse().unwrap();
    let htu: Htu = ctx_get("wire-server-uri").unwrap().as_str().try_into().unwrap();

    let leeway = 2;
    let max_expiry = 2082008461;
    let access_token = RustyJwtTools::generate_access_token(
        dpop,
        &client_id,
        nonce,
        htu,
        Htm::Post,
        leeway,
        max_expiry,
        backend_kp,
        hash_alg,
    )
    .unwrap();
    serde_json::json!({
        "expires_in": 2082008461,
        "token": access_token,
        "type": "DPoP"
    })
}

fn not_found() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body("".into())
        .unwrap()
}
