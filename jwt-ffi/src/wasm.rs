#![warn(dead_code)]

use wasm_bindgen::prelude::*;

use rusty_jwt_tools::prelude::*;

pub type WasmRustyError = JsError;
pub type WasmRustyResult<T> = Result<T, WasmRustyError>;

#[allow(non_camel_case_types)]
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WasmJwsAlgorithm {
    P256 = 0x0001,
    P384 = 0x0002,
    Ed25519 = 0x0003,
}

impl From<WasmJwsAlgorithm> for JwsAlgorithm {
    fn from(alg: WasmJwsAlgorithm) -> Self {
        match alg {
            WasmJwsAlgorithm::P256 => Self::P256,
            WasmJwsAlgorithm::P384 => Self::P384,
            WasmJwsAlgorithm::Ed25519 => Self::Ed25519,
        }
    }
}

#[allow(non_camel_case_types)]
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WasmHtm {
    Post = 0x0001,
}

impl From<WasmHtm> for Htm {
    fn from(alg: WasmHtm) -> Self {
        match alg {
            WasmHtm::Post => Self::Post,
        }
    }
}

#[derive(Debug)]
#[wasm_bindgen]
#[repr(transparent)]
pub struct RustyJwtToolsFfi;

#[wasm_bindgen]
impl RustyJwtToolsFfi {
    pub fn generate_dpop_token(
        alg: WasmJwsAlgorithm,
        kp_pem: String,
        uri: String,
        method: WasmHtm,
        acme_challenge: String,
        nonce: String,
        client_id: String,
        extra_claims: Option<JsValue>,
    ) -> WasmRustyResult<String> {
        let extra_claims = serde_wasm_bindgen::from_value::<serde_json::Value>(extra_claims)?;
        let client_id = QualifiedClientId::try_from(client_id)?;
        let dpop = Dpop {
            htu: uri.try_into()?,
            htm: method.into(),
            challenge: acme_challenge.into(),
            extra_claims: Some(extra_claims),
        };
        Ok(RustyJwtTools::generate_dpop_token(
            alg.into(),
            kp_pem.into(),
            dpop,
            nonce.into(),
            client_id,
        )?)
    }
}
