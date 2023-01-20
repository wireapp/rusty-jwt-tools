#![cfg(not(target_family = "wasm"))]

pub mod dex;
pub mod wiremock;

use jwt_simple::reexports::rand;
use reqwest::Client;
use std::{collections::HashMap, path::PathBuf};
use testcontainers::{clients::Cli, core::WaitFor, Container, Image, RunnableImage};

pub const NETWORK: &str = "wire";

#[derive(Debug, Clone)]
pub struct StepCaConfig {
    pub sign_key: String,
    pub issuer: String,
    pub audience: String,
    pub jwks_uri: String,
}

impl StepCaConfig {
    fn cfg(self) -> serde_json::Value {
        // see https://github.com/wireapp/smallstep-certificates/blob/b6019aeb7ffaae1c978c87760656980162e9b785/helm/values.yaml#L88-L100
        let provisioner = StepCaImage::ACME_PROVISIONER;
        let Self {
            sign_key,
            issuer,
            audience,
            jwks_uri,
        } = self;
        serde_json::json!({
            "provisioners": [
                {
                    "type": "ACME",
                    "name": provisioner,
                    "forceCN": true,
                    "claims": {
                        "disableRenewal": false,
                        "allowRenewalAfterExpiry": false
                    },
                    "options": {
                        "oidc": {
                            "provider": {
                                "issuer": issuer,
                                "authorization_endpoint": "https://authorization_endpoint.com",
                                "token_endpoint": "https://token_endpoint.com",
                                "jwks_uri": jwks_uri,
                                "userinfo_endpoint": "https://userinfo_endpoint.com",
                                "id_token_signing_alg_values_supported": [
                                    "ES256",
                                    "ES384",
                                    "EdDSA"
                                ]
                            },
                            "config": {
                                "client-id": audience,
                                "support-signing-algs": [
                                    "ES256",
                                    "ES384",
                                    "EdDSA"
                                ]
                            }
                        },
                        "dpop": {
                            "key": sign_key,
                            "validation-exec-path": "/usr/local/bin/rusty-jwt-cli"
                        }
                    }
                }
            ]
        })
    }
}

#[derive(Debug)]
pub struct StepCaImage {
    pub is_builder: bool,
    pub volumes: HashMap<String, String>,
    pub env_vars: HashMap<String, String>,
    pub host_volume: PathBuf,
}

impl StepCaImage {
    const NAME: &'static str = "quay.io/wire/smallstep-acme";
    const TAG: &'static str = "0.0.42-test.35";

    const CA_NAME: &'static str = "wire";
    pub const ACME_PROVISIONER: &'static str = "acme";
    pub const ACME_ADMIN: &'static str = "admin";
    pub const PORT: u16 = 9000;

    pub fn run(docker: &Cli, stepca_cfg: StepCaConfig) -> (u16, Client, Container<StepCaImage>) {
        // We have to create an ACME provisioner at startup which is done in `exec_after_start`.
        // Since step-ca does not support hot reload of the configuration and we cannot
        // restart the process within the container with testcontainers cli, we will start a first
        // container, do the initialization step, copy the generated configuration then use it to
        // start a second, final one
        let builder = Self::new(true, None);
        let host_volume = builder.host_volume.clone();

        let builder_image: RunnableImage<Self> = builder.into();
        let builder_container = docker.run(builder_image);
        // now the configuration should have been generated and mapped to our host volume.
        // We can kill this container
        drop(builder_container);

        let image: RunnableImage<Self> = Self::new(false, Some(host_volume.clone())).into();

        // Alter the configuration by adding an ACME provisioner manually, waaaaay simpler than using the cli
        let cfg_file = host_volume.join("config").join("ca.json");
        let cfg_content = std::fs::read_to_string(&cfg_file).unwrap();
        let mut cfg = serde_json::from_str::<serde_json::Value>(&cfg_content).unwrap();
        cfg.as_object_mut()
            .unwrap()
            .insert("authority".to_string(), stepca_cfg.cfg());
        std::fs::write(&cfg_file, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();

        let image = image.with_network(NETWORK);
        let node = docker.run(image);
        let port = node.get_host_port_ipv4(Self::PORT);
        let step_client = Self::reqwest_client(host_volume);
        (port, step_client, node)
    }

    pub fn reqwest_client(host_volume: PathBuf) -> Client {
        // we need to call step-ca over https
        // so we need to add its self-signed CA to our reqwest client truststore
        let ca_cert = host_volume.join("certs").join("root_ca.crt");

        // required in Github action rootless container
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&ca_cert, std::fs::Permissions::from_mode(0o777)).unwrap();

        let ca_pem = std::fs::read(ca_cert).unwrap();
        let ca_cert =
            reqwest::tls::Certificate::from_pem(ca_pem.as_slice()).expect("SmallStep issued an invalid certificate");
        reqwest::ClientBuilder::new()
            .add_root_certificate(ca_cert)
            .build()
            .unwrap()
    }
}

impl StepCaImage {
    fn new(is_builder: bool, host_volume: Option<PathBuf>) -> Self {
        let host_volume = host_volume.unwrap_or_else(|| std::env::temp_dir().join(rand_str()));
        if !host_volume.exists() {
            std::fs::create_dir(&host_volume).unwrap();
        }

        // required in Github action rootless container
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&host_volume, std::fs::Permissions::from_mode(0o777)).unwrap();

        let host_volume_str = host_volume.as_os_str().to_str().unwrap();
        Self {
            is_builder,
            volumes: HashMap::from_iter(vec![(host_volume_str.to_string(), "/home/step".to_string())]),
            env_vars: HashMap::from_iter(
                vec![
                    ("DOCKER_STEPCA_INIT_PROVISIONER_NAME", Self::CA_NAME),
                    ("DOCKER_STEPCA_INIT_NAME", Self::CA_NAME),
                    ("DOCKER_STEPCA_INIT_DNS_NAMES", "localhost,$(hostname -f)"),
                    ("DOCKER_STEPCA_INIT_ACME", "true"),
                    ("DOCKER_STEPCA_INIT_REMOTE_MANAGEMENT", "true"),
                ]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string())),
            ),
            host_volume,
        }
    }
}

impl Image for StepCaImage {
    type Args = ();

    fn name(&self) -> String {
        Self::NAME.to_string()
    }

    fn tag(&self) -> String {
        Self::TAG.to_string()
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        vec![WaitFor::message_on_stderr("Serving HTTPS on :")]
    }

    fn env_vars(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_> {
        Box::new(self.env_vars.iter())
    }

    fn volumes(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_> {
        Box::new(self.volumes.iter())
    }

    fn expose_ports(&self) -> Vec<u16> {
        vec![Self::PORT]
    }
}

fn rand_str() -> String {
    use rand::distributions::{Alphanumeric, DistString};
    Alphanumeric.sample_string(&mut rand::thread_rng(), 12)
}
