#![cfg(not(target_family = "wasm"))]

use jwt_simple::reexports::rand;
use reqwest::Client;
use std::{collections::HashMap, path::PathBuf};
use testcontainers::{
    clients::Cli,
    core::{ContainerState, ExecCommand, WaitFor},
    Container, Image, ImageArgs, RunnableImage,
};

pub const NETWORK: &str = "wire";

#[derive(Debug)]
pub struct StepCaImage {
    pub is_builder: bool,
    pub volumes: HashMap<String, String>,
    pub env_vars: HashMap<String, String>,
    pub host_volume: PathBuf,
}

impl StepCaImage {
    const NAME: &'static str = "smallstep/step-ca";
    const TAG: &'static str = "latest";
    const CA_NAME: &'static str = "wire";
    pub const ACME_PROVISIONER_NAME: &'static str = "wire-acme";
    pub const PORT: u16 = 9000;

    pub fn run(docker: &Cli) -> (u16, Client, Container<StepCaImage>) {
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

    fn exec_after_start(&self, _cs: ContainerState) -> Vec<ExecCommand> {
        if self.is_builder {
            let cmd = format!("step ca provisioner add {} --type ACME", Self::ACME_PROVISIONER_NAME);
            let ready_conditions = vec![WaitFor::seconds(1)];
            vec![
                ExecCommand { cmd, ready_conditions },
                ExecCommand {
                    cmd: "chmod +w /home/step/password".to_string(),
                    ready_conditions: vec![WaitFor::seconds(1)],
                },
            ]
        } else {
            vec![]
        }
    }
}

#[derive(Debug)]
pub struct WiremockImage {
    pub volumes: HashMap<String, String>,
    pub env_vars: HashMap<String, String>,
    pub stubs_dir: PathBuf,
}

#[derive(Debug, Default, Clone)]
pub struct WiremockArgs;

impl ImageArgs for WiremockArgs {
    fn into_iterator(self) -> Box<dyn Iterator<Item = String>> {
        Box::new(vec!["/stubs".to_string(), "-p".to_string(), WiremockImage::PORT.to_string()].into_iter())
    }
}

impl WiremockImage {
    const NAME: &'static str = "ghcr.io/beltram/stubr";
    const TAG: &'static str = "latest";
    pub const PORT: u16 = 80;

    pub fn run<'a>(docker: &'a Cli, host: &str, stubs: Vec<serde_json::Value>) -> Container<'a, WiremockImage> {
        let instance = Self::default();
        instance.write_stubs(stubs);
        let image: RunnableImage<Self> = instance.into();
        let image = image.with_container_name(host).with_network(NETWORK);
        docker.run(image)
    }

    fn write_stubs(&self, stubs: Vec<serde_json::Value>) {
        for stub in stubs {
            let stub_name = format!("{}.json", rand_str());
            let stub_content = serde_json::to_string_pretty(&stub).unwrap();
            let stub_file = self.stubs_dir.join(stub_name);
            std::fs::write(stub_file, stub_content).unwrap();
        }
    }
}

impl Image for WiremockImage {
    type Args = WiremockArgs;

    fn name(&self) -> String {
        Self::NAME.to_string()
    }

    fn tag(&self) -> String {
        Self::TAG.to_string()
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        vec![WaitFor::seconds(1)]
    }

    fn volumes(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_> {
        Box::new(self.volumes.iter())
    }

    fn expose_ports(&self) -> Vec<u16> {
        vec![Self::PORT]
    }
}

impl Default for WiremockImage {
    fn default() -> Self {
        let stubs_dir = std::env::temp_dir().join(rand_str());
        std::fs::create_dir(&stubs_dir).unwrap();
        let host_volume = stubs_dir.as_os_str().to_str().unwrap();
        Self {
            volumes: HashMap::from_iter(vec![(host_volume.to_string(), "/stubs".to_string())]),
            env_vars: HashMap::default(),
            stubs_dir,
        }
    }
}

fn rand_str() -> String {
    use rand::distributions::{Alphanumeric, DistString};
    Alphanumeric.sample_string(&mut rand::thread_rng(), 12)
}
