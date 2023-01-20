use std::collections::HashMap;
use testcontainers::{clients::Cli, core::WaitFor, Container, Image, RunnableImage};

#[derive(Debug)]
pub struct DexImage {
    pub volumes: HashMap<String, String>,
    pub env_vars: HashMap<String, String>,
}

impl DexImage {
    const NAME: &'static str = "dexidp/dex";
    const TAG: &'static str = "latest";
    pub const PORT: u16 = 5556;

    pub fn run<'a>(docker: &'a Cli, host: &str) -> (u16, Container<'a, DexImage>) {
        let instance = Self::default();
        let image: RunnableImage<Self> = instance.into();
        let image = image.with_container_name(host).with_network(super::NETWORK);
        let node = docker.run(image);
        let port = node.get_host_port_ipv4(Self::PORT);
        (port, node)
    }
}

impl Image for DexImage {
    type Args = ();

    fn name(&self) -> String {
        Self::NAME.to_string()
    }

    fn tag(&self) -> String {
        Self::TAG.to_string()
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        vec![WaitFor::message_on_stderr("listening (http) on 0.0.0.0:5556")]
    }

    fn volumes(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_> {
        Box::new(self.volumes.iter())
    }

    fn expose_ports(&self) -> Vec<u16> {
        vec![Self::PORT]
    }
}

impl Default for DexImage {
    fn default() -> Self {
        Self {
            volumes: HashMap::from_iter(vec![]),
            env_vars: HashMap::default(),
        }
    }
}

#[test]
fn test_dex() {
    let docker = Cli::docker();
    let (port, _dex) = DexImage::run(&docker, "dex");

    let uri = format!("http://localhost:{port}/dex/.well-known/openid-configuration");

    let response = reqwest::blocking::get(uri).unwrap();
    let body = response.json::<serde_json::Value>().unwrap();
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
}
