use std::{collections::HashMap, path::PathBuf};
use testcontainers::{clients::Cli, core::WaitFor, Container, Image, ImageArgs, RunnableImage};

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
        let image = image.with_container_name(host).with_network(super::NETWORK);
        docker.run(image)
    }

    /// Runs with a stub accepting anything
    pub fn run_echo<'a>(docker: &'a Cli, host: &str) -> (Container<'a, WiremockImage>, String) {
        let stub = serde_json::json!({
           "request": {
                "method": "GET"
            },
            "response": {
                "status": 200
            }
        });
        let node = Self::run(docker, host, vec![stub]);
        let port = node.get_host_port_ipv4(Self::PORT);
        (node, format!("http://localhost:{port}"))
    }

    fn write_stubs(&self, stubs: Vec<serde_json::Value>) {
        for stub in stubs {
            let stub_name = format!("{}.json", super::rand_str());
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
        let stubs_dir = std::env::temp_dir().join(super::rand_str());
        std::fs::create_dir(&stubs_dir).unwrap();
        let host_volume = stubs_dir.as_os_str().to_str().unwrap();
        Self {
            volumes: HashMap::from_iter(vec![(host_volume.to_string(), "/stubs".to_string())]),
            env_vars: HashMap::default(),
            stubs_dir,
        }
    }
}
