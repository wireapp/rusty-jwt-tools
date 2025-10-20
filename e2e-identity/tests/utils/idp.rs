use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};

use serde::{Deserialize, Serialize};

use crate::utils::docker::{authelia, keycloak};

pub const OAUTH_CLIENT_ID: &'static str = "wireapp";
pub const OAUTH_CLIENT_NAME: &'static str = "Wire";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpServer {
    pub hostname: String,
    pub addr: SocketAddr,
    pub issuer: String,
    pub discovery_base_url: String,
    pub user: User,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpServerConfig {
    pub domain: String,
    pub redirect_uri: String,
    pub host: String,
    pub user: User,
}

/// Get a free port from the OS
fn free_tcp_port() -> Option<u16> {
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    let port = TcpListener::bind(addr).ok()?.local_addr().ok()?.port();
    Some(port)
}

// pub async fn start_idp_server(wire_server_hostname: &str, redirect_uri: &str) -> IdpServer {
//     let hostname = "keycloak".to_string();
//     let port = free_tcp_port().unwrap();
//     let username = format!("alice_wire@{wire_server_hostname}");
//     let email = format!("alicesmith@{wire_server_hostname}");
//     let password = "foo".to_string();
//     let keycloak_cfg = KeycloakCfg {
//         oauth_client_id: "wireapp".to_string(),
//         http_host_port: port,
//         host: hostname.clone(),
//         firstname: "Alice".to_string(),
//         lastname: "Smith".to_string(),
//         username: username.clone(),
//         email,
//         password: password.clone(),
//     };
//
//     let keycloak_server = KeycloakImage::run(keycloak_cfg, redirect_uri.to_string()).await;
//     let addr = keycloak_server.socket;
//
//     let realm = KeycloakImage::REALM.to_string();
//     let issuer = format!("http://{hostname}:{port}/realms/{realm}");
//     let discovery_base_url = issuer.clone();
//
//     IdpServer {
//         hostname,
//         addr,
//         username,
//         password,
//         issuer,
//         discovery_base_url,
//         realm,
//     }
// }

pub async fn start_idp_server(wire_server_hostname: &str, redirect_uri: &str) -> IdpServer {
    env_logger::init();

    let user = User {
        username: format!("alice_wire@{wire_server_hostname}"),
        password: "foo".to_string(),
        first_name: "Alice".to_string(),
        last_name: "Smith".to_string(),
        email: "alice.smith@some.provider".to_string()
    };

    let hostname = "authelia".to_string();
    let config = IdpServerConfig {
        domain: "wire".to_string(),
        redirect_uri: redirect_uri.to_string(),
        host: hostname.clone(),
        user: user.clone()
    };

    let port = authelia::start_server(&config).await;
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    eprintln!("STARTED IDP server on {addr}");

    let issuer = format!("http://{hostname}:{port}");
    let discovery_base_url = format!("http://{hostname}:{port}");

    let x = IdpServer {
        hostname,
        addr,
        issuer,
        discovery_base_url,
        user
    };
    dbg!(&x);
    x
}
