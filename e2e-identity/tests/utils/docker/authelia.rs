use std::net::SocketAddr;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use testcontainers::core::{ContainerPort, Mount};
use testcontainers::runners::AsyncRunner;
use crate::utils::docker::{rand_str, NETWORK, SHM};

const PORT: ContainerPort = ContainerPort::Tcp(9091);
pub struct AutheliaServer {
    pub http_uri: String,
    pub node: ContainerAsync<GenericImage>,
    pub socket: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct AutheliaCfg {
    pub oauth_client_id: String,
    pub http_host_port: u16,
    pub domain: String,
    pub host: String,
}

fn authelia_users() -> String {
r#"
users:
  authelia:
    disabled: false
    displayname: 'Authelia User'
    # Password is authelia
    password: '$6$rounds=50000$BpLnfgDsc2WD8F2q$Zis.ixdg9s/UOJYrs56b5QEZFiZECu0qZVNsIYxBaNJ7ucIL.nlxVCT5tqh8KHG8X4tlwCFm5r6NTOZZ5qRFN/'  # yamllint disable-line rule:line-length
    email: 'authelia@authelia.com'
    groups:
      - 'admins'
      - 'dev'
...
"#.to_string()
}

fn authelia_config(port: &str, oauth_client_id: &str, redirect_uri: &str) -> String {
    format!(
r#"
server:
  address: 'tcp://:{port}'

log:
  level: 'debug'

totp:
  issuer: 'authelia.com'

identity_validation:
  reset_password:
    jwt_secret: 'a_very_important_secret'

# duo_api:
#  hostname: api-123456789.example.com
#  integration_key: ABCDEF
#  # This secret can also be set using the env variables AUTHELIA_DUO_API_SECRET_KEY_FILE
#  secret_key: 1234567890abcdefghifjkl

authentication_backend:
  file:
    path: '/config/users_database.yml'

access_control:
  default_policy: 'deny'
  rules:
    # Rules applied to everyone
    - domain: 'public.example.com'
      policy: 'bypass'
    - domain: 'traefik.example.com'
      policy: 'one_factor'
    - domain: 'secure.example.com'
      policy: 'two_factor'

session:
  # This secret can also be set using the env variables AUTHELIA_SESSION_SECRET_FILE
  secret: 'insecure_session_secret'

  cookies:
    - name: 'authelia_session'
      domain: 'example.com'  # Should match whatever your root protected domain is
      authelia_url: 'https://authelia.example.com'
      expiration: '1 hour'
      inactivity: '5 minutes'

regulation:
  max_retries: 3
  find_time: '2 minutes'
  ban_time: '5 minutes'

storage:
  encryption_key: 'you_must_generate_a_random_string_of_more_than_twenty_chars_and_configure_this'
  local:
    path: '/config/db.sqlite3'

notifier:
  filesystem:
    filename: '/config/notification.txt'

identity_providers:
  oidc:
    clients:
      - client_id: '{oauth_client_id}'
        client_name: 'wireapp-oauth-client'
        client_secret: '$pbkdf2-sha512$310000$c8p78n7pUMln0jzvd4aK4Q$JNRBzwAo0ek5qKn50cFzzvE9RXV88h1wJn5KGiHrD0YKtZaR/nCb2CJPOsKaPK0hjf.9yHxzQGZziziccp6Yng'  # The digest of 'insecure_secret'.
        sector_identifier_uri: 'https://example.com/sector.json'
        public: false
        redirect_uris:
          - '{redirect_uri}'
        request_uris:
          - 'https://oidc.example.com:8080/oidc/request-object.jwk'
        audience:
          - 'https://app.example.com'
        scopes:
          - 'openid'
          - 'groups'
          - 'email'
          - 'profile'
        grant_types:
          - 'refresh_token'
          - 'authorization_code'
        response_types:
          - 'code'
        response_modes:
          - 'form_post'
          - 'query'
          - 'fragment'
        authorization_policy: 'two_factor'
        lifespan: ''
        claims_policy: ''
        requested_audience_mode: 'explicit'
        consent_mode: 'explicit'
        pre_configured_consent_duration: '1 week'
        require_pushed_authorization_requests: false
        require_pkce: false
        pkce_challenge_method: 'S256'
        authorization_signed_response_key_id: ''
        authorization_signed_response_alg: 'RS256'
        authorization_encrypted_response_key_id: ''
        authorization_encrypted_response_alg: 'none'
        authorization_encrypted_response_enc: 'A128CBC-HS256'
        id_token_signed_response_key_id: ''
        id_token_signed_response_alg: 'RS256'
        id_token_encrypted_response_key_id: ''
        id_token_encrypted_response_alg: 'none'
        id_token_encrypted_response_enc: 'A128CBC-HS256'
        access_token_signed_response_key_id: ''
        access_token_signed_response_alg: 'none'
        access_token_encrypted_response_key_id: ''
        access_token_encrypted_response_alg: 'none'
        access_token_encrypted_response_enc: 'A128CBC-HS256'
        userinfo_signed_response_key_id: ''
        userinfo_signed_response_alg: 'none'
        userinfo_encrypted_response_key_id: ''
        userinfo_encrypted_response_alg: 'none'
        userinfo_encrypted_response_enc: 'A128CBC-HS256'
        introspection_signed_response_key_id: ''
        introspection_signed_response_alg: 'none'
        introspection_encrypted_response_key_id: ''
        introspection_encrypted_response_alg: 'none'
        introspection_encrypted_response_enc: 'A128CBC-HS256'
        request_object_signing_alg: 'RS256'
        request_object_encryption_alg: ''
        request_object_encryption_enc: ''
        token_endpoint_auth_method: 'client_secret_basic'
        token_endpoint_auth_signing_alg: 'RS256'
        revocation_endpoint_auth_method: 'client_secret_basic'
        revocation_endpoint_auth_signing_alg: 'RS256'
        introspection_endpoint_auth_method: 'client_secret_basic'
        introspection_endpoint_auth_signing_alg: 'RS256'
        pushed_authorization_request_endpoint_auth_method: 'client_secret_basic'
        pushed_authorization_request_endpoint_auth_signing_alg: 'RS256'
        jwks_uri: ''
        jwks:
          - key_id: 'example'
            algorithm: 'RS256'
            use: 'sig'
            key: |
              -----BEGIN RSA PUBLIC KEY-----
              ...
              -----END RSA PUBLIC KEY-----
            certificate_chain: |
              -----BEGIN CERTIFICATE-----
              ...
              -----END CERTIFICATE-----
              -----BEGIN CERTIFICATE-----
              ...
              -----END CERTIFICATE-----
...
"#
    )
}

pub async fn start_authelia_server(cfg: &AutheliaCfg) -> AutheliaServer {
    let host_volume = std::env::temp_dir().join(rand_str());
    std::fs::create_dir(&host_volume).unwrap();

    // #[cfg(unix)]
    // {
    //     // Allow container user to write to our host volume.
    //     use std::os::unix::fs::PermissionsExt;
    //     let permissions = std::fs::Permissions::from_mode(0o777);
    //     std::fs::set_permissions(&host_volume, permissions).unwrap();
    //     std::fs::write(
    //         host_volume.join("intermediate.template"),
    //         crate::utils::docker::stepca::INTERMEDIATE_CERT_TEMPLATE.to_string().into_bytes(),
    //     )
    //         .unwrap();
    // }

    std::fs::create_dir(host_volume.join("config")).unwrap();
    std::fs::write(
        host_volume.join("config/configuration.yml"),
        authelia_config(&cfg.http_host_port.to_string()).into_bytes(),
    ).unwrap();

    std::fs::write(
        host_volume.join("config/users_database.yml"),
        authelia_users().into_bytes(),
    ).unwrap();

    // Prepare the container image. Note that instead of just starting the image as-is, we're
    // overriding the command to be a long sleep, in order to be able to issue commands inside
    // the container, to generate exactly the root & intermediate certificates we need. Otherwise,
    // the CA server would start and automatically generate the PKI & CA configuration that would
    // not suit us. Specifically, the intermediate certificate auto-generated by step-ca would not
    // have the necessary x509 name constraints, which is why we have to use a custom certificate
    // template that includes name constraints.
    let image = GenericImage::new("authelia/authelia", "4.39")
        .with_exposed_port(ContainerPort::Tcp(cfg.http_host_port))
        .with_container_name(&cfg.host)
        .with_network(NETWORK)
        // .with_mount(Mount::bind_mount(host_volume.to_str().unwrap(), "/data/authelia"))
        .with_mount(Mount::bind_mount(host_volume.join("config").to_str().unwrap(), "/config"))
        .with_shm_size(SHM);

    let node = image.start().await.expect("Error running Authelia image");

    let port = node.get_host_port_ipv4(ContainerPort::Tcp(cfg.http_host_port)).await.unwrap();
    let http_uri = format!("https://{}:{}", &cfg.host, port);

    let ip = std::net::IpAddr::V4("127.0.0.1".parse().unwrap());
    let socket = SocketAddr::new(ip, port);

    AutheliaServer {
        http_uri,
        socket,
        node,
    }
}
