use argon2::{
    Algorithm, Argon2, ParamsBuilder, Version,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{
        CmdWaitFor, ContainerPort, ExecCommand, IntoContainerPort, Mount, ReuseDirective,
        logs::{LogFrame, consumer::logging_consumer::LoggingConsumer},
    },
    runners::AsyncRunner,
};

use crate::utils::{
    docker::{NETWORK, SHM, rand_str},
    idp::{OAUTH_CLIENT_ID, OAUTH_CLIENT_NAME, User, IdpServerConfig},
};

fn compute_password_hash(password: &str) -> String {
    // Use parameters corresponding to the "Low Memory" situation:
    // https://www.authelia.com/reference/guides/passwords/#user--password-file
    let params = ParamsBuilder::new().m_cost(65536).p_cost(4).t_cost(3).build().unwrap();

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::generate(&mut OsRng);

    // Return the digest as a PHC string ($argon2id$v=19$...).
    // https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
    argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string()
}

const PORT: ContainerPort = ContainerPort::Tcp(9091);

fn authelia_users(user: &User) -> String {
    format!(
        r#"
users:
  {username}:
    disabled: false
    displayname: '{displayname}'
    password: '{password}'
    email: '{email}
"#,
        username = user.username,
        displayname = format!("{} {}", user.first_name, user.last_name),
        email = user.email,
        password = compute_password_hash(&user.password)
    )
}

fn authelia_config(redirect_uri: &str) -> String {
    let x = format!(
        include_str!("config.template"),
        redirect_uri = redirect_uri,
        oauth_client_id = OAUTH_CLIENT_ID,
        oauth_client_name = OAUTH_CLIENT_NAME,
    );
    std::fs::write("/tmp/burek", &x).unwrap();
    x
}

pub async fn start_server(config: &IdpServerConfig) -> u16 {
    let host_volume = std::env::temp_dir().join(format!("authelia-{}", rand_str()));
    std::fs::create_dir_all(host_volume.join("config")).unwrap();
    std::fs::write(
        host_volume.join("config/config.yml"),
        authelia_config(&config.redirect_uri)
    )
    .unwrap();

    std::fs::write(host_volume.join("config/users.yml"), authelia_users(&config.user)).unwrap();

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let private_key_path = std::path::Path::new(manifest_dir)
        .parent()
        .unwrap()
        .join(file!())
        .parent()
        .unwrap()
        .join("private.pem");
    dbg!(&host_volume);
    dbg!(&config);

    // The image exposes port 9091.
    let image = GenericImage::new("authelia/authelia", "4.39")
        .with_container_name(&config.host)
        .with_network(NETWORK)
        .with_mount(Mount::bind_mount(
            host_volume.join("config").to_str().unwrap(),
            "/config",
        ))
        .with_log_consumer(LoggingConsumer::new())
        .with_copy_to("/config/private.pem", private_key_path)
        .with_reuse(ReuseDirective::Always)
        .with_cmd(vec![
            "authelia",
            "--config",
            "/config/config.yml",
            "--config.experimental.filters",
            "template",
        ])
        .with_shm_size(SHM);

    let node = image.start().await.expect("Error starting Authelia image");
    node.get_host_port_ipv4(PORT).await.unwrap()
}
