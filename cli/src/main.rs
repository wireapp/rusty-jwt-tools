use clap::{Parser, Subcommand};

pub mod build;
pub mod parse;
pub mod pem;
pub mod verify;

/// Simple program to greet a person
#[derive(Debug, Parser)]
#[command(
    version,
    about,
    name = "rusty-jwt-cli",
    bin_name = "rusty-jwt-cli",
    rename_all = "kebab-case"
)]
struct RustyCli {
    #[clap(subcommand)]
    cmd: Commands,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::enum_variant_names)]
enum Commands {
    /// Create a new JWT
    JwtBuild {
        #[command(flatten)]
        delegate: build::BuildJwt,
    },
    /// Parse (debug) a JWT
    JwtParse {
        #[command(flatten)]
        delegate: parse::ParseJwt,
    },
    /// Verify a JWT
    JwtVerify {
        #[command(flatten)]
        delegate: parse::ParseJwt,
    },
}

fn main() -> anyhow::Result<()> {
    let cli: RustyCli = RustyCli::parse();
    match cli.cmd {
        Commands::JwtBuild { delegate } => delegate.execute()?,
        Commands::JwtParse { delegate } => delegate.execute()?,
        Commands::JwtVerify { delegate } => delegate.execute()?,
    };
    Ok(())
}
