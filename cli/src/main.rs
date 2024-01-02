use clap::Parser;
use rusty_jwt_cli::*;

fn main() -> anyhow::Result<()> {
    let cli: RustyCli = RustyCli::parse();
    match cli.cmd {
        Commands::JwtBuild { delegate } => delegate.execute()?,
        Commands::JwtParse { delegate } => delegate.execute()?,
        Commands::JwkParse { delegate } => delegate.execute()?,
        Commands::VerifyAccess { delegate } => delegate.execute()?,
        Commands::GenerateAccess { delegate } => delegate.execute()?,
    };
    Ok(())
}
