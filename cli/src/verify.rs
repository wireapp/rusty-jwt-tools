use clap::Parser;

#[derive(Debug, Parser)]
pub struct VerifyJwt {
    /// JWT to verify
    jwt: String,
}

impl VerifyJwt {
    pub fn execute(self) -> anyhow::Result<()> {
        println!("Verify JWT");
        Ok(())
    }
}
