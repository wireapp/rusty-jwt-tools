use clap::Parser;

#[derive(Debug, Parser)]
pub struct ParseJwt {
    /// JSON claims
    jwt: String,
}

impl ParseJwt {
    pub fn execute(self) -> anyhow::Result<()> {
        println!("Parse JWT");
        Ok(())
    }
}
