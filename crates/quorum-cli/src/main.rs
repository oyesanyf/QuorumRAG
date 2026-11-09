use clap::Parser;
use anyhow::Result;
use quorum_cli::{run_issue_cert, run_buyer_pull, Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    let cli = Cli::parse();

    match cli.command {
        Commands::MarketplaceIssueCert(ref args) => {
            let _cert = run_issue_cert(args)?;
        }
        Commands::MarketplaceBuyerPull(ref args) => {
            let _summary = run_buyer_pull(args).await?;
        }
    }

    Ok(())
}
