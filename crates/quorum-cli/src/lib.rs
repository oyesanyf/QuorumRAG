use clap::{Parser, Subcommand};

pub mod commands;

pub use commands::issue_cert::{run_issue_cert, MarketplaceIssueCertArgs};
pub use commands::buyer_pull::{run_buyer_pull, MarketplaceBuyerPullArgs, BuyerPullSummary};

#[derive(Parser, Debug)]
#[command(
    name = "quorum-cli",
    about = "QuorumRAG CLI & Sovereign Marketplace Testing Tools",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Issue and sign a SovereignBuyerCertificate supporting corporate CIDRs including 127.0.0.1/32
    #[command(name = "marketplace-issue-cert", visible_alias = "issue-cert")]
    MarketplaceIssueCert(MarketplaceIssueCertArgs),

    /// Execute an end-to-end pull of training data from a localhost or remote seller daemon
    #[command(name = "marketplace-buyer-pull", visible_alias = "buyer-pull")]
    MarketplaceBuyerPull(MarketplaceBuyerPullArgs),
}
