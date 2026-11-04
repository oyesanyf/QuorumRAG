//! # QuorumRAG Web UI & Static Assets
//!
//! Embedded responsive ChatGPT-like web interface, static asset handler with
//! mime resolution, LangExtract visualizer, and SPA fallback.

pub mod assets;

pub use assets::{get_asset, get_index_html, static_handler, WebAssets};
