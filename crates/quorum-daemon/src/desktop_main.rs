#![cfg_attr(windows, windows_subsystem = "windows")]
//! QuorumRAG Desktop single executable launcher.
//! Launches the QuorumRAG daemon and Web UI service.

use std::env;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn find_quorumrag_binary() -> anyhow::Result<PathBuf> {
    let current_exe = env::current_exe()?;
    if let Some(exe_dir) = current_exe.parent() {
        let candidate_names = if cfg!(windows) {
            vec!["quorumrag.exe", "quorumrag"]
        } else {
            vec!["quorumrag", "quorumrag.exe"]
        };

        for name in &candidate_names {
            let candidate = exe_dir.join(name);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    // Fallback: check PATH
    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            let candidate = if cfg!(windows) {
                dir.join("quorumrag.exe")
            } else {
                dir.join("quorumrag")
            };
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    anyhow::bail!("Could not locate quorumrag binary next to launcher or in PATH")
}

fn main() -> anyhow::Result<()> {
    let quorumrag_bin = find_quorumrag_binary()?;
    let args: Vec<String> = env::args().skip(1).collect();

    let mut cmd = Command::new(quorumrag_bin);
    cmd.args(&args);

    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let status: ExitStatus = cmd.status()?;

    std::process::exit(status.code().unwrap_or(1));
}
