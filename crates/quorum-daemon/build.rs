//! Hermetic, zero-network Windows resource embedding script for `quorum-daemon`.
//!
//! Compiles `assets/icons/quorumrag.rc` (`assets/icons/quorumrag.ico`) via Windows SDK `rc.exe`
//! so both `quorumrag.exe` and `quorum-desktop.exe` carry the native QuorumRAG icon resource
//! directly in their PE headers (visible in Explorer, Taskbar, Start Menu, and Desktop shortcuts).

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| manifest_dir.clone());

    let icons_dir = repo_root.join("assets").join("icons");
    let rc_path = icons_dir.join("quorumrag.rc");
    let ico_path = icons_dir.join("quorumrag.ico");

    println!("cargo:rerun-if-changed={}", rc_path.display());
    println!("cargo:rerun-if-changed={}", ico_path.display());

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" || target_env != "msvc" {
        return;
    }
    if !rc_path.is_file() || !ico_path.is_file() {
        println!(
            "cargo:warning=QuorumRAG Windows icon assets missing at {}; skipping PE icon embed.",
            icons_dir.display()
        );
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let res_path = out_dir.join("quorumrag_icon.res");

    let Some(rc_exe) = locate_rc_exe() else {
        println!("cargo:warning=Windows SDK rc.exe not found; skipping PE icon resource embed.");
        return;
    };

    let status = Command::new(&rc_exe)
        .arg("/nologo")
        .arg("/fo")
        .arg(&res_path)
        .arg(&rc_path)
        .current_dir(&icons_dir)
        .status();

    match status {
        Ok(s) if s.success() && res_path.is_file() => {
            println!("cargo:rustc-link-arg-bins={}", res_path.display());
        }
        Ok(s) => {
            println!(
                "cargo:warning=rc.exe exited with status {}; skipping PE icon embed.",
                s
            );
        }
        Err(err) => {
            println!("cargo:warning=Failed to invoke rc.exe: {err}");
        }
    }
}

fn locate_rc_exe() -> Option<PathBuf> {
    if let Ok(path_var) = env::var("PATH") {
        for dir in env::split_paths(&path_var) {
            let cand = dir.join("rc.exe");
            if cand.is_file() {
                return Some(cand);
            }
        }
    }

    let kits_bin = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    if let Ok(entries) = std::fs::read_dir(kits_bin) {
        let mut versions: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|ent| ent.path()))
            .filter(|p| p.is_dir())
            .collect();
        versions.sort();
        versions.reverse();
        for ver_dir in versions {
            let cand = ver_dir.join("x64").join("rc.exe");
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}
