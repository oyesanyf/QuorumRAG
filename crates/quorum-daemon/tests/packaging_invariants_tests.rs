//! Cross-OS installer & MSI database sequencing invariant regression tests.
//!
//! Guards against:
//! 1. Windows Installer Error 2613 (`ICE63`: `RemoveExistingProducts` sequenced
//!    after a deferred action without an intervening `InstallExecute`).
//! 2. Windows Installer Error 267 / 1721 (`Directory="INSTALLFOLDER"` on system
//!    custom actions running before `INSTALLFOLDER` exists or after `RemoveFiles`).
//! 3. Orphaned `watch-p2p` supervisor child processes holding `data/` locks across
//!    upgrades (`taskkill.exe /f /t /im quorumrag.exe`).
//! 4. Universal Zero-Touch PATH law (`<Environment` forbidden in WiX manifests).
//! 5. Debian Policy §7.6 self-conflict (`Conflicts: quorumrag (<< ...)`), RPM
//!    missing `%pre` upgrade service stop, and macOS `launchctl bootstrap`
//!    failing under `set -euo pipefail`.
//! 6. Cross-OS package script default version drift relative to workspace `Cargo.toml`.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn strip_xml_comments(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        if let Some(end) = rest[start + 4..].find("-->") {
            rest = &rest[start + 4 + end + 3..];
        } else {
            return out;
        }
    }
    out.push_str(rest);
    out
}

fn workspace_version(cargo_toml: &str) -> String {
    let mut in_workspace_pkg = false;
    for line in cargo_toml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_workspace_pkg = trimmed == "[workspace.package]";
            continue;
        }
        if in_workspace_pkg && trimmed.starts_with("version") {
            if let Some((_, rhs)) = trimmed.split_once('=') {
                return rhs.trim().trim_matches('"').to_string();
            }
        }
    }
    panic!("workspace.package.version not found in Cargo.toml");
}

#[test]
fn wix_manifest_enforces_ice63_error_2613_prevention_and_zero_touch_path() {
    let root = repo_root();
    let wxs_raw = fs::read_to_string(root.join("wix/QuorumRAG.wxs"))
        .expect("read wix/QuorumRAG.wxs");
    let wxs = strip_xml_comments(&wxs_raw);

    // 1. Universal Zero-Touch PATH invariant: zero <Environment elements.
    assert!(
        !wxs.contains("<Environment"),
        "Zero-Touch PATH violation: <Environment element found in wix/QuorumRAG.wxs"
    );

    // 2. MSI Error 2613 / ICE63 invariant:
    // MajorUpgrade must use Schedule="afterInstallExecute", with StopDeleteQuorumServiceUpgrade
    // scheduled After="InstallInitialize" and <InstallExecute After="StopDeleteQuorumServiceUpgrade" />
    // flushing the script immediately before RemoveExistingProducts.
    assert!(
        wxs.contains(r#"<MajorUpgrade AllowDowngrades="yes" Schedule="afterInstallExecute" />"#),
        "MajorUpgrade must use Schedule=\"afterInstallExecute\" to prevent MSI Error 2613"
    );
    assert!(
        !wxs.contains(r#"Schedule="afterInstallInitialize""#),
        "Schedule=\"afterInstallInitialize\" with pre-upgrade deferred actions triggers MSI Error 2613"
    );
    assert!(
        !wxs.contains(r#"Before="RemoveExistingProducts""#),
        "Placing custom actions directly Before=\"RemoveExistingProducts\" violates ICE63 (MSI Error 2613)"
    );
    assert!(
        wxs.contains(
            r#"<Custom Action="StopDeleteQuorumServiceUpgrade" After="InstallInitialize" Condition="WIX_UPGRADE_DETECTED AND NOT REINSTALL" />"#
        ),
        "StopDeleteQuorumServiceUpgrade must run After=\"InstallInitialize\" on upgrade"
    );
    assert!(
        wxs.contains(r#"<InstallExecute After="StopDeleteQuorumServiceUpgrade" />"#),
        "InstallExecute must flush StopDeleteQuorumServiceUpgrade immediately before RemoveExistingProducts"
    );

    // 3. Process-tree kill (/t) so watch-p2p child processes never hold data locks during upgrade.
    assert!(
        wxs.contains("taskkill.exe /f /t /im quorumrag.exe")
            || wxs.contains(r#"taskkill.exe&quot; /f /t /im quorumrag.exe"#),
        "taskkill.exe must pass /t to terminate watch-p2p child processes cleanly"
    );
    assert!(
        !wxs.contains("taskkill.exe /f /im quorumrag.exe"),
        "Found taskkill.exe without /t tree-termination flag in wix/QuorumRAG.wxs"
    );

    // 4. System-utility custom actions must anchor to System64Folder, not INSTALLFOLDER
    // (INSTALLFOLDER does not exist yet on fresh install before CreateFolders and is deleted after RemoveFiles).
    for system_ca in [
        "StopDeleteQuorumServiceUpgrade",
        "StopDeleteQuorumServiceUninstall",
        "KillQuorumOrphans",
        "RemoveQuorumData",
        "AddQuorumFirewallRule_In_Program",
        "RemoveQuorumFirewallRule_In_Program",
    ] {
        let marker = format!(r#"<CustomAction Id="{system_ca}""#);
        let idx = wxs
            .find(&marker)
            .unwrap_or_else(|| panic!("missing CustomAction {system_ca}"));
        let snippet_end = wxs[idx..]
            .find("/>")
            .map(|rel| idx + rel)
            .unwrap_or(wxs.len());
        let snippet = &wxs[idx..snippet_end];
        assert!(
            snippet.contains(r#"Directory="System64Folder""#),
            "CustomAction {system_ca} must use Directory=\"System64Folder\", got: {snippet}"
        );
    }
}

#[test]
fn linux_and_macos_installers_enforce_clean_upgrade_invariants() {
    let root = repo_root();

    let linux_sh = fs::read_to_string(root.join("packaging/linux/build_packages.sh"))
        .expect("read packaging/linux/build_packages.sh");
    assert!(
        !linux_sh.contains("Conflicts: ${PACKAGE_NAME}"),
        "Debian control file must not self-conflict on package upgrades"
    );
    assert!(
        linux_sh.contains("Provides: ${PACKAGE_NAME}")
            && linux_sh.contains("Replaces: ${PACKAGE_NAME}"),
        "Debian control file must declare Provides + Replaces"
    );
    assert!(
        linux_sh.contains("%pre\n") || linux_sh.contains("%pre\r\n"),
        "RPM spec must define a %pre scriptlet to stop running service before upgrade replacement"
    );
    assert!(
        linux_sh.contains("pkill -TERM -x quorumrag"),
        "Linux installer scripts must terminate lingering quorumrag/watch-p2p processes before replacing binary"
    );

    let macos_install = fs::read_to_string(root.join("packaging/macos/install.sh"))
        .expect("read packaging/macos/install.sh");
    assert!(
        macos_install.contains(r#"launchctl bootstrap system "${TARGET_PLIST}" 2>/dev/null || true"#),
        "macOS install.sh must guard launchctl bootstrap under set -euo pipefail"
    );
    assert!(
        macos_install.contains(r#"pkill -9 -f "quorumrag" 2>/dev/null || true"#),
        "macOS install.sh must terminate lingering quorumrag processes before upgrade"
    );
}

#[test]
fn cross_os_packaging_versions_match_workspace_cargo_toml() {
    let root = repo_root();
    let cargo_toml = fs::read_to_string(root.join("Cargo.toml")).expect("read Cargo.toml");
    let ver = workspace_version(&cargo_toml);

    let wxs = fs::read_to_string(root.join("wix/QuorumRAG.wxs")).expect("read QuorumRAG.wxs");
    assert!(
        wxs.contains(&format!(r#"<?define ProductVersion = "{ver}" ?>"#)),
        "wix/QuorumRAG.wxs default ProductVersion does not match Cargo.toml ({ver})"
    );

    let package_ps1 =
        fs::read_to_string(root.join("scripts/package.ps1")).expect("read scripts/package.ps1");
    assert!(
        package_ps1.contains(&format!(r#"[string]$Version = "{ver}""#)),
        "scripts/package.ps1 default $Version does not match Cargo.toml ({ver})"
    );

    let linux_sh = fs::read_to_string(root.join("packaging/linux/build_packages.sh"))
        .expect("read packaging/linux/build_packages.sh");
    assert!(
        linux_sh.contains(&format!(r#"VERSION="${{2:-{ver}}}""#)),
        "packaging/linux/build_packages.sh default VERSION does not match Cargo.toml ({ver})"
    );

    let macos_sh = fs::read_to_string(root.join("packaging/macos/build_packages.sh"))
        .expect("read packaging/macos/build_packages.sh");
    assert!(
        macos_sh.contains(&format!(r#"VERSION="${{2:-{ver}}}""#)),
        "packaging/macos/build_packages.sh default VERSION does not match Cargo.toml ({ver})"
    );
}
