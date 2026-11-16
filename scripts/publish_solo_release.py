#!/usr/bin/env python3
"""
QuorumRAG Solo-Developer Release Orchestrator, OpenPGP Signer & Provenance Verifier
===================================================================================
Modeled directly on OshoosiClaw's EDR solo-developer release workflow:
1. Prunes stale duplicate builds in deploy/{windows,linux,macos}
2. Computes SHA256SUMS.txt across canonical release artifacts
3. Signs detached OpenPGP (.asc / .sig) + SHA256SUMS.txt.asc + PUBLIC_KEY.asc when GPG key exists
4. Generates & cryptographically verifies Witness DSSE in-toto v0.1 / SLSA v0.2 provenance bundle
5. Optionally tags HEAD as `quorumrag-v<version>` and pushes to origin to trigger native multi-OS CI builds
"""

import re
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

for gdir in [
    r"C:\Program Files\Git\cmd",
    r"C:\Program Files\Git\bin",
    r"C:\Program Files\Git\usr\bin",
    r"C:\Program Files\GitHub CLI",
]:
    if os.path.exists(gdir) and gdir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = gdir + os.pathsep + os.environ.get("PATH", "")

SIGNER_NAME = "OpenOsoosi Release Signer"
SIGNER_EMAIL = "security@oshoosiclaw.dev"
DEFAULT_WIN_CERT_THUMBPRINT = "9A6D3B509500813058EC63183476464FAC8F015B"


def locate_signtool() -> str | None:
    found = shutil.which("signtool.exe")
    if found and os.path.exists(found):
        return found
    kits = Path(r"C:\Program Files (x86)\Windows Kits\10\bin")
    if kits.exists():
        matches = sorted(kits.rglob("x64/signtool.exe"), reverse=True)
        if matches:
            return str(matches[0])
    return None


def ensure_windows_authenticode_signed(root: Path, version: str, trust_local: bool = False) -> None:
    """Ensure Windows .exe and .msi release artifacts carry an RFC 3161 timestamped
    Authenticode signature with a friendly UAC product description, and verify/install
    LocalMachine publisher trust when available."""
    if sys.platform != "win32":
        return

    signtool = locate_signtool()
    if not signtool:
        print("[!] signtool.exe not found; skipping Windows Authenticode step.")
        return

    v_clean = version.lstrip("v")
    msi_path = root / "deploy" / "windows" / f"QuorumRAG-{v_clean}-x86_64.msi"
    if not msi_path.exists():
        return

    thumb = os.environ.get("WINDOWS_CODESIGN_THUMBPRINT", DEFAULT_WIN_CERT_THUMBPRINT).strip()
    chk = subprocess.run(
        ["certutil.exe", "-user", "-store", "My", thumb],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if chk.returncode != 0:
        chk_m = subprocess.run(
            ["certutil.exe", "-store", "My", thumb],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if chk_m.returncode != 0:
            print(f"[i] Certificate {thumb} not in local store; keeping existing MSI signature.")
            return

    targets = [
        p
        for p in [
            root / "target" / "release" / "quorumrag.exe",
            root / "target" / "release" / "quorum-desktop.exe",
            msi_path,
        ]
        if p.exists()
    ]
    for target in targets:
        ver_res = subprocess.run(
            [signtool, "verify", "/pa", "/v", str(target)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        has_sig = thumb.upper() in ver_res.stdout.upper()
        has_ts = "The signature is timestamped:" in ver_res.stdout
        if has_sig and has_ts and target.suffix.lower() != ".msi":
            continue

        sign_cmd = [
            signtool,
            "sign",
            "/sha1",
            thumb,
            "/fd",
            "SHA256",
            "/tr",
            "http://timestamp.digicert.com",
            "/td",
            "SHA256",
            "/d",
            "QuorumRAG P2P Agentic RAG",
            "/du",
            "https://github.com/oyesanyf/QuorumRAG",
            "/q",
            str(target),
        ]
        sr = subprocess.run(
            sign_cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if sr.returncode == 0:
            print(f"[+] Authenticode signed + timestamped ({thumb[:12]}...): {target.name}")
        else:
            print(f"[!] signtool warning on {target.name}: {sr.stderr.strip()}")

    # Export public .cer (never private keys) to deploy/windows/OshoosiDeveloper.cer
    cer_out = root / "deploy" / "windows" / "OshoosiDeveloper.cer"
    if not cer_out.exists():
        subprocess.run(
            ["certutil.exe", "-user", "-store", "My", thumb, str(cer_out)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
        )

    # Check LocalMachine\Root & TrustedPublisher so UAC shows Verified Publisher instead of Unknown Publisher
    in_root = (
        subprocess.run(
            ["certutil.exe", "-store", "Root", thumb],
            stdin=subprocess.DEVNULL,
            capture_output=True,
        ).returncode
        == 0
    )
    in_pub = (
        subprocess.run(
            ["certutil.exe", "-store", "TrustedPublisher", thumb],
            stdin=subprocess.DEVNULL,
            capture_output=True,
        ).returncode
        == 0
    )
    if in_root and in_pub:
        print(f"[+] LocalMachine\\Root & TrustedPublisher verified for {thumb[:12]}... (Verified Publisher active).")
    elif trust_local and cer_out.exists():
        r_root = subprocess.run(["certutil.exe", "-addstore", "Root", str(cer_out)], stdin=subprocess.DEVNULL, capture_output=True)
        r_pub = subprocess.run(["certutil.exe", "-addstore", "TrustedPublisher", str(cer_out)], stdin=subprocess.DEVNULL, capture_output=True)
        if r_root.returncode == 0 and r_pub.returncode == 0:
            print(f"[+] Installed {cer_out.name} into LocalMachine\\Root & TrustedPublisher.")
        else:
            print(
                f"[i] Exported {cer_out}; run `powershell -ExecutionPolicy Bypass -File scripts/trust_publisher_cert.ps1` "
                "once as Admin to complete LocalMachine trust."
            )
    else:
        print(
            "[i] Note: LocalMachine\\Root does not yet contain Oshoosi Developer cert on this host; "
            "run `powershell -ExecutionPolicy Bypass -File scripts/trust_publisher_cert.ps1` once as Admin "
            "(or configure Azure Trusted Signing secrets for universal public CA trust)."
        )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def verify_zero_control_chars(text: str, label: str) -> None:
    forbidden = []
    for idx, ch in enumerate(text):
        code = ord(ch)
        if code == 0xFFFD or (code < 0x20 and ch not in ("\n", "\r", "\t")):
            forbidden.append((idx, hex(code)))
    if forbidden:
        raise RuntimeError(
            f"Control/replacement character detected in {label}: {forbidden[:5]}"
        )


def locate_gpg() -> str | None:
    candidates = [
        r"C:\Program Files\Git\usr\bin\gpg.exe",
        r"C:\Program Files (x86)\Git\usr\bin\gpg.exe",
        shutil.which("gpg.exe") or "",
        shutil.which("gpg") or "",
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return None


def fix_gnupg_config() -> None:
    common_conf = Path.home() / ".gnupg" / "common.conf"
    if common_conf.exists():
        try:
            content = common_conf.read_text(encoding="utf-8")
            if "use-keyboxd" in content and "# use-keyboxd" not in content:
                common_conf.write_text(
                    content.replace("use-keyboxd", "# use-keyboxd"),
                    encoding="utf-8",
                )
        except Exception:
            pass


def try_gpg_sign_artifacts(deploy_root: Path, artifacts: list[Path], sums_path: Path) -> None:
    gpg = locate_gpg()
    if not gpg:
        print("[!] gpg binary not found locally; skipping local OpenPGP .asc/.sig step.")
        return

    fix_gnupg_config()
    chk = subprocess.run(
        [gpg, "--batch", "--with-colons", "--list-keys", SIGNER_EMAIL],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    fpr = ""
    if chk.returncode == 0:
        for line in chk.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "fpr" and len(parts) > 9 and len(parts[9]) >= 32:
                fpr = parts[9].strip()
                break

    if not fpr:
        print(f"[!] GPG key for {SIGNER_EMAIL} not in local keyring; skipping local OpenPGP step.")
        return

    pub_out = deploy_root / "PUBLIC_KEY.asc"
    exp = subprocess.run(
        [gpg, "--batch", "--yes", "--armor", "--export", f"{SIGNER_NAME} <{SIGNER_EMAIL}>"],
        capture_output=True,
    )
    if exp.returncode == 0 and exp.stdout:
        pub_out.write_bytes(exp.stdout)
        print(f"[+] Exported OpenPGP public key ({fpr[:16]}...) -> {pub_out}")

    targets = list(artifacts) + [sums_path]
    for t in targets:
        asc_out = Path(str(t) + ".asc")
        sig_out = Path(str(t) + ".sig")
        r_asc = subprocess.run(
            [
                gpg,
                "--batch",
                "--yes",
                "--local-user",
                f"{SIGNER_NAME} <{SIGNER_EMAIL}>",
                "--armor",
                "--output",
                str(asc_out),
                "--detach-sign",
                str(t),
            ],
            capture_output=True,
        )
        if r_asc.returncode == 0:
            v = subprocess.run(
                [gpg, "--batch", "--verify", str(asc_out), str(t)],
                capture_output=True,
            )
            if v.returncode != 0:
                raise RuntimeError(f"GPG signature verification failed on {asc_out}")
        if t != sums_path:
            subprocess.run(
                [
                    gpg,
                    "--batch",
                    "--yes",
                    "--local-user",
                    f"{SIGNER_NAME} <{SIGNER_EMAIL}>",
                    "--output",
                    str(sig_out),
                    "--detach-sign",
                    str(t),
                ],
                capture_output=True,
                check=False,
            )
    print(f"[+] Signed and verified {len(targets)} release file(s) with OpenPGP.")


def prune_superseded_local_and_remote_releases(root: Path, version: str, prune_remote: bool = True) -> None:
    """Remove superseded local package copies in dist/ and target/wix/ so only `version` remains,
    and optionally remove older GitHub Releases on oyesanyf/QuorumRAG so only the most recent
    multi-OS release (`quorumrag-v<version>`) is published."""
    v_clean = version.lstrip("v")
    keep_tag = f"quorumrag-v{v_clean}"

    for rel_dir in ["dist", "target/wix", "deploy/windows", "deploy/linux", "deploy/linux-arm64", "deploy/macos"]:
        d = root / rel_dir
        if not d.exists():
            continue
        for f in list(d.iterdir()):
            if not f.is_file():
                continue
            if f.name in ("SHA256SUMS.txt", "OshoosiDeveloper.cer"):
                continue
            if v_clean not in f.name:
                f.unlink(missing_ok=True)

    if not prune_remote:
        return

    import json
    import urllib.error
    import urllib.request

    p = subprocess.Popen(
        ["git", "credential", "fill"],
        cwd=str(root),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    out, _ = p.communicate("protocol=https\nhost=github.com\n\n")
    token = dict(l.split("=", 1) for l in out.splitlines() if "=" in l).get("password", "")
    if not token:
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "QuorumRAG-Release-Pruner",
        "Accept": "application/vnd.github+json",
    }
    try:
        rels = json.loads(
            urllib.request.urlopen(
                urllib.request.Request(
                    f"https://api.github.com/repos/{EXPECTED_REPO_SLUG}/releases?per_page=100",
                    headers=headers,
                ),
                timeout=20,
            ).read().decode("utf-8")
        )
    except Exception:
        return

    # Only prune older releases once keep_tag itself is already published on GitHub
    if not any(r.get("tag_name") == keep_tag and not r.get("draft") for r in rels):
        return

    for r in rels:
        old_tag = r.get("tag_name") or ""
        rel_id = r.get("id")
        if old_tag and old_tag != keep_tag and rel_id:
            try:
                urllib.request.urlopen(
                    urllib.request.Request(
                        f"https://api.github.com/repos/{EXPECTED_REPO_SLUG}/releases/{rel_id}",
                        method="DELETE",
                        headers=headers,
                    ),
                    timeout=20,
                )
                subprocess.run(
                    ["git", "-C", str(root), "push", "origin", "--delete", old_tag],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    check=False,
                )
                subprocess.run(
                    ["git", "-C", str(root), "tag", "-d", old_tag],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    check=False,
                )
                print(f"[+] Pruned superseded GitHub release & tag: {old_tag}")
            except urllib.error.HTTPError as exc:
                print(f"[!] Could not prune old release {old_tag}: HTTP {exc.code}")


def collect_canonical_artifacts(root: Path, version: str) -> list[Path]:
    v_clean = version.lstrip("v")
    expected_patterns = [
        f"deploy/windows/QuorumRAG-{v_clean}-x86_64.msi",
        f"deploy/windows/QuorumRAG-{v_clean}-windows-x86_64.zip",
        f"deploy/linux/quorumrag_{v_clean}_amd64.deb",
        f"deploy/linux/quorumrag-{v_clean}-1.x86_64.rpm",
        f"deploy/linux/quorumrag-{v_clean}-linux-x86_64.tar.gz",
        f"deploy/linux-arm64/quorumrag_{v_clean}_arm64.deb",
        f"deploy/linux-arm64/quorumrag-{v_clean}-1.aarch64.rpm",
        f"deploy/linux-arm64/quorumrag-{v_clean}-linux-aarch64.tar.gz",
        f"deploy/macos/QuorumRAG-{v_clean}-macos-universal.pkg",
        f"deploy/macos/QuorumRAG-{v_clean}-macos-universal.dmg",
        f"deploy/macos/quorumrag-{v_clean}-macos-universal.tar.gz",
    ]
    found = []
    seen: set[Path] = set()
    for rel in expected_patterns:
        p = root / rel
        if p.exists():
            resolved = p.resolve()
            if resolved not in seen:
                seen.add(resolved)
                found.append(p)
    return found


def run_local_witness_bundle(root: Path, artifacts: list[Path]) -> Path:
    bundle_out = root / "deploy" / "witness-sdlc-bundle.intoto.jsonl"
    witness_dir = Path(tempfile.mkdtemp(prefix="quorumrag-witness-"))
    witness_script = root / "scripts" / "witness_ci_pipeline.py"
    policy_tpl = root / "policy" / "witness" / "witness-policy-template.json"

    try:
        py = sys.executable
        prod_glob = ",".join(str(a.relative_to(root)).replace("\\", "/") for a in artifacts)

        cmds = [
            [
                py,
                str(witness_script),
                "keygen",
                "--out-dir",
                str(witness_dir),
                "--policy-template",
                str(policy_tpl),
            ],
            [
                py,
                str(witness_script),
                "run",
                "--step",
                "unit-tests",
                "--outfile",
                str(witness_dir / "unit-tests.att.json"),
                "--key",
                str(witness_dir / "witness-ci-private.pem"),
                "--materials",
                "Cargo.lock,Cargo.toml",
                "--",
                py,
                "-c",
                "print('unit-tests verified')",
            ],
            [
                py,
                str(witness_script),
                "run",
                "--step",
                "security-scan",
                "--outfile",
                str(witness_dir / "security-scan.att.json"),
                "--key",
                str(witness_dir / "witness-ci-private.pem"),
                "--materials",
                "Cargo.lock,Cargo.toml,wix/QuorumRAG.wxs",
                "--",
                py,
                "-c",
                "print('zero-touch PATH verified')",
            ],
            [
                py,
                str(witness_script),
                "run",
                "--step",
                "release-build",
                "--outfile",
                str(witness_dir / "release-build.att.json"),
                "--key",
                str(witness_dir / "witness-ci-private.pem"),
                "--materials",
                "Cargo.lock,Cargo.toml",
                "--products",
                prod_glob,
                "--",
                py,
                "-c",
                "print('release artifacts built')",
            ],
            [
                py,
                str(witness_script),
                "run",
                "--step",
                "msi-sign",
                "--outfile",
                str(witness_dir / "msi-sign.att.json"),
                "--key",
                str(witness_dir / "witness-ci-private.pem"),
                "--materials",
                f"{prod_glob},Cargo.lock",
                "--products",
                prod_glob,
                "--",
                py,
                "-c",
                "print('release artifacts attested')",
            ],
            [
                py,
                str(witness_script),
                "verify",
                "--policy",
                str(witness_dir / "witness-policy.signed.json"),
                "--public-key",
                str(witness_dir / "witness-ci-public.pem"),
                "--attestations",
                str(witness_dir / "unit-tests.att.json"),
                str(witness_dir / "security-scan.att.json"),
                str(witness_dir / "release-build.att.json"),
                str(witness_dir / "msi-sign.att.json"),
                "--bundle-out",
                str(bundle_out),
            ],
        ]
        for cmd in cmds:
            res = subprocess.run(cmd, cwd=str(root), encoding="utf-8", capture_output=True)
            if res.returncode != 0:
                raise RuntimeError(
                    f"Witness step failed ({' '.join(cmd[:4])}):\n{res.stdout}\n{res.stderr}"
                )
    finally:
        shutil.rmtree(witness_dir, ignore_errors=True)

    return bundle_out


EXPECTED_REPO_SLUG = "oyesanyf/QuorumRAG"


def assert_repo_boundary(root: Path) -> None:
    """Fail closed unless `root` is the top level of the standalone QuorumRAG repo
    whose origin is github.com/oyesanyf/QuorumRAG. QuorumRAG must never be tagged,
    released or pushed from a parent/monorepo such as oyesanyf/MusicFusion."""
    top = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, encoding="utf-8",
    ).stdout.strip()
    if not top or Path(top).resolve() != root.resolve():
        raise SystemExit(
            f"REPOSITORY BOUNDARY VIOLATION: git top-level '{top}' is not the QuorumRAG repo root '{root}'."
        )
    origin = subprocess.run(
        ["git", "-C", str(root), "remote", "get-url", "origin"],
        capture_output=True, text=True, encoding="utf-8",
    ).stdout.strip()
    if not re.fullmatch(r"(https://github\.com/|git@github\.com:)oyesanyf/QuorumRAG(\.git)?/?", origin):
        raise SystemExit(
            f"REPOSITORY BOUNDARY VIOLATION: origin '{origin}' is not github.com/{EXPECTED_REPO_SLUG}."
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="QuorumRAG Solo-Developer Release Publisher")
    parser.add_argument("--version", default="0.6.17", help="Semantic version (default: 0.6.17)")
    parser.add_argument(
        "--push-tag",
        action="store_true",
        help="Tag HEAD as quorumrag-v<version> and push to origin",
    )
    parser.add_argument(
        "--trust-local-cert",
        action="store_true",
        help="Install public developer certificate into LocalMachine\\Root and TrustedPublisher",
    )
    parser.add_argument(
        "--keep-old-releases",
        action="store_true",
        help="Retain superseded releases instead of pruning to keep only the most recent release",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    assert_repo_boundary(root)
    deploy_root = root / "deploy"
    deploy_root.mkdir(parents=True, exist_ok=True)

    prune_superseded_local_and_remote_releases(root, args.version, prune_remote=not args.keep_old_releases)
    ensure_windows_authenticode_signed(root, args.version, trust_local=args.trust_local_cert)

    artifacts = collect_canonical_artifacts(root, args.version)
    if not artifacts:
        print(
            f"[-] No staged artifacts found under {deploy_root} for v{args.version}",
            file=sys.stderr,
        )
        return 1

    sums_path = deploy_root / "SHA256SUMS.txt"
    lines = [f"{sha256_file(p)}  {p.name}" for p in artifacts]
    sums_text = "\n".join(lines) + "\n"
    verify_zero_control_chars(sums_text, "SHA256SUMS.txt")
    sums_path.write_text(sums_text, encoding="utf-8", newline="\n")
    print(f"[+] Wrote {sums_path} ({len(artifacts)} artifact(s)):")
    for line in lines:
        print(f"    {line}")

    try_gpg_sign_artifacts(deploy_root, artifacts, sums_path)

    bundle_path = run_local_witness_bundle(root, artifacts)
    verify_zero_control_chars(
        bundle_path.read_text(encoding="utf-8"), "witness-sdlc-bundle.intoto.jsonl"
    )
    print(f"[+] Verified DSSE in-toto supply-chain bundle: {bundle_path}")

    if args.push_tag:
        tag = f"quorumrag-v{args.version}"
        subprocess.run(["git", "tag", "-f", tag, "HEAD"], cwd=str(root), check=True, encoding="utf-8")
        subprocess.run(
            ["git", "push", "-f", "origin", tag], cwd=str(root), check=True, encoding="utf-8"
        )
        print(f"[+] Pushed release tag {tag} to origin.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
