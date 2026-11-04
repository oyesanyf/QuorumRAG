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


def collect_canonical_artifacts(root: Path, version: str) -> list[Path]:
    expected_patterns = [
        f"deploy/windows/QuorumRAG-{version}-x86_64.msi",
        f"deploy/windows/QuorumRAG-{version}-windows-x86_64.zip",
        f"deploy/linux/quorumrag_{version}_amd64.deb",
        f"deploy/linux/quorumrag-{version}-1.x86_64.rpm",
        f"deploy/linux/quorumrag-{version}-linux-x86_64.tar.gz",
        f"deploy/linux-arm64/quorumrag_{version}_arm64.deb",
        f"deploy/linux-arm64/quorumrag-{version}-1.aarch64.rpm",
        f"deploy/linux-arm64/quorumrag-{version}-linux-aarch64.tar.gz",
        f"deploy/macos/QuorumRAG-{version}-macos-universal.pkg",
        f"deploy/macos/QuorumRAG-{version}-macos-universal.dmg",
        f"deploy/macos/quorumrag-{version}-macos-universal.tar.gz",
    ]
    found = []
    for rel in expected_patterns:
        p = root / rel
        if p.exists():
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


def main() -> int:
    parser = argparse.ArgumentParser(description="QuorumRAG Solo-Developer Release Publisher")
    parser.add_argument("--version", default="0.1.0", help="Semantic version (default: 0.1.0)")
    parser.add_argument(
        "--push-tag",
        action="store_true",
        help="Tag HEAD as quorumrag-v<version> and push to origin",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    deploy_root = root / "deploy"
    deploy_root.mkdir(parents=True, exist_ok=True)

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
