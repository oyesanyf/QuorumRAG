#!/usr/bin/env bash
set -euo pipefail

# QuorumRAG Linux Packaging Script
# Generates Debian (.deb), RedHat (.rpm), and portable (.tar.gz) packages for Linux deployments.

BINARY_PATH="${1:-target/release/quorumrag}"
VERSION="${2:-0.1.0}"
INPUT_ARCH="${3:-amd64}"
DIST_DIR="${4:-deploy/linux}"
PACKAGE_NAME="${5:-quorumrag}"

case "$INPUT_ARCH" in
    x86_64|amd64)
        DEB_ARCH="amd64"
        RPM_ARCH="x86_64"
        ;;
    aarch64|arm64)
        DEB_ARCH="arm64"
        RPM_ARCH="aarch64"
        ;;
    *)
        DEB_ARCH="$INPUT_ARCH"
        RPM_ARCH="$INPUT_ARCH"
        ;;
esac

echo "[*] Packaging QuorumRAG v${VERSION} (${DEB_ARCH} / ${RPM_ARCH})"
echo "[*] Binary source: ${BINARY_PATH}"

if [ ! -f "$BINARY_PATH" ]; then
    echo "[-] Error: Binary not found at ${BINARY_PATH}" >&2
    exit 1
fi

BINARY_PATH="$(cd "$(dirname "${BINARY_PATH}")" && pwd)/$(basename "${BINARY_PATH}")"
mkdir -p "${DIST_DIR}"
DIST_DIR="$(cd "${DIST_DIR}" && pwd)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SERVICE_FILE="${SCRIPT_DIR}/quorumrag.service"
CTL_FILE="${SCRIPT_DIR}/quorumrag-ctl.sh"
DESKTOP_FILE="${SCRIPT_DIR}/quorumrag.desktop"

# Prune stale duplicate format artifacts for this architecture
rm -f "${DIST_DIR}/${PACKAGE_NAME}_"*"_${DEB_ARCH}.deb"* \
      "${DIST_DIR}/${PACKAGE_NAME}-"*".${RPM_ARCH}.rpm"* \
      "${DIST_DIR}/${PACKAGE_NAME}-"*"-linux-${RPM_ARCH}.tar.gz"* 2>/dev/null || true

# ---------------------------------------------------------
# 1. Portable Tarball (.tar.gz)
# ---------------------------------------------------------
echo "[*] Building portable tarball..."
TAR_TMP="$(mktemp -d)"
TAR_STAGING="${TAR_TMP}/${PACKAGE_NAME}-${VERSION}-linux-${RPM_ARCH}"
mkdir -p "${TAR_STAGING}"

cp -f "${BINARY_PATH}" "${TAR_STAGING}/quorumrag"
chmod 755 "${TAR_STAGING}/quorumrag"
cp -f "${SERVICE_FILE}" "${TAR_STAGING}/quorumrag.service"
chmod 644 "${TAR_STAGING}/quorumrag.service"
cp -f "${CTL_FILE}" "${TAR_STAGING}/quorumrag-ctl"
chmod 755 "${TAR_STAGING}/quorumrag-ctl"
cp -f "${DESKTOP_FILE}" "${TAR_STAGING}/quorumrag.desktop"
chmod 644 "${TAR_STAGING}/quorumrag.desktop"

cat <<'EOF' > "${TAR_STAGING}/install.sh"
#!/usr/bin/env bash
# Installs QuorumRAG as an always-on systemd service and opens the Web UI.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
    exec sudo "$0" "$@"
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p /usr/bin /lib/systemd/system /usr/lib/quorumrag /usr/share/applications \
         /var/lib/quorumrag/data /var/lib/quorumrag/docs /var/log/quorumrag
install -m 755 "${SCRIPT_DIR}/quorumrag" /usr/bin/quorumrag
install -m 644 "${SCRIPT_DIR}/quorumrag.service" /lib/systemd/system/quorumrag.service
install -m 755 "${SCRIPT_DIR}/quorumrag-ctl" /usr/lib/quorumrag/quorumrag-ctl
install -m 644 "${SCRIPT_DIR}/quorumrag.desktop" /usr/share/applications/quorumrag.desktop
/usr/lib/quorumrag/quorumrag-ctl post-install
echo "[+] Installed /usr/bin/quorumrag and quorumrag.service (Zero-Touch PATH)."
echo "    Uninstall completely: sudo ./uninstall.sh [--purge]"
EOF
chmod 755 "${TAR_STAGING}/install.sh"

cat <<'EOF' > "${TAR_STAGING}/uninstall.sh"
#!/usr/bin/env bash
# Stops and deletes quorumrag.service and removes all installed files.
#   --purge   also delete /var/lib/quorumrag (index) and /var/log/quorumrag
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
    exec sudo "$0" "$@"
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -x /usr/lib/quorumrag/quorumrag-ctl ]; then
    exec sh /usr/lib/quorumrag/quorumrag-ctl uninstall "$@"
fi
exec sh "${SCRIPT_DIR}/quorumrag-ctl" uninstall "$@"
EOF
chmod 755 "${TAR_STAGING}/uninstall.sh"

TAR_OUT="${DIST_DIR}/${PACKAGE_NAME}-${VERSION}-linux-${RPM_ARCH}.tar.gz"
tar -czf "${TAR_OUT}" -C "${TAR_TMP}" "$(basename "${TAR_STAGING}")"
echo "[+] Created: ${TAR_OUT}"
rm -rf "${TAR_TMP}"

# ---------------------------------------------------------
# 2. Debian Package (.deb)
# ---------------------------------------------------------
echo "[*] Building Debian package..."
DEB_TMP="$(mktemp -d)"
DEB_STAGING="${DEB_TMP}/deb_build"
mkdir -p "${DEB_STAGING}/DEBIAN"
mkdir -p "${DEB_STAGING}/usr/bin"
mkdir -p "${DEB_STAGING}/lib/systemd/system"
mkdir -p "${DEB_STAGING}/usr/lib/quorumrag"
mkdir -p "${DEB_STAGING}/usr/share/applications"
mkdir -p "${DEB_STAGING}/var/lib/quorumrag/data"
mkdir -p "${DEB_STAGING}/var/lib/quorumrag/docs"

cat <<EOF > "${DEB_STAGING}/DEBIAN/control"
Package: ${PACKAGE_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: Oshoosi Security Team <security@oshoosiclaw.dev>
Homepage: https://github.com/oyesanyf/MusicFusion
Recommends: curl, xdg-utils
Description: QuorumRAG Local-First P2P Agentic RAG Daemon and Web UI
 Self-contained local-first peer-to-peer Retrieval-Augmented Generation
 daemon with embedded LanceDB/Tantivy hybrid search, Ed25519 mesh auth,
 multi-turn MMR deduplication, and embedded ChatGPT-style Web UI.
EOF

cat <<'EOF' > "${DEB_STAGING}/DEBIAN/postinst"
#!/bin/sh
# Enable + start quorumrag.service at boot and now, then open the Web UI for the desktop user.
set -e
if [ "$1" = "configure" ]; then
    sh /usr/lib/quorumrag/quorumrag-ctl post-install || true
fi
exit 0
EOF
chmod 755 "${DEB_STAGING}/DEBIAN/postinst"

cat <<'EOF' > "${DEB_STAGING}/DEBIAN/prerm"
#!/bin/sh
# Stop the service before removal or upgrade; disable it on removal.
set -e
case "$1" in
    remove|deconfigure)
        sh /usr/lib/quorumrag/quorumrag-ctl pre-remove || true ;;
    upgrade|failed-upgrade)
        if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
            systemctl stop quorumrag.service >/dev/null 2>&1 || true
        fi ;;
esac
exit 0
EOF
chmod 755 "${DEB_STAGING}/DEBIAN/prerm"

cat <<'EOF' > "${DEB_STAGING}/DEBIAN/postrm"
#!/bin/sh
# remove: unit file is gone -> reload systemd. purge: also delete index data and logs.
set -e
case "$1" in
    remove|purge)
        if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload >/dev/null 2>&1 || true
            systemctl reset-failed quorumrag.service >/dev/null 2>&1 || true
        fi ;;
esac
if [ "$1" = "purge" ]; then
    rm -rf /var/lib/quorumrag /var/log/quorumrag
fi
exit 0
EOF
chmod 755 "${DEB_STAGING}/DEBIAN/postrm"

cp -f "${BINARY_PATH}" "${DEB_STAGING}/usr/bin/quorumrag"
chmod 755 "${DEB_STAGING}/usr/bin/quorumrag"
cp -f "${SERVICE_FILE}" "${DEB_STAGING}/lib/systemd/system/quorumrag.service"
chmod 644 "${DEB_STAGING}/lib/systemd/system/quorumrag.service"
cp -f "${CTL_FILE}" "${DEB_STAGING}/usr/lib/quorumrag/quorumrag-ctl"
chmod 755 "${DEB_STAGING}/usr/lib/quorumrag/quorumrag-ctl"
cp -f "${DESKTOP_FILE}" "${DEB_STAGING}/usr/share/applications/quorumrag.desktop"
chmod 644 "${DEB_STAGING}/usr/share/applications/quorumrag.desktop"

DEB_OUT="${DIST_DIR}/${PACKAGE_NAME}_${VERSION}_${DEB_ARCH}.deb"
if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb --build --root-owner-group "${DEB_STAGING}" "${DEB_OUT}"
    echo "[+] Created: ${DEB_OUT}"
else
    echo "[!] dpkg-deb not found; constructing standard Debian 2.0 ar archive..."
    (
        cd "${DEB_STAGING}"
        printf "2.0\n" > debian-binary
        tar -czf control.tar.gz -C DEBIAN control postinst prerm postrm
        tar -czf data.tar.gz usr lib var
        if command -v ar >/dev/null 2>&1; then
            ar -rc "${DEB_OUT}" debian-binary control.tar.gz data.tar.gz
        else
            PY_BIN="python3"
            command -v python3 >/dev/null 2>&1 || PY_BIN="python"
            "${PY_BIN}" - "${DEB_OUT}" debian-binary control.tar.gz data.tar.gz <<'PYEOF'
import os, sys, time
out_path = sys.argv[1]
members = sys.argv[2:]
with open(out_path, "wb") as out:
    out.write(b"!<arch>\n")
    mtime = str(int(time.time())).encode("ascii")
    for m in members:
        data = open(m, "rb").read()
        name = os.path.basename(m).encode("ascii")
        hdr = (
            name.ljust(16, b" ")
            + mtime.ljust(12, b" ")
            + b"0     "
            + b"0     "
            + b"100644  "
            + str(len(data)).encode("ascii").ljust(10, b" ")
            + b"`\n"
        )
        out.write(hdr)
        out.write(data)
        if len(data) % 2 == 1:
            out.write(b"\n")
PYEOF
        fi
    )
    echo "[+] Created: ${DEB_OUT} (portable ar builder)"
fi
rm -rf "${DEB_TMP}"

# ---------------------------------------------------------
# 3. RedHat Package (.rpm)
# ---------------------------------------------------------
RPM_OUT="${DIST_DIR}/${PACKAGE_NAME}-${VERSION}-1.${RPM_ARCH}.rpm"
if command -v rpmbuild >/dev/null 2>&1; then
    echo "[*] Building RPM package with rpmbuild..."
    RPM_TMP="$(mktemp -d)"
    RPM_TOP="${RPM_TMP}/rpmtop"
    mkdir -p "${RPM_TOP}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS,BUILDROOT}

    cat <<EOF > "${RPM_TOP}/SPECS/${PACKAGE_NAME}.spec"
Name:           ${PACKAGE_NAME}
Version:        ${VERSION}
Release:        1
Summary:        QuorumRAG Local-First P2P Agentic RAG Daemon and Web UI
License:        MIT OR Apache-2.0
URL:            https://github.com/oyesanyf/MusicFusion
AutoReqProv:    no
%define __strip /bin/true
%define _build_id_links none
%global __os_install_post %{nil}

%description
Self-contained local-first peer-to-peer Retrieval-Augmented Generation
daemon with embedded LanceDB/Tantivy hybrid search and Web UI.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/lib/systemd/system
mkdir -p %{buildroot}/usr/lib/quorumrag
mkdir -p %{buildroot}/usr/share/applications
mkdir -p %{buildroot}/var/lib/quorumrag/data
mkdir -p %{buildroot}/var/lib/quorumrag/docs

install -m 755 "${BINARY_PATH}" %{buildroot}/usr/bin/quorumrag
install -m 644 "${SERVICE_FILE}" %{buildroot}/usr/lib/systemd/system/quorumrag.service
install -m 755 "${CTL_FILE}" %{buildroot}/usr/lib/quorumrag/quorumrag-ctl
install -m 644 "${DESKTOP_FILE}" %{buildroot}/usr/share/applications/quorumrag.desktop

%post
# Fresh install and upgrade: enable + (re)start the service, then open the Web UI.
sh /usr/lib/quorumrag/quorumrag-ctl post-install || :

%preun
# Final erase (not upgrade): stop + disable the service.
if [ \$1 -eq 0 ]; then
    sh /usr/lib/quorumrag/quorumrag-ctl pre-remove || :
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
if [ \$1 -eq 0 ]; then
    systemctl reset-failed quorumrag.service >/dev/null 2>&1 || :
    # Logs are always removed on erase; the index is removed only when QUORUMRAG_PURGE=1
    # (or use: /usr/lib/quorumrag/quorumrag-ctl uninstall --purge before erasing).
    rm -rf /var/log/quorumrag
    if [ "\${QUORUMRAG_PURGE:-0}" = "1" ]; then
        rm -rf /var/lib/quorumrag
    fi
fi

%files
/usr/bin/quorumrag
/usr/lib/systemd/system/quorumrag.service
%dir /usr/lib/quorumrag
/usr/lib/quorumrag/quorumrag-ctl
/usr/share/applications/quorumrag.desktop
%dir /var/lib/quorumrag
%dir /var/lib/quorumrag/data
%dir /var/lib/quorumrag/docs

%changelog
* Tue Nov 03 2026 Oshoosi Security Team <security@oshoosiclaw.dev> - ${VERSION}-1
- QuorumRAG ${VERSION} native RPM release package.
EOF

    rpmbuild --define "_topdir ${RPM_TOP}" --target "${RPM_ARCH}" -bb "${RPM_TOP}/SPECS/${PACKAGE_NAME}.spec"
    FOUND_RPM="$(find "${RPM_TOP}/RPMS" -type f -name "*.rpm" | head -n 1)"
    cp -f "${FOUND_RPM}" "${RPM_OUT}"
    echo "[+] Created: ${RPM_OUT}"
    rm -rf "${RPM_TMP}"
else
    echo "[!] rpmbuild not installed on this host; skipping local .rpm build (built natively on Linux CI runner)."
fi

echo "[+] Linux packaging complete. Artifacts in ${DIST_DIR}:"
ls -lh "${DIST_DIR}"
