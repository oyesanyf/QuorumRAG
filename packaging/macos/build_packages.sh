#!/usr/bin/env bash
set -euo pipefail

# QuorumRAG macOS Packaging Script
# Generates macOS native installer (.pkg), disk image (.dmg), and portable (.tar.gz) packages.

BINARY_PATH="${1:-target/release/quorumrag}"
VERSION="${2:-0.1.0}"
INPUT_ARCH="${3:-universal}"
DIST_DIR="${4:-deploy/macos}"
PACKAGE_NAME="${5:-quorumrag}"

case "$INPUT_ARCH" in
    aarch64|arm64)
        MACOS_ARCH="arm64"
        ;;
    x86_64|amd64)
        MACOS_ARCH="x86_64"
        ;;
    *)
        MACOS_ARCH="universal"
        ;;
esac

echo "[*] Packaging QuorumRAG v${VERSION} for macOS (${MACOS_ARCH})"
echo "[*] Binary source: ${BINARY_PATH}"

if [ ! -f "$BINARY_PATH" ]; then
    echo "[-] Error: Binary not found at ${BINARY_PATH}" >&2
    exit 1
fi

BINARY_PATH="$(cd "$(dirname "${BINARY_PATH}")" && pwd)/$(basename "${BINARY_PATH}")"
mkdir -p "${DIST_DIR}"
DIST_DIR="$(cd "${DIST_DIR}" && pwd)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLIST_FILE="${SCRIPT_DIR}/dev.quorumrag.daemon.plist"
INSTALL_SH="${SCRIPT_DIR}/install.sh"
UNINSTALL_SH="${SCRIPT_DIR}/uninstall.sh"

# Prune stale macOS artifacts for this arch
rm -f "${DIST_DIR}/QuorumRAG-"*"-macos-${MACOS_ARCH}.pkg"* \
      "${DIST_DIR}/QuorumRAG-"*"-macos-${MACOS_ARCH}.dmg"* \
      "${DIST_DIR}/${PACKAGE_NAME}-"*"-macos-${MACOS_ARCH}.tar.gz"* 2>/dev/null || true

# ---------------------------------------------------------
# 1. Portable macOS Tarball (.tar.gz)
# ---------------------------------------------------------
TAR_TMP="$(mktemp -d)"
TAR_STAGING="${TAR_TMP}/${PACKAGE_NAME}-${VERSION}-macos-${MACOS_ARCH}"
mkdir -p "${TAR_STAGING}"

cp -f "${BINARY_PATH}" "${TAR_STAGING}/quorumrag"
chmod 755 "${TAR_STAGING}/quorumrag"
cp -f "${PLIST_FILE}" "${TAR_STAGING}/dev.quorumrag.daemon.plist"
chmod 644 "${TAR_STAGING}/dev.quorumrag.daemon.plist"
cp -f "${INSTALL_SH}" "${TAR_STAGING}/install.sh"
chmod 755 "${TAR_STAGING}/install.sh"
cp -f "${UNINSTALL_SH}" "${TAR_STAGING}/uninstall.sh"
chmod 755 "${TAR_STAGING}/uninstall.sh"

TAR_OUT="${DIST_DIR}/${PACKAGE_NAME}-${VERSION}-macos-${MACOS_ARCH}.tar.gz"
tar -czf "${TAR_OUT}" -C "${TAR_TMP}" "$(basename "${TAR_STAGING}")"
echo "[+] Created: ${TAR_OUT}"
rm -rf "${TAR_TMP}"

# ---------------------------------------------------------
# 2. Construct QuorumRAG.app Bundle (used by both .dmg and .pkg)
# ---------------------------------------------------------
APP_TMP="$(mktemp -d)"
APP_BUNDLE="${APP_TMP}/QuorumRAG.app"
mkdir -p "${APP_BUNDLE}/Contents/MacOS" "${APP_BUNDLE}/Contents/Resources"

cp -f "${BINARY_PATH}" "${APP_BUNDLE}/Contents/MacOS/quorumrag-bin"
chmod 755 "${APP_BUNDLE}/Contents/MacOS/quorumrag-bin"

cat <<'EOF' > "${APP_BUNDLE}/Contents/MacOS/QuorumRAG"
#!/usr/bin/env bash
# If the QuorumRAG LaunchDaemon is installed (pkg / install.sh), just open the Web UI.
# Otherwise (drag-installed from the .dmg) run a per-user instance, which opens the browser itself.
set -euo pipefail
APP_MACOS_DIR="$(cd "$(dirname "$0")" && pwd)"
URL="http://127.0.0.1:3031/"
HEALTH="http://127.0.0.1:3031/api/health"
if curl -fsS -m 2 "${HEALTH}" >/dev/null 2>&1; then
    exec open "${URL}"
fi
if [ -f /Library/LaunchDaemons/dev.quorumrag.daemon.plist ]; then
    for _ in $(seq 1 60); do
        curl -fsS -m 2 "${HEALTH}" >/dev/null 2>&1 && break
        sleep 1
    done
    exec open "${URL}"
fi
DATA_DIR="${HOME}/Library/Application Support/QuorumRAG/data"
mkdir -p "${DATA_DIR}"
exec "${APP_MACOS_DIR}/quorumrag-bin" --host 0.0.0.0 --port 3031 --p2p-port 3032 --data-dir "${DATA_DIR}"
EOF
chmod 755 "${APP_BUNDLE}/Contents/MacOS/QuorumRAG"

cat <<EOF > "${APP_BUNDLE}/Contents/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDisplayName</key>
    <string>QuorumRAG</string>
    <key>CFBundleExecutable</key>
    <string>QuorumRAG</string>
    <key>CFBundleIdentifier</key>
    <string>dev.quorumrag.app</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>QuorumRAG</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

# ---------------------------------------------------------
# 3. Native Apple .pkg & .dmg (when running on Darwin / macOS runner)
# ---------------------------------------------------------
if [ "$(uname -s)" = "Darwin" ] && command -v pkgbuild >/dev/null 2>&1; then
    echo "[*] Building native macOS .pkg installer..."
    PKG_TMP="$(mktemp -d)"
    PKG_ROOT="${PKG_TMP}/root"
    PKG_SCRIPTS="${PKG_TMP}/scripts"
    mkdir -p "${PKG_ROOT}/usr/local/bin" \
             "${PKG_ROOT}/usr/local/share/quorumrag" \
             "${PKG_ROOT}/Library/LaunchDaemons" \
             "${PKG_ROOT}/Applications" \
             "${PKG_SCRIPTS}"

    install -m 755 "${BINARY_PATH}" "${PKG_ROOT}/usr/local/bin/quorumrag"
    install -m 644 "${PLIST_FILE}" "${PKG_ROOT}/Library/LaunchDaemons/dev.quorumrag.daemon.plist"
    install -m 755 "${UNINSTALL_SH}" "${PKG_ROOT}/usr/local/share/quorumrag/uninstall.sh"
    cp -R "${APP_BUNDLE}" "${PKG_ROOT}/Applications/QuorumRAG.app"

    cat <<'EOF' > "${PKG_SCRIPTS}/preinstall"
#!/bin/sh
# Stop a running daemon before the payload replaces the binary (upgrade).
launchctl bootout system/dev.quorumrag.daemon 2>/dev/null || true
exit 0
EOF
    chmod 755 "${PKG_SCRIPTS}/preinstall"

    cat <<'EOF' > "${PKG_SCRIPTS}/postinstall"
#!/bin/sh
# Register + start the always-on LaunchDaemon, then open the Web UI for the console user.
LABEL="dev.quorumrag.daemon"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
URL="http://127.0.0.1:3031/"
HEALTH="http://127.0.0.1:3031/api/health"
mkdir -p "/Library/Application Support/QuorumRAG/data" \
         "/Library/Application Support/QuorumRAG/docs" \
         "/Library/Logs/QuorumRAG"
chmod 755 "/Library/Application Support/QuorumRAG" "/Library/Logs/QuorumRAG"
chown root:wheel "${PLIST}"
chmod 644 "${PLIST}"
launchctl enable "system/${LABEL}" 2>/dev/null || true
launchctl bootstrap system "${PLIST}" 2>/dev/null || true
launchctl kickstart -k "system/${LABEL}" 2>/dev/null || true
if [ "${COMMAND_LINE_INSTALL:-0}" != "1" ] || [ "${QUORUMRAG_OPEN_BROWSER:-0}" = "1" ]; then
    (
        i=0
        while [ $i -lt 90 ]; do
            curl -fsS -m 2 "${HEALTH}" >/dev/null 2>&1 && break
            i=$((i + 1)); sleep 1
        done
        CONSOLE_USER="$(stat -f%Su /dev/console 2>/dev/null)"
        if [ -n "${CONSOLE_USER}" ] && [ "${CONSOLE_USER}" != "root" ] && [ "${CONSOLE_USER}" != "loginwindow" ]; then
            launchctl asuser "$(id -u "${CONSOLE_USER}")" sudo -u "${CONSOLE_USER}" open "${URL}" 2>/dev/null || true
        fi
    ) >/dev/null 2>&1 &
fi
exit 0
EOF
    chmod 755 "${PKG_SCRIPTS}/postinstall"

    COMP_PKG="${PKG_TMP}/QuorumRAG-component.pkg"
    PKG_OUT="${DIST_DIR}/QuorumRAG-${VERSION}-macos-${MACOS_ARCH}.pkg"
    pkgbuild --root "${PKG_ROOT}" \
             --scripts "${PKG_SCRIPTS}" \
             --identifier "dev.quorumrag.pkg" \
             --version "${VERSION}" \
             --install-location "/" \
             "${COMP_PKG}"

    if command -v productbuild >/dev/null 2>&1; then
        productbuild --package "${COMP_PKG}" "${PKG_OUT}"
    else
        cp -f "${COMP_PKG}" "${PKG_OUT}"
    fi
    echo "[+] Created: ${PKG_OUT}"
    rm -rf "${PKG_TMP}"
else
    echo "[!] Not on Darwin (pkgbuild unavailable locally); .pkg is built natively on macOS CI runner."
fi

if [ "$(uname -s)" = "Darwin" ] && command -v hdiutil >/dev/null 2>&1; then
    echo "[*] Building native macOS .dmg disk image..."
    DMG_STAGE="$(mktemp -d)"
    cp -R "${APP_BUNDLE}" "${DMG_STAGE}/QuorumRAG.app"
    ln -s /Applications "${DMG_STAGE}/Applications"
    DMG_OUT="${DIST_DIR}/QuorumRAG-${VERSION}-macos-${MACOS_ARCH}.dmg"
    hdiutil create -volname "QuorumRAG ${VERSION}" \
                   -srcfolder "${DMG_STAGE}" \
                   -ov -format UDZO \
                   "${DMG_OUT}"
    echo "[+] Created: ${DMG_OUT}"
    rm -rf "${DMG_STAGE}"
else
    APP_TAR_OUT="${DIST_DIR}/QuorumRAG-${VERSION}-macos-${MACOS_ARCH}.app.tar.gz"
    tar -czf "${APP_TAR_OUT}" -C "${APP_TMP}" "QuorumRAG.app"
    echo "[+] Staged QuorumRAG.app bundle archive: ${APP_TAR_OUT} (native .dmg built via hdiutil on macOS CI runner)"
fi

rm -rf "${APP_TMP}"
echo "[+] macOS packaging complete. Artifacts in ${DIST_DIR}:"
ls -lh "${DIST_DIR}"
