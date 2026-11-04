#!/usr/bin/env bash
# QuorumRAG macOS installer (tarball): installs the always-on LaunchDaemon
# "dev.quorumrag.daemon", starts it, and opens the Web UI. Zero-Touch PATH.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Elevating privileges via sudo..." >&2
    exec sudo "$0" "$@"
fi

LABEL="dev.quorumrag.daemon"
TARGET_PLIST="/Library/LaunchDaemons/${LABEL}.plist"
URL="http://127.0.0.1:3031/"
HEALTH="http://127.0.0.1:3031/api/health"

mkdir -p /usr/local/bin /usr/local/share/quorumrag \
         "/Library/Application Support/QuorumRAG/data" \
         "/Library/Application Support/QuorumRAG/docs" \
         "/Library/Logs/QuorumRAG" \
         /Library/LaunchDaemons

# Stop a previous instance before replacing the binary.
launchctl bootout "system/${LABEL}" 2>/dev/null || true

if [ -f "${SCRIPT_DIR}/quorumrag" ]; then
    install -m 755 "${SCRIPT_DIR}/quorumrag" /usr/local/bin/quorumrag
    echo "[+] Installed /usr/local/bin/quorumrag"
fi
if [ -f "${SCRIPT_DIR}/uninstall.sh" ]; then
    install -m 755 "${SCRIPT_DIR}/uninstall.sh" /usr/local/share/quorumrag/uninstall.sh
fi

install -m 644 -o root -g wheel "${SCRIPT_DIR}/${LABEL}.plist" "${TARGET_PLIST}"
launchctl enable "system/${LABEL}" 2>/dev/null || true
launchctl bootstrap system "${TARGET_PLIST}"
launchctl kickstart -k "system/${LABEL}" 2>/dev/null || true
echo "[+] LaunchDaemon ${LABEL} installed, enabled at boot, and started"

if [ "${QUORUMRAG_NO_BROWSER:-0}" != "1" ]; then
    for _ in $(seq 1 90); do
        curl -fsS -m 2 "${HEALTH}" >/dev/null 2>&1 && break
        sleep 1
    done
    CONSOLE_USER="$(stat -f%Su /dev/console 2>/dev/null || true)"
    if [ -n "${CONSOLE_USER}" ] && [ "${CONSOLE_USER}" != "root" ] && [ "${CONSOLE_USER}" != "loginwindow" ]; then
        CONSOLE_UID="$(id -u "${CONSOLE_USER}")"
        launchctl asuser "${CONSOLE_UID}" sudo -u "${CONSOLE_USER}" open "${URL}" 2>/dev/null || true
    fi
fi

echo "[+] QuorumRAG installed on macOS (Web UI: ${URL}; Zero-Touch PATH preserved)."
echo "    Uninstall completely: sudo /usr/local/share/quorumrag/uninstall.sh [--purge]"
