#!/usr/bin/env bash
# QuorumRAG macOS uninstaller: stops and deletes the dev.quorumrag.daemon LaunchDaemon
# and removes every installed file.
#   --purge   also delete the index (/Library/Application Support/QuorumRAG) and logs
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Elevating privileges via sudo..." >&2
    exec sudo "$0" "$@"
fi

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

LABEL="dev.quorumrag.daemon"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"

launchctl bootout "system/${LABEL}" 2>/dev/null || launchctl unload -w "${PLIST}" 2>/dev/null || true
launchctl disable "system/${LABEL}" 2>/dev/null || true
if [ -f "${PLIST}" ]; then
    rm -f "${PLIST}"
    echo "[+] Removed ${PLIST}"
fi

pkill -TERM -f "/usr/local/bin/quorumrag" 2>/dev/null || true
pkill -TERM -f "QuorumRAG.app/Contents/MacOS/quorumrag-bin" 2>/dev/null || true

if [ -f /usr/local/bin/quorumrag ]; then
    rm -f /usr/local/bin/quorumrag
    echo "[+] Removed /usr/local/bin/quorumrag"
fi

if [ -d "/Applications/QuorumRAG.app" ]; then
    rm -rf "/Applications/QuorumRAG.app"
    echo "[+] Removed /Applications/QuorumRAG.app"
fi

# Forget the installer receipt so macOS no longer lists the package.
pkgutil --forget dev.quorumrag.pkg >/dev/null 2>&1 || true

if [ "${PURGE}" -eq 1 ]; then
    rm -rf "/Library/Application Support/QuorumRAG" "/Library/Logs/QuorumRAG"
    echo "[+] Purged /Library/Application Support/QuorumRAG and /Library/Logs/QuorumRAG"
else
    echo "[i] Index data kept in /Library/Application Support/QuorumRAG (re-run with --purge to delete)"
fi

if launchctl print "system/${LABEL}" >/dev/null 2>&1; then
    echo "[!] ${LABEL} is still loaded; reboot to finish removal."
else
    echo "[+] QuorumRAG uninstalled cleanly; ${LABEL} removed."
fi

rm -rf /usr/local/share/quorumrag
