#!/bin/sh
# QuorumRAG Linux service + browser helper.
# Installed as /usr/lib/quorumrag/quorumrag-ctl by the .deb, .rpm and tarball install.sh.
#
#   quorumrag-ctl post-install          enable + (re)start quorumrag.service, open the Web UI
#   quorumrag-ctl pre-remove            stop + disable quorumrag.service
#   quorumrag-ctl open-ui [--as-user U] wait for the daemon health endpoint, then open the browser
#   quorumrag-ctl uninstall [--purge]   remove the package/service completely (--purge: also data + logs)
#   quorumrag-ctl purge-data            delete /var/lib/quorumrag and /var/log/quorumrag
#
# Never modifies PATH or any persistent environment variable.
# Set QUORUMRAG_NO_BROWSER=1 to suppress the browser launch during install.

UNIT=quorumrag.service
PORT="${QUORUMRAG_PORT:-3031}"
URL="http://127.0.0.1:${PORT}/"
HEALTH="http://127.0.0.1:${PORT}/api/health"
DATA_DIRS="/var/lib/quorumrag /var/log/quorumrag"

have() { command -v "$1" >/dev/null 2>&1; }
has_systemd() { [ -d /run/systemd/system ] && have systemctl; }

wait_health() {
    i=0
    while [ "$i" -lt 90 ]; do
        if have curl; then
            curl -fsS -m 2 "$HEALTH" >/dev/null 2>&1 && return 0
        elif have wget; then
            wget -q -T 2 -O /dev/null "$HEALTH" >/dev/null 2>&1 && return 0
        else
            sleep 5
            return 0
        fi
        i=$((i + 1))
        sleep 1
    done
    return 1
}

open_url_here() {
    for opener in xdg-open gio sensible-browser x-www-browser; do
        if have "$opener"; then
            if [ "$opener" = gio ]; then
                gio open "$URL" >/dev/null 2>&1 && return 0
            else
                "$opener" "$URL" >/dev/null 2>&1 && return 0
            fi
        fi
    done
    echo "QuorumRAG Web UI: $URL"
    return 0
}

# Pick the desktop user who should see the browser: sudo caller, pkexec caller,
# or the active graphical login session.
desktop_user() {
    if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
        echo "$SUDO_USER"; return 0
    fi
    if [ -n "${PKEXEC_UID:-}" ] && have getent; then
        getent passwd "$PKEXEC_UID" | cut -d: -f1; return 0
    fi
    if have loginctl; then
        for sid in $(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}'); do
            info="$(loginctl show-session "$sid" -p Active -p Type -p Name 2>/dev/null)"
            case "$info" in
                *Active=yes*)
                    case "$info" in
                        *Type=x11*|*Type=wayland*)
                            echo "$info" | sed -n 's/^Name=//p'; return 0 ;;
                    esac ;;
            esac
        done
    fi
    return 1
}

open_ui() {
    as_user=""
    if [ "${1:-}" = "--as-user" ]; then as_user="${2:-}"; fi
    wait_health || echo "QuorumRAG is still starting; open $URL when ready."
    if [ -n "$as_user" ] && [ "$(id -u)" -eq 0 ] && [ "$as_user" != "root" ]; then
        uid="$(id -u "$as_user" 2>/dev/null)" || return 0
        rt="/run/user/${uid}"
        set -- env XDG_RUNTIME_DIR="$rt"
        [ -S "${rt}/bus" ] && set -- "$@" DBUS_SESSION_BUS_ADDRESS="unix:path=${rt}/bus"
        if [ -S /tmp/.X11-unix/X0 ]; then set -- "$@" DISPLAY="${DISPLAY:-:0}"; fi
        for w in "$rt"/wayland-*; do
            case "$w" in *.lock) continue ;; esac
            [ -S "$w" ] && { set -- "$@" WAYLAND_DISPLAY="$(basename "$w")"; break; }
        done
        if have runuser; then
            runuser -u "$as_user" -- "$@" xdg-open "$URL" >/dev/null 2>&1 || true
        elif have sudo; then
            sudo -u "$as_user" "$@" xdg-open "$URL" >/dev/null 2>&1 || true
        fi
        return 0
    fi
    open_url_here
}

post_install() {
    mkdir -p /var/lib/quorumrag/data /var/lib/quorumrag/docs /var/log/quorumrag
    chmod 750 /var/lib/quorumrag /var/log/quorumrag 2>/dev/null || true
    if has_systemd; then
        systemctl daemon-reload || true
        if systemctl is-active --quiet "$UNIT"; then
            systemctl restart "$UNIT" || true
        else
            systemctl enable --now "$UNIT" || true
        fi
        echo "[+] quorumrag.service enabled and started (Web UI: $URL)"
    else
        echo "[!] systemd not detected; start manually: /usr/bin/quorumrag --data-dir /var/lib/quorumrag/data"
    fi
    if [ "${QUORUMRAG_NO_BROWSER:-0}" != "1" ]; then
        user="$(desktop_user 2>/dev/null || true)"
        if [ -n "$user" ]; then
            # Detached and best-effort: the package install never waits on or fails because of this.
            ( nohup sh "$0" open-ui --as-user "$user" >/dev/null 2>&1 & ) || true
        fi
    fi
    return 0
}

pre_remove() {
    if has_systemd; then
        systemctl stop "$UNIT" >/dev/null 2>&1 || true
        systemctl disable "$UNIT" >/dev/null 2>&1 || true
    fi
    return 0
}

purge_data() {
    for d in $DATA_DIRS; do
        [ -d "$d" ] && rm -rf "$d"
    done
    echo "[+] Removed QuorumRAG data and logs ($DATA_DIRS)"
}

uninstall() {
    purge=0
    [ "${1:-}" = "--purge" ] && purge=1
    if [ "$(id -u)" -ne 0 ]; then
        exec sudo "$0" uninstall "$@"
    fi
    if have dpkg && dpkg -s quorumrag >/dev/null 2>&1; then
        if [ "$purge" -eq 1 ]; then
            apt-get purge -y quorumrag 2>/dev/null || dpkg --purge quorumrag
        else
            apt-get remove -y quorumrag 2>/dev/null || dpkg -r quorumrag
        fi
    elif have rpm && rpm -q quorumrag >/dev/null 2>&1; then
        if have dnf; then dnf remove -y quorumrag
        elif have yum; then yum remove -y quorumrag
        elif have zypper; then zypper -n remove quorumrag
        else rpm -e quorumrag
        fi
    else
        pre_remove
        rm -f /lib/systemd/system/$UNIT /etc/systemd/system/$UNIT /usr/lib/systemd/system/$UNIT
        has_systemd && systemctl daemon-reload || true
        has_systemd && systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true
        rm -f /usr/bin/quorumrag /usr/share/applications/quorumrag.desktop
        rm -rf /usr/lib/quorumrag
    fi
    [ "$purge" -eq 1 ] && purge_data
    if has_systemd && systemctl list-unit-files "$UNIT" 2>/dev/null | grep -q "$UNIT"; then
        echo "[!] $UNIT is still registered"
        return 1
    fi
    echo "[+] QuorumRAG uninstalled; $UNIT removed."
    return 0
}

cmd="${1:-}"
[ $# -gt 0 ] && shift
case "$cmd" in
    post-install) post_install ;;
    pre-remove)   pre_remove ;;
    open-ui)      open_ui "$@" ;;
    uninstall)    uninstall "$@" ;;
    purge-data)   purge_data ;;
    *)
        echo "usage: quorumrag-ctl {post-install|pre-remove|open-ui [--as-user USER]|uninstall [--purge]|purge-data}" >&2
        exit 2 ;;
esac
