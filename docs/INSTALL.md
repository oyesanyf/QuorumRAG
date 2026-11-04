# Installing QuorumRAG as a Service

Every native package installs QuorumRAG the same way the OsoosiEDR agent is installed:

- as an always-on background service that starts at boot,
- started immediately after the install,
- with the Web UI (http://127.0.0.1:3031/) opened in the desktop user's browser once the daemon answers `/api/health`.

Uninstalling stops the service and **deletes it completely** from the service manager. An optional purge step also deletes the index and logs.

None of the installers modify `PATH` or any persistent environment variable.

## Summary

| OS | Package | Service | Data / logs | Uninstall | Purge data |
|---|---|---|---|---|---|
| Windows | `QuorumRAG-<ver>-x86_64.msi` | `QuorumRAGDaemon` (auto start, LocalSystem) | `%ProgramData%\QuorumRAG\data` (log: `data\logs\quorumrag-service.log`) | Apps & Features, Start Menu "Uninstall QuorumRAG", or `msiexec /x <msi>` | `msiexec /x <msi> REMOVEDATA=1` |
| Windows | `QuorumRAG-<ver>-windows-x86_64.zip` | none (portable console) | `%LOCALAPPDATA%\QuorumRAG\data` | delete the folder | `quorumrag-uninstall.cmd /purge` |
| Debian/Ubuntu | `quorumrag_<ver>_<arch>.deb` | `quorumrag.service` (enabled + started) | `/var/lib/quorumrag`, `/var/log/quorumrag` | `sudo apt remove quorumrag` | `sudo apt purge quorumrag` |
| RHEL/Fedora/SUSE | `quorumrag-<ver>-1.<arch>.rpm` | `quorumrag.service` (enabled + started) | `/var/lib/quorumrag`, `/var/log/quorumrag` | `sudo dnf remove quorumrag` | `sudo /usr/lib/quorumrag/quorumrag-ctl uninstall --purge` |
| Linux (any) | `quorumrag-<ver>-linux-<arch>.tar.gz` | `quorumrag.service` via `sudo ./install.sh` | as above | `sudo ./uninstall.sh` | `sudo ./uninstall.sh --purge` |
| macOS | `QuorumRAG-<ver>-macos-universal.pkg` | LaunchDaemon `dev.quorumrag.daemon` (RunAtLoad, KeepAlive) | `/Library/Application Support/QuorumRAG`, `/Library/Logs/QuorumRAG` | `sudo /usr/local/share/quorumrag/uninstall.sh` | `... uninstall.sh --purge` |
| macOS | `quorumrag-<ver>-macos-universal.tar.gz` | same, via `sudo ./install.sh` | as above | `sudo ./uninstall.sh` | `sudo ./uninstall.sh --purge` |

## Windows (MSI)

```powershell
msiexec /i QuorumRAG-0.1.0-x86_64.msi                       # interactive
msiexec /i QuorumRAG-0.1.0-x86_64.msi /qn LAUNCHBROWSER=0   # silent, no browser
msiexec /i QuorumRAG-0.1.0-x86_64.msi /qn FIREWALLRULE=0    # no private-LAN firewall rule
```

- `quorumrag.exe --service` runs under the Service Control Manager. It reports `START_PENDING` and then `RUNNING`, and handles `STOP`/`SHUTDOWN` with a graceful daemon shutdown. The code is in [win_service.rs](../crates/quorum-daemon/src/win_service.rs).
- When the MSI finishes, it runs `quorumrag-open-ui.cmd` as the installing user. The script waits up to 90 s for `/api/health` and then opens the default browser.
- The Start Menu and Desktop shortcut "QuorumRAG Chat UI" runs `quorumrag-launch.cmd`, which opens the UI of the running service.

### Uninstall

The MSI `ServiceControl` element (`Stop="both" Remove="uninstall"`) stops the `QuorumRAGDaemon` service and deletes it from the SCM. The uninstall also removes:
- the firewall rule
- the shortcuts and registry keys
- `C:\Program Files\QuorumRAG`

To also delete the index and logs, uninstall with `REMOVEDATA=1`.

If the Apps entry is missing or broken, run `quorumrag-uninstall.cmd /purge` as administrator. It:
1. uninstalls the MSI if it is registered,
2. runs `sc stop` and `sc delete QuorumRAGDaemon`,
3. removes the firewall rule, shortcuts, program files and (with `/purge`) the data.

### Code signing and Smart App Control

`quorumrag.exe` and the MSI are signed exactly once with `signtool` (SHA256 with an RFC 3161 timestamp). The signing script is [submit_to_microsoft.ps1](../scripts/submit_to_microsoft.ps1).

The local `CN=Oshoosi Developer` certificate is self-signed, not publicly trusted. On machines where Smart App Control or a Device Guard (WDAC) reputation policy is enforced, Windows can therefore still block the binary.

The only supported way to get guaranteed trust is to sign with a publicly trusted code-signing certificate (Microsoft Trusted Signing, OV or EV). The build never modifies Code Integrity policy or certificate trust stores.

## Linux (deb / rpm / tarball)

- The package postinstall runs `/usr/lib/quorumrag/quorumrag-ctl post-install`. It:
  1. creates `/var/lib/quorumrag/{data,docs}` and `/var/log/quorumrag`,
  2. runs `systemctl daemon-reload`,
  3. runs `systemctl enable --now quorumrag.service` (or a restart on upgrade),
  4. opens the Web UI with `xdg-open` for the installing desktop user (`$SUDO_USER`, `$PKEXEC_UID`, or the active graphical `loginctl` session).
- The browser launch is detached and best-effort: it never blocks or fails the install. Set `QUORUMRAG_NO_BROWSER=1` to skip it.
- `/usr/share/applications/quorumrag.desktop` adds a "QuorumRAG Chat UI" menu entry.
- Uninstall:
  - prerm / `%preun` stops and disables the unit.
  - postrm / `%postun` reloads systemd and resets the failed state.
  - `apt purge` also deletes `/var/lib/quorumrag` and `/var/log/quorumrag`.
  - `quorumrag-ctl uninstall [--purge]` works for deb, rpm and tarball installs.

## macOS (pkg / tarball)

- preinstall boots out any running daemon. postinstall runs `launchctl enable`, `launchctl bootstrap system` and `launchctl kickstart -k`, then opens the Web UI as the console user once it is healthy.
- `QuorumRAG.app`:
  - With the LaunchDaemon installed, it only opens the browser.
  - Installed by dragging from the `.dmg`, it runs a per-user instance with data in `~/Library/Application Support/QuorumRAG`.
- `uninstall.sh`:
  - runs `launchctl bootout` and `disable`,
  - removes the plist, `/usr/local/bin/quorumrag`, `QuorumRAG.app` and the pkg receipt (`pkgutil --forget dev.quorumrag.pkg`),
  - with `--purge`, also removes data and logs.
