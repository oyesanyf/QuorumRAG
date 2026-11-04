QuorumRAG Local-First P2P Agentic RAG
=====================================

Installed Location:
  C:\Program Files\QuorumRAG\quorumrag.exe
  C:\Program Files\QuorumRAG\quorumrag-launch.cmd     (Start Menu / Desktop "QuorumRAG Chat UI")
  C:\Program Files\QuorumRAG\quorumrag-open-ui.cmd    (waits for the service, then opens the browser)
  C:\Program Files\QuorumRAG\quorumrag-uninstall.cmd  (complete removal helper)

Windows Service (installed and started automatically):
  Name:      QuorumRAGDaemon ("QuorumRAG Local-First P2P RAG Service")
  Startup:   Automatic, runs as LocalSystem
  Web UI:    http://127.0.0.1:3031  (opened in your browser when setup finishes)
  Data:      %ProgramData%\QuorumRAG\data
  Log:       %ProgramData%\QuorumRAG\data\logs\quorumrag-service.log

  Manage it as an administrator:
    sc.exe query QuorumRAGDaemon
    sc.exe stop  QuorumRAGDaemon
    sc.exe start QuorumRAGDaemon

Silent install options:
  msiexec /i QuorumRAG-0.1.0-x86_64.msi /qn                    install + start service + open browser
  msiexec /i QuorumRAG-0.1.0-x86_64.msi /qn LAUNCHBROWSER=0    do not open the browser
  msiexec /i QuorumRAG-0.1.0-x86_64.msi /qn FIREWALLRULE=0     do not add the private-LAN firewall rule

Uninstall (stops AND deletes the QuorumRAGDaemon service completely):
  - Settings > Apps > Installed apps > "QuorumRAG P2P Agentic RAG" > Uninstall, or
  - Start Menu > QuorumRAG > "Uninstall QuorumRAG", or
  - msiexec /x QuorumRAG-0.1.0-x86_64.msi
  Add REMOVEDATA=1 to also delete the index and logs in %ProgramData%\QuorumRAG:
    msiexec /x QuorumRAG-0.1.0-x86_64.msi REMOVEDATA=1
  If the Apps entry is missing or broken, run as administrator:
    "C:\Program Files\QuorumRAG\quorumrag-uninstall.cmd" /purge
  which removes the MSI, the service (sc delete), the firewall rule, shortcuts,
  program files and (with /purge) all data.

Portable ZIP:
  quorumrag-launch.cmd runs QuorumRAG in a console window (no service) with data in
  %LOCALAPPDATA%\QuorumRAG\data, then opens the browser. Delete the folder to remove it.

Code signing / Smart App Control:
  quorumrag.exe and the MSI are Authenticode-signed (SHA256, RFC3161 timestamp) with the
  Oshoosi Developer certificate. That certificate is not issued by a public CA, so
  Windows Smart App Control / Device Guard can still block the binary on machines that
  enforce reputation-based policy. Guaranteed trust requires a publicly trusted
  code-signing certificate (e.g. Microsoft Trusted Signing, OV or EV).

Zero-Touch Environment Guarantee:
  This installer never modifies User or System PATH or any environment variable.
