@echo off
setlocal
REM QuorumRAG launcher (Zero-Touch Registry/System PATH: changes PATH for this process only).
REM Installed by the MSI: the QuorumRAGDaemon service runs the daemon, so just make sure it is
REM started and open the Web UI. Portable ZIP (no service): run the daemon in this console.
set "APP_DIR=%~dp0"
set "PATH=%APP_DIR%;%PATH%"

sc.exe query QuorumRAGDaemon >nul 2>&1
if %errorlevel%==0 (
    sc.exe query QuorumRAGDaemon | find "RUNNING" >nul || sc.exe start QuorumRAGDaemon >nul 2>&1
    call "%APP_DIR%quorumrag-open-ui.cmd"
    goto :eof
)

set "DATA_DIR=%LOCALAPPDATA%\QuorumRAG\data"
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
echo Starting QuorumRAG Local-First P2P Agentic RAG on http://127.0.0.1:3031 ...
"%APP_DIR%quorumrag.exe" --host 0.0.0.0 --port 3031 --p2p-port 3032 --data-dir "%DATA_DIR%" %*
endlocal
