@echo off
setlocal
REM Opens the QuorumRAG Web UI once the local service answers on its health endpoint.
REM Used by the MSI (end of install) and by the Start Menu / Desktop shortcut.
set "URL=http://127.0.0.1:3031/"
set "CURL=%SystemRoot%\System32\curl.exe"

echo Waiting for the QuorumRAG service at %URL% ...
if not exist "%CURL%" (
    timeout /t 8 /nobreak >nul
    goto open
)
for /l %%i in (1,1,90) do (
    "%CURL%" -s -f -o NUL --max-time 2 "%URL%api/health" && goto open
    timeout /t 1 /nobreak >nul
)
echo QuorumRAG did not answer within 90 seconds. Opening the browser anyway.
echo Check the service in services.msc (QuorumRAGDaemon) or the log in
echo %ProgramData%\QuorumRAG\data\logs\quorumrag-service.log

:open
start "" "%URL%"
endlocal
