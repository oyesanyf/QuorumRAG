@echo off
setlocal EnableExtensions
rem ------------------------------------------------------------------
rem QuorumRAG complete uninstaller (Windows)
rem
rem   quorumrag-uninstall.cmd           remove MSI, service, firewall rule
rem   quorumrag-uninstall.cmd /purge    ...and delete all index data + logs
rem
rem Normal uninstall is Settings ^> Apps ^> "QuorumRAG P2P Agentic RAG" or
rem   msiexec /x QuorumRAG-0.1.0-x86_64.msi [REMOVEDATA=1]
rem This script also cleans up when the MSI entry is already gone.
rem Never touches PATH or any environment variable.
rem ------------------------------------------------------------------

set "SERVICE=QuorumRAGDaemon"
set "PURGE=0"
if /I "%~1"=="/purge" set "PURGE=1"
if /I "%~1"=="--purge" set "PURGE=1"

rem Require elevation (service + Program Files removal need admin).
net session >nul 2>&1
if errorlevel 1 goto :elevate

rem The MSI deletes the install folder this script lives in; run from a temp copy.
if not defined QR_UNINSTALL_RELAUNCHED (
    set "QR_UNINSTALL_RELAUNCHED=1"
    copy /y "%~f0" "%TEMP%\quorumrag-uninstall.cmd" >nul
    "%TEMP%\quorumrag-uninstall.cmd" %*
)

echo [1/4] Uninstalling the QuorumRAG MSI package (if registered)...
set "MSI_EXTRA="
if "%PURGE%"=="1" set "MSI_EXTRA=REMOVEDATA=1"
set "PS_FIND=$k='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'QuorumRAG P2P Agentic RAG' } | ForEach-Object { $_.PSChildName }"
for /f "usebackq delims=" %%G in (`powershell -NoProfile -Command "%PS_FIND%"`) do call :msi_remove %%G

echo [2/4] Stopping and deleting the %SERVICE% service (if still present)...
sc.exe query "%SERVICE%" >nul 2>&1
if errorlevel 1 (
    echo   service not installed.
    goto :firewall
)
sc.exe stop "%SERVICE%" >nul 2>&1
set /a WAITED=0
:wait_stop
sc.exe query "%SERVICE%" | find "STOPPED" >nul 2>&1
if not errorlevel 1 goto :stopped
if %WAITED% GEQ 30 goto :stopped
set /a WAITED+=1
timeout /t 1 /nobreak >nul
goto :wait_stop
:stopped
taskkill /f /im quorumrag.exe >nul 2>&1
sc.exe delete "%SERVICE%"

:firewall
echo [3/4] Removing firewall rule...
netsh advfirewall firewall delete rule name="QuorumRAG P2P Mesh" >nul 2>&1

echo [4/4] Removing leftover files...
if exist "%ProgramFiles%\QuorumRAG" rmdir /s /q "%ProgramFiles%\QuorumRAG"
if exist "%ProgramData%\Microsoft\Windows\Start Menu\Programs\QuorumRAG" rmdir /s /q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\QuorumRAG"
if exist "%PUBLIC%\Desktop\QuorumRAG Chat UI.lnk" del /f /q "%PUBLIC%\Desktop\QuorumRAG Chat UI.lnk"
reg delete "HKLM\Software\OshoosiSecurity\QuorumRAG" /f >nul 2>&1
if "%PURGE%"=="1" goto :purge
echo   index data kept in %ProgramData%\QuorumRAG (re-run with /purge to delete).
goto :verify

:purge
echo   purging data: %ProgramData%\QuorumRAG and %LOCALAPPDATA%\QuorumRAG
if exist "%ProgramData%\QuorumRAG" rmdir /s /q "%ProgramData%\QuorumRAG"
if exist "%LOCALAPPDATA%\QuorumRAG" rmdir /s /q "%LOCALAPPDATA%\QuorumRAG"

:verify
sc.exe query "%SERVICE%" >nul 2>&1
if errorlevel 1 (
    echo QuorumRAG uninstalled. Service %SERVICE% is gone.
) else (
    echo WARNING: service %SERVICE% is still registered; a reboot may be required.
)
endlocal
exit /b 0

:msi_remove
echo   msiexec /x %~1 /qb %MSI_EXTRA%
msiexec /x %~1 /qb /norestart %MSI_EXTRA%
exit /b 0

:elevate
echo Requesting administrator rights...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%~1' -Verb RunAs"
exit /b 0
