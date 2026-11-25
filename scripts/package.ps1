param(
    [string]$Version = "0.9.3",
    [switch]$SkipBuild = $false,
    [switch]$SkipDefenderScan = $false,
    [string]$CertThumbprint = "9A6D3B509500813058EC63183476464FAC8F015B"
)

# QuorumRAG Windows Release & WiX v5 MSI Packaging Pipeline
# Enforces Universal Zero-Touch PATH & Environment Protection Protocol.

$ErrorActionPreference = "Stop"
if (Test-Path Variable:\PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}
$ProjectRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
Set-Location $ProjectRoot

# Process-scoped PATH additions ONLY (Zero-Touch Registry and System PATH)
$RustupBin = Join-Path $env:USERPROFILE ".rustup\toolchains\stable-x86_64-pc-windows-msvc\bin"
$CargoExe = "cargo"
if (Test-Path (Join-Path $RustupBin "cargo.exe")) {
    $env:PATH = "$RustupBin;$env:PATH"
    $env:RUSTC = Join-Path $RustupBin "rustc.exe"
    $CargoExe = Join-Path $RustupBin "cargo.exe"
}

$ProcessToolDirs = @(
    (Join-Path $env:USERPROFILE ".cargo\bin"),
    (Join-Path $env:USERPROFILE ".dotnet\tools"),
    "C:\Users\oyesanyf\wix_tools\PFiles64\WiX Toolset v5.0\bin",
    "C:\Program Files\Git\cmd",
    "C:\Program Files\dotnet"
)
foreach ($d in $ProcessToolDirs) {
    if ($d -and (Test-Path $d) -and ($env:PATH -notmatch [regex]::Escape($d))) {
        $env:PATH = "$d;$env:PATH"
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " QuorumRAG v$Version Windows Release & MSI Packaging" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Step 0: Fail-Closed Zero-Touch PATH Manifest Audit
$WixWxs = Join-Path $ProjectRoot "wix\QuorumRAG.wxs"
if (-not (Test-Path $WixWxs)) {
    throw "Missing WiX manifest at $WixWxs"
}
$WxsRaw = Get-Content -Path $WixWxs -Raw -Encoding UTF8
$WxsNoComments = [regex]::Replace($WxsRaw, '<!--[\s\S]*?-->', '')
if ($WxsNoComments -match '<\s*Environment\b') {
    throw "SECURITY INVARIANT VIOLATION: WiX Environment element detected in $WixWxs. Zero-Touch PATH law forbids all MSI environment mutations."
}
Write-Host "[0/5] Zero-Touch PATH static manifest audit: PASS (0 Environment tags)" -ForegroundColor Green

# Step 1: Build Release Binaries (quorumrag.exe & quorum-desktop.exe) with WDAC build-script signing support
$ReleaseExe = Join-Path $ProjectRoot "target\release\quorumrag.exe"
$DesktopExe = Join-Path $ProjectRoot "target\release\quorum-desktop.exe"
if (-not $SkipBuild) {
    Write-Host "[1/5] Building release binaries (quorum-daemon -> quorumrag.exe, quorum-desktop.exe)..." -ForegroundColor Cyan
    if (Test-Path $ReleaseExe) {
        try {
            Remove-Item -Path $ReleaseExe -Force -ErrorAction Stop
        } catch {
            $lockedCopy = "$ReleaseExe.locked." + (Get-Random)
            Write-Host "  target\release\quorumrag.exe is in use; renaming to $lockedCopy..." -ForegroundColor Yellow
            Move-Item -Path $ReleaseExe -Destination $lockedCopy -Force
        }
    }
    if (Test-Path $DesktopExe) {
        try {
            Remove-Item -Path $DesktopExe -Force -ErrorAction Stop
        } catch {
            $lockedCopy = "$DesktopExe.locked." + (Get-Random)
            Write-Host "  target\release\quorum-desktop.exe is in use; renaming to $lockedCopy..." -ForegroundColor Yellow
            Move-Item -Path $DesktopExe -Destination $lockedCopy -Force
        }
    }
    Remove-Item -Path (Join-Path $ProjectRoot "target\release\deps\quorumrag*") -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $ProjectRoot "target\release\deps\quorum_desktop*") -Force -ErrorAction SilentlyContinue

    $env:CARGO_INCREMENTAL = "0"
    $env:VSCMD_SKIP_SENDTELEMETRY = "1"
    $env:CARGO_BUILD_JOBS = "6"
    $maxAttempts = 60
    $buildOk = $false
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        # Invoke cargo directly (not Start-Process -Wait): -Wait also waits for detached descendants
        # such as the MSVC linker's vctip.exe telemetry helper, which can stall packaging indefinitely.
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $cargoLines = & $CargoExe build --release -p quorum-daemon --bin quorumrag --bin quorum-desktop 2>&1 | ForEach-Object {
            $line = "$_"
            Write-Host $line
            $line
        }
        $cargoExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEap
        $errText = ($cargoLines -join "`n")
        if ($cargoExit -eq 0) {
            $buildOk = $true
            break
        }
        $handledSac = $false
        # If Windows 11 Smart App Control blocked stale pre-existing build-script-build.exe binaries
        # (including Cargo 1.100+ nested build/<crate>/<hash>/out/build_script_build.exe, os error 4551),
        # purge all matched build directories in one pass so link.exe emits fresh Smartlocker-trusted inodes.
        $bsMatches = [regex]::Matches($errText, 'target[\\/](?:debug|release)[\\/]build[\\/]([^\\/]+)[\\/].*build[-_]script[-_]build')
        if ($bsMatches.Count -gt 0 -and $attempt -lt $maxAttempts) {
            $seenBs = @{}
            foreach ($bm in $bsMatches) {
                $bsPkg = $bm.Groups[1].Value
                if ($seenBs.ContainsKey($bsPkg)) { continue }
                $seenBs[$bsPkg] = $true
                foreach ($prof in @("release", "debug")) {
                    $blockedPkgDir = Join-Path $ProjectRoot ("target\$prof\build\" + $bsPkg)
                    if (Test-Path $blockedPkgDir) {
                        Write-Host "  [SAC] Purging stale build-script directory '$blockedPkgDir' ($attempt/$maxAttempts)..." -ForegroundColor Yellow
                        Remove-Item -Recurse -Force -Path $blockedPkgDir -ErrorAction SilentlyContinue
                    }
                    Remove-Item -Recurse -Force -Path (Join-Path $ProjectRoot "target\$prof\.fingerprint\$bsPkg*") -ErrorAction SilentlyContinue
                }
            }
            $handledSac = $true
        }
        $dllMatches = [regex]::Matches($errText, '(target[\\/](?:debug|release)[\\/][^\r\n:`"'']+?\.dll)')
        if ($dllMatches.Count -gt 0 -and ($errText -match '4551' -or $errText -match 'E0463' -or $errText -match 'LoadLibraryExW') -and $attempt -lt $maxAttempts) {
            $cleanedDllPkgs = @{}
            foreach ($dm in $dllMatches) {
                $relDll = $dm.Groups[1].Value -replace '/', '\'
                $blockedDll = Join-Path $ProjectRoot $relDll
                $dllName = [System.IO.Path]::GetFileName($blockedDll)
                $stemPrefix = ($dllName -split '-')[0]
                Write-Host "  [SAC] Purging stale proc-macro DLL '$blockedDll' ($attempt/$maxAttempts)..." -ForegroundColor Yellow
                Remove-Item -Force -Path $blockedDll -ErrorAction SilentlyContinue
                $parentDir = [System.IO.Path]::GetDirectoryName($blockedDll)
                if ([System.IO.Path]::GetFileName($parentDir) -eq "out") {
                    $hashDir = [System.IO.Path]::GetDirectoryName($parentDir)
                    $crateDirName = [System.IO.Path]::GetFileName([System.IO.Path]::GetDirectoryName($hashDir))
                    Remove-Item -Recurse -Force -Path $hashDir -ErrorAction SilentlyContinue
                    $cleanedDllPkgs[$crateDirName] = $true
                } else {
                    $cleanedDllPkgs[($stemPrefix -replace '_', '-')] = $true
                }
            }
            foreach ($pkg in $cleanedDllPkgs.Keys) {
                $pkgUnder = $pkg -replace '-', '_'
                foreach ($prof in @("release", "debug")) {
                    Remove-Item -Force -Path (Join-Path $ProjectRoot "target\$prof\deps\$pkgUnder*.dll") -ErrorAction SilentlyContinue
                    Remove-Item -Force -Path (Join-Path $ProjectRoot "target\$prof\deps\$pkgUnder*.pdb") -ErrorAction SilentlyContinue
                    Remove-Item -Recurse -Force -Path (Join-Path $ProjectRoot "target\$prof\.fingerprint\$pkg*") -ErrorAction SilentlyContinue
                    Remove-Item -Recurse -Force -Path (Join-Path $ProjectRoot "target\$prof\.fingerprint\$pkgUnder*") -ErrorAction SilentlyContinue
                    Remove-Item -Recurse -Force -Path (Join-Path $ProjectRoot "target\$prof\build\$pkg") -ErrorAction SilentlyContinue
                    Remove-Item -Recurse -Force -Path (Join-Path $ProjectRoot "target\$prof\build\$pkgUnder") -ErrorAction SilentlyContinue
                }
            }
            $handledSac = $true
        }
        $e0463Matches = [regex]::Matches($errText, 'error\[E0463\]: can''t find crate for [`'']([a-zA-Z0-9_]+)[`'']')
        if ($e0463Matches.Count -gt 0 -and $attempt -lt $maxAttempts) {
            $seenCrates = @{}
            foreach ($m in $e0463Matches) {
                $cname = $m.Groups[1].Value
                if ($seenCrates.ContainsKey($cname)) { continue }
                $seenCrates[$cname] = $true
                $cdash = $cname -replace '_', '-'
                Write-Host "  [SAC] Fast-purging E0463 proc-macro fingerprints/DLLs for $cdash / $cname ($attempt/$maxAttempts)..." -ForegroundColor Yellow
                foreach ($prof in @("release", "debug")) {
                    Remove-Item -Force -Path (Join-Path $ProjectRoot "target\$prof\deps\$cname*.dll") -ErrorAction SilentlyContinue
                    Remove-Item -Force -Path (Join-Path $ProjectRoot "target\$prof\deps\$cname*.pdb") -ErrorAction SilentlyContinue
                    Remove-Item -Recurse -Force -Path (Join-Path $ProjectRoot "target\$prof\.fingerprint\$cdash*") -ErrorAction SilentlyContinue
                    Remove-Item -Recurse -Force -Path (Join-Path $ProjectRoot "target\$prof\.fingerprint\$cname*") -ErrorAction SilentlyContinue
                    Remove-Item -Recurse -Force -Path (Join-Path $ProjectRoot "target\$prof\build\$cdash") -ErrorAction SilentlyContinue
                    Remove-Item -Recurse -Force -Path (Join-Path $ProjectRoot "target\$prof\build\$cname") -ErrorAction SilentlyContinue
                }
            }
            $handledSac = $true
        }
        if ($handledSac) {
            Start-Sleep -Milliseconds 300
            continue
        }
        $LASTEXITCODE = $cargoExit
        break
    }
    if (-not $buildOk -or $cargoExit -ne 0) {
        throw "cargo build --release failed with exit code $cargoExit"
    }
} else {
    Write-Host "[1/5] Skipping cargo build (-SkipBuild)" -ForegroundColor Gray
}

if (-not (Test-Path $ReleaseExe)) {
    $AltExe = Join-Path $ProjectRoot "target\x86_64-pc-windows-msvc\release\quorumrag.exe"
    if (Test-Path $AltExe) {
        New-Item -ItemType Directory -Force -Path (Split-Path $ReleaseExe -Parent) | Out-Null
        Copy-Item -Path $AltExe -Destination $ReleaseExe -Force
    } else {
        throw "Release binary not found at $ReleaseExe"
    }
}

# Break Cargo NTFS hardlink between release binaries and deps before Authenticode signing
foreach ($targetBin in @($ReleaseExe, $DesktopExe)) {
    if (Test-Path $targetBin) {
        $hlOut = & fsutil hardlink list $targetBin 2>$null
        if ($hlOut -and ($hlOut.Count -gt 1)) {
            $targetFull = [System.IO.Path]::GetFullPath($targetBin)
            $driveRoot = [System.IO.Path]::GetPathRoot($targetFull).TrimEnd('\')
            foreach ($hlRel in $hlOut) {
                $hlCandidate = "$driveRoot$hlRel"
                if ([System.IO.Path]::GetFullPath($hlCandidate) -ne $targetFull) {
                    Remove-Item -Path $hlCandidate -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

# Pre-sign target\release\quorumrag.exe and quorum-desktop.exe before embedding into MSI & ZIP so installed binaries carry Authenticode signature.
# IMPORTANT: invoke directly in-process (& $SubmitScript) rather than via `powershell -File ... -Files $a, $b`,
# because PowerShell `-File` splits comma-separated arrays across positional parameters and silently skips the second file.
$SubmitScript = Join-Path $ProjectRoot "scripts\submit_to_microsoft.ps1"
if (Test-Path $SubmitScript) {
    $BinariesToSign = @($ReleaseExe)
    if (Test-Path $DesktopExe) {
        $BinariesToSign += $DesktopExe
    }
    & $SubmitScript -Version $Version -SkipDefenderScan -Files $BinariesToSign

    # Fail-closed Authenticode parity check: if quorumrag.exe was signed, quorum-desktop.exe MUST also be signed
    # (prevents Windows 11 Smart App Control err=4551 when Session 0 spawns quorum-desktop.exe --session-fs-bridge).
    if (Test-Path $DesktopExe) {
        $mainSig = Get-AuthenticodeSignature -FilePath $ReleaseExe
        $deskSig = Get-AuthenticodeSignature -FilePath $DesktopExe
        if ($null -ne $mainSig.SignerCertificate -and ($null -eq $deskSig.SignerCertificate -or $deskSig.Status -eq 'NotSigned')) {
            throw "SECURITY PACKAGING INVARIANT VIOLATION: quorumrag.exe is signed, but quorum-desktop.exe is unsigned ($($deskSig.Status))."
        }
        Write-Host "  [Sign Parity] quorumrag.exe & quorum-desktop.exe Authenticode parity verified." -ForegroundColor Green
    }
}

# Step 2: Stage deploy\windows Portable Bundle (.zip)
Write-Host "[2/5] Staging portable Windows bundle & pruning stale artifacts..." -ForegroundColor Cyan
$WinDeployDir = Join-Path $ProjectRoot "deploy\windows"
New-Item -ItemType Directory -Force -Path $WinDeployDir | Out-Null
Get-ChildItem -Path $WinDeployDir -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

# Ensure old staging directories (deploy\windows\portable_stage) are completely cleaned
$PortableStageBase = Join-Path $WinDeployDir "portable_stage"
if (Test-Path $PortableStageBase) {
    Remove-Item -Path $PortableStageBase -Recurse -Force -ErrorAction SilentlyContinue
}

$PortableStage = Join-Path $PortableStageBase "QuorumRAG-$Version-windows-x86_64"
New-Item -ItemType Directory -Force -Path $PortableStage | Out-Null
Copy-Item -Path $ReleaseExe -Destination (Join-Path $PortableStage "quorumrag.exe") -Force
if (Test-Path $DesktopExe) {
    Copy-Item -Path $DesktopExe -Destination (Join-Path $PortableStage "quorum-desktop.exe") -Force
}
Copy-Item -Path (Join-Path $ProjectRoot "packaging\windows\quorumrag-launch.cmd") -Destination (Join-Path $PortableStage "quorumrag-launch.cmd") -Force
Copy-Item -Path (Join-Path $ProjectRoot "packaging\windows\README_INSTALL.txt") -Destination (Join-Path $PortableStage "README_INSTALL.txt") -Force
Copy-Item -Path (Join-Path $ProjectRoot "packaging\windows\quorumrag-open-ui.cmd") -Destination (Join-Path $PortableStage "quorumrag-open-ui.cmd") -Force
Copy-Item -Path (Join-Path $ProjectRoot "packaging\windows\quorumrag-uninstall.cmd") -Destination (Join-Path $PortableStage "quorumrag-uninstall.cmd") -Force

$ZipOut = Join-Path $WinDeployDir "QuorumRAG-$Version-windows-x86_64.zip"
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($PortableStageBase, $ZipOut)
Remove-Item -Path $PortableStageBase -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "  -> Created portable archive: $ZipOut" -ForegroundColor Green

# Step 3: Resolve WiX v5 CLI & Compile QuorumRAG-<Version>-x86_64.msi
Write-Host "[3/5] Compiling WiX v5 MSI installer..." -ForegroundColor Cyan
$WixCmd = $null
$FoundWix = Get-Command "wix.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($FoundWix) {
    $WixCmd = $FoundWix.Source
} else {
    $CandidateWix = @(
        "C:\Users\oyesanyf\wix_tools\PFiles64\WiX Toolset v5.0\bin\wix.exe",
        (Join-Path $env:USERPROFILE "wix_tools\PFiles64\WiX Toolset v5.0\bin\wix.exe"),
        (Join-Path $env:USERPROFILE ".dotnet\tools\wix.exe"),
        (Join-Path $env:ProgramFiles "WiX Toolset v5.0\bin\wix.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "WiX Toolset v5.0\bin\wix.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\wix\wix.exe")
    )
    foreach ($cand in $CandidateWix) {
        if ($cand -and (Test-Path $cand)) {
            $WixCmd = $cand
            break
        }
    }
}

if (-not $WixCmd) {
    if (Get-Command "dotnet" -ErrorAction SilentlyContinue) {
        Write-Host "  Installing WiX v5.0.2 dotnet tool..." -ForegroundColor Yellow
        & dotnet tool install --global wix --version 5.0.2
        $DotnetWix = Join-Path $env:USERPROFILE ".dotnet\tools\wix.exe"
        if (Test-Path $DotnetWix) { $WixCmd = $DotnetWix }
    }
}

if (-not $WixCmd) {
    throw "WiX v5 (wix.exe) could not be found or installed."
}

$MinMsiProductVersion = [version]"0.6.0"
$ParsedVer = $null
$MsiProductVersion = if ([version]::TryParse($Version, [ref]$ParsedVer) -and $ParsedVer -lt $MinMsiProductVersion) {
    "0.6.0"
} else {
    $Version
}
$MsiOut = Join-Path $WinDeployDir "QuorumRAG-$Version-x86_64.msi"
& $WixCmd build $WixWxs -arch x64 -d "ProductVersion=$MsiProductVersion" -out $MsiOut
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $MsiOut)) {
    throw "WiX MSI compilation failed (exit code $LASTEXITCODE)"
}
Write-Host "  -> Created MSI installer: $MsiOut" -ForegroundColor Green

# Step 4: Binary MSI Database Inspection (Zero-Touch PATH + ICE63 Error 2613 + CustomAction Directory Audit)
Write-Host "[4/5] Auditing compiled MSI database tables via Windows Installer COM..." -ForegroundColor Cyan
$Installer = New-Object -ComObject WindowsInstaller.Installer
$Database = $Installer.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $Installer, @([string]$MsiOut, [int]0))

$TablesView = $Database.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $Database, @('SELECT `Name` FROM `_Tables`'))
$TablesView.GetType().InvokeMember("Execute", "InvokeMethod", $null, $TablesView, $null) | Out-Null
$TableNames = @()
while ($true) {
    $Rec = $TablesView.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $TablesView, $null)
    if (-not $Rec) { break }
    $TableNames += $Rec.GetType().InvokeMember("StringData", "GetProperty", $null, $Rec, @(1))
}
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($TablesView) | Out-Null

# 4a. Verify CustomAction Directory_ references exist in Directory table (prevents MSI Error 2727)
$DirView = $Database.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $Database, @('SELECT `Directory` FROM `Directory`'))
$DirView.GetType().InvokeMember("Execute", "InvokeMethod", $null, $DirView, $null) | Out-Null
$ValidDirs = @{}
while ($true) {
    $Rec = $DirView.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $DirView, $null)
    if (-not $Rec) { break }
    $dName = $Rec.GetType().InvokeMember("StringData", "GetProperty", $null, $Rec, @(1))
    $ValidDirs[$dName] = $true
}
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($DirView) | Out-Null

$CaView = $Database.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $Database, @('SELECT `Action`, `Type`, `Source` FROM `CustomAction`'))
$CaView.GetType().InvokeMember("Execute", "InvokeMethod", $null, $CaView, $null) | Out-Null
while ($true) {
    $Rec = $CaView.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $CaView, $null)
    if (-not $Rec) { break }
    $caName = $Rec.GetType().InvokeMember("StringData", "GetProperty", $null, $Rec, @(1))
    $caType = [int]($Rec.GetType().InvokeMember("StringData", "GetProperty", $null, $Rec, @(2)))
    $caSource = $Rec.GetType().InvokeMember("StringData", "GetProperty", $null, $Rec, @(3))
    # CustomAction base type 34 (0x22 = Exe + Directory) uses Source as a foreign key into Directory table
    if ((($caType -band 0x3F) -eq 34) -and (-not $ValidDirs.ContainsKey($caSource))) {
        throw "MSI ERROR 2727 VIOLATION: CustomAction '$caName' references missing Directory '$caSource'!"
    }
}
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($CaView) | Out-Null

# 4b. Verify ICE63 RemoveExistingProducts placement in InstallExecuteSequence (prevents MSI Error 2613)
$SeqView = $Database.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $Database, @('SELECT `Action`, `Sequence` FROM `InstallExecuteSequence` ORDER BY `Sequence`'))
$SeqView.GetType().InvokeMember("Execute", "InvokeMethod", $null, $SeqView, $null) | Out-Null
$SeqRows = @()
$ActionSeq = @{}
while ($true) {
    $Rec = $SeqView.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $SeqView, $null)
    if (-not $Rec) { break }
    $act = $Rec.GetType().InvokeMember("StringData", "GetProperty", $null, $Rec, @(1))
    $seq = [int]($Rec.GetType().InvokeMember("StringData", "GetProperty", $null, $Rec, @(2)))
    $SeqRows += [PSCustomObject]@{ Action = $act; Sequence = $seq }
    $ActionSeq[$act] = $seq
}
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($SeqView) | Out-Null
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($Database) | Out-Null
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($Installer) | Out-Null

if ($TableNames -contains "Environment") {
    throw "SECURITY INVARIANT VIOLATION: Compiled MSI contains an 'Environment' table!"
}
if (-not $ActionSeq.ContainsKey("RemoveExistingProducts")) {
    throw "MSI UPGRADE VIOLATION: InstallExecuteSequence is missing 'RemoveExistingProducts'!"
}
$repSeq = $ActionSeq["RemoveExistingProducts"]
$initSeq = if ($ActionSeq.ContainsKey("InstallInitialize")) { $ActionSeq["InstallInitialize"] } else { -1 }
$finSeq = if ($ActionSeq.ContainsKey("InstallFinalize")) { $ActionSeq["InstallFinalize"] } else { -1 }
if ($repSeq -lt $finSeq) {
    $anchorName = $null
    $anchorSeq = -1
    foreach ($cand in @("InstallInitialize", "InstallExecute", "InstallExecuteAgain")) {
        if ($ActionSeq.ContainsKey($cand)) {
            $cSeq = $ActionSeq[$cand]
            if ($cSeq -lt $repSeq -and $cSeq -gt $anchorSeq) {
                $anchorSeq = $cSeq
                $anchorName = $cand
            }
        }
    }
    if ($anchorSeq -lt 0 -or $repSeq -le $initSeq) {
        throw "MSI ICE63 / ERROR 2613 VIOLATION: RemoveExistingProducts ($repSeq) is in an invalid location (InstallInitialize=$initSeq)!"
    }
    $intervening = @($SeqRows | Where-Object { $_.Sequence -gt $anchorSeq -and $_.Sequence -lt $repSeq } | ForEach-Object { "$($_.Action)($($_.Sequence))" })
    if ($intervening.Count -gt 0) {
        throw "MSI ICE63 / ERROR 2613 VIOLATION: Actions found between $anchorName($anchorSeq) and RemoveExistingProducts($repSeq): $($intervening -join ', ')"
    }
    Write-Host "  -> ICE63 RemoveExistingProducts sequence PASS ($anchorName=$anchorSeq -> RemoveExistingProducts=$repSeq, 0 intervening actions)." -ForegroundColor Green
} else {
    Write-Host "  -> ICE63 RemoveExistingProducts sequence PASS (after InstallFinalize=$finSeq -> RemoveExistingProducts=$repSeq)." -ForegroundColor Green
}
Write-Host "  -> MSI tables verified ($($TableNames -join ', ')); 'Environment' table is ABSENT (100% Zero-Touch PATH)." -ForegroundColor Green

# Step 5: Authenticode Signing of MSI, Defender Pre-Flight Scan & WDSI Manifest
Write-Host "[5/5] Running Authenticode MSI signing, Defender scan & SHA256SUMS generation..." -ForegroundColor Cyan
if (Test-Path $SubmitScript) {
    # Sign ONLY the MSI here; the exe was signed exactly once before being embedded.
    $subArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $SubmitScript, "-Version", $Version, "-Files", $MsiOut)
    if ($SkipDefenderScan) { $subArgs += "-SkipDefenderScan" }
    & powershell @subArgs
}

$SumsLines = @()
foreach ($art in (Get-ChildItem -Path $WinDeployDir -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | Sort-Object Name)) {
    $hash = (Get-FileHash -Path $art.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $SumsLines += "$hash  $($art.Name)"
}
[System.IO.File]::WriteAllLines((Join-Path $WinDeployDir "SHA256SUMS.txt"), $SumsLines, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " Windows Packaging Complete: $WinDeployDir" -ForegroundColor Green
Get-ChildItem -Path $WinDeployDir | Format-Table Name, Length, LastWriteTime -AutoSize
Write-Host "============================================================`n" -ForegroundColor Green
