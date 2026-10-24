# ======================================================================
# INTERNALTOOLS - HASH-FILE COMMAND AUTOMATED INSTALLER
# ======================================================================
$ErrorActionPreference = "Stop"

# Paths and targets configuration
$TargetDir = "C:\InternalTools"
$TargetExe = "$TargetDir\ith_xof.exe"
$SourceExe = "target\release\ith_hash.exe"
$MacroFile = "C:\InternalTools\macro.txt" 

Write-Host "--- ITH-XOF Native Command Installer ---" -ForegroundColor Cyan

# Check if binary was compiled
if (-not (Test-Path $SourceExe)) {
    Write-Error "Error: Build target '$SourceExe' not found. Run 'cargo build --release' first!"
}

# Ensure destination tool directory exists
if (-not (Test-Path $TargetDir)) {
    Write-Host "[*] Creating production suite deployment directory at $TargetDir..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $TargetDir | Out-Null
}

# Deploy engine binary to the application suite root
Write-Host "[*] Deploying native engine binary to $TargetExe..." -ForegroundColor Yellow
Copy-Item -Path $SourceExe -Destination $TargetExe -Force

# Inject integration rules into the Doskey engine macro workspace
Write-Host "[*] Configuring Doskey structural macro context inside $MacroFile..." -ForegroundColor Yellow
$MacroLine = "Hash-File=C:\InternalTools\ith_xof.exe `$`*"

if (-not (Test-Path $MacroFile)) {
    Set-Content -Path $MacroFile -Value $MacroLine -Encoding utf8
    Write-Host "[+] Created a fresh macro file containing the Hash-File schema." -ForegroundColor Green
} else {
    $Content = Get-Content -Path $MacroFile
    if ($Content -contains $MacroLine -or $Content -like "Hash-File=*") {
        Write-Host "[i] Entry schema 'Hash-File' already mapped inside the workspace. Overwriting safely..." -ForegroundColor Yellow
        $CleanContent = $Content | Where-Object { $_ -notlike "Hash-File=*" }
        $CleanContent + $MacroLine | Set-Content -Path $MacroFile -Encoding utf8
    } else {
        Add-Content -Path $MacroFile -Value "`n$MacroLine" -Encoding utf8
        Write-Host "[+] Appended the Hash-File interface command payload successfully." -ForegroundColor Green
    }
}

Write-Host "`n[SUCCESS] Deployment phase finalized. Native 'Hash-File' command interface is live." -ForegroundColor Green
Write-Host "Remember to reload your terminal environment macros (e.g. doskey /macrofile=$MacroFile)" -ForegroundColor Cyan
