# Web Forensic Extractor - crea il pacchetto MSIX per il Microsoft Store
# Copyright (C) 2026 Giovanni Ciccarese - SPDX-License-Identifier: EUPL-1.2
# Viene eseguito da build_store.bat, che imposta IDENTITY_NAME, PUBLISHER,
# PUBLISHER_DISPLAY_NAME, DISPLAY_NAME e VERSION.
param(
    [Parameter(Mandatory = $true)] [string]$AppDir,   # cartella prodotta da PyInstaller
    [Parameter(Mandatory = $true)] [string]$OutDir    # cartella in cui creare il pacchetto
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# Percorsi assoluti: MakeAppx non accetta percorsi relativi per il file di uscita
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$OutDir = (Resolve-Path $OutDir).Path
$AppDir = (Resolve-Path $AppDir).Path

$ver = $env:VERSION
if ($ver -notmatch '^\d+\.\d+\.\d+\.0$') {
    throw "VERSION deve avere quattro numeri e terminare con .0 (esempio 4.1.0.0)."
}

# MakeAppx.exe dal Windows SDK (versione piu' recente installata)
$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$makeappx = Get-ChildItem -Path $kits -Filter 'makeappx.exe' -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\' } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if (-not $makeappx) {
    throw "MakeAppx.exe non trovato: installare il Windows SDK (vedi la guida alla pubblicazione)."
}
Write-Host "MakeAppx: $($makeappx.FullName)"

# Struttura del pacchetto: programma + loghi + manifest
$layout = Join-Path $OutDir 'msix_layout'
if (Test-Path $layout) { Remove-Item $layout -Recurse -Force }
New-Item -ItemType Directory -Path $layout | Out-Null
Copy-Item -Path (Join-Path $AppDir '*') -Destination $layout -Recurse
Copy-Item -Path (Join-Path $here 'Assets') -Destination $layout -Recurse

function Esc([string]$s) { return [System.Security.SecurityElement]::Escape($s) }
$xml = Get-Content -Path (Join-Path $here 'AppxManifest.template.xml') -Raw -Encoding UTF8
$xml = $xml.Replace('{{IDENTITY_NAME}}', (Esc $env:IDENTITY_NAME))
$xml = $xml.Replace('{{PUBLISHER}}', (Esc $env:PUBLISHER))
$xml = $xml.Replace('{{PUBLISHER_DISPLAY_NAME}}', (Esc $env:PUBLISHER_DISPLAY_NAME))
$xml = $xml.Replace('{{DISPLAY_NAME}}', (Esc $env:DISPLAY_NAME))
$xml = $xml.Replace('{{VERSION}}', $ver)
$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Join-Path $layout 'AppxManifest.xml'), $xml, $utf8)

# Pacchetto (non firmato: il Microsoft Store lo firma al momento della pubblicazione)
$msix = Join-Path $OutDir ("WebForensicExtractor_{0}_x64.msix" -f $ver)
& $makeappx.FullName pack /d $layout /p $msix /o
if ($LASTEXITCODE -ne 0) { throw "MakeAppx ha restituito un errore ($LASTEXITCODE)." }

Write-Host ""
Write-Host "Pacchetto creato: $msix"
Write-Host ("SHA-256: " + (Get-FileHash -Path $msix -Algorithm SHA256).Hash)
