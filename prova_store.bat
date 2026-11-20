@echo off
setlocal
cd /d "%~dp0"
REM ============================================================================
REM  Web Forensic Extractor - prova locale del pacchetto Store (senza firma)
REM  Richiede la Modalita' sviluppatore: Impostazioni > Sistema > Per sviluppatori
REM  SPDX-License-Identifier: EUPL-1.2
REM ============================================================================
if not exist "dist_store\msix_layout\AppxManifest.xml" (
  echo Eseguire prima build_store.bat.
  goto :err
)
echo.
echo  1 = Installa il pacchetto di prova
echo  2 = Rimuovi il pacchetto di prova
echo.
choice /C 12 /N /M "Scelta (1 o 2): "
if errorlevel 2 goto :rimuovi

powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-AppxPackage -Register (Resolve-Path 'dist_store\msix_layout\AppxManifest.xml')" || goto :err
echo.
echo Installato: cercare "Web Forensic Extractor" nel menu Start.
echo Le acquisizioni vanno in Documenti\Web Forensic Extractor\Acquisizioni.
pause
exit /b 0

:rimuovi
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-AppxPackage | Where-Object { $_.InstallLocation -like '*dist_store\msix_layout*' } | Remove-AppxPackage" || goto :err
echo Pacchetto di prova rimosso. Le acquisizioni nei Documenti non vengono cancellate.
pause
exit /b 0

:err
echo.
echo ERRORE.
pause
exit /b 1
