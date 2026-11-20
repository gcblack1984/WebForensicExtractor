@echo off
setlocal
cd /d "%~dp0"
REM ============================================================================
REM  Web Forensic Extractor - creazione del pacchetto MSIX per il Microsoft Store
REM  Copyright (C) 2026 Giovanni Ciccarese
REM  Concesso in licenza a norma dell'EUPL v. 1.2 - SPDX-License-Identifier: EUPL-1.2
REM ============================================================================
REM  PRIMA DI ESEGUIRE: copiare qui sotto i valori indicati in Partner Center,
REM  pagina dell'app > Gestione prodotto > Identita' del prodotto.
REM ----------------------------------------------------------------------------
set "IDENTITY_NAME=CICCARESEGiovanni.WebForensicExtractor"
set "PUBLISHER=CN=E9C25802-DEC0-43B0-BFF6-582461D661F8"
set "PUBLISHER_DISPLAY_NAME=CICCARESE Giovanni"
set "DISPLAY_NAME=Web Forensic Extractor"
set "VERSION=4.2.0.0"
REM ----------------------------------------------------------------------------
REM  Requisiti: Python 3.10+ a 64 bit, Windows SDK (per MakeAppx), internet.
REM ============================================================================

echo %IDENTITY_NAME% %PUBLISHER% %PUBLISHER_DISPLAY_NAME% | findstr /C:"INSERIRE" >nul && (
  echo.
  echo Compila prima IDENTITY_NAME, PUBLISHER e PUBLISHER_DISPLAY_NAME
  echo all'inizio di build_store.bat con i dati di Partner Center.
  goto :err
)

for %%F in (webacq_gui.py verbale.py AVVISI.txt store\AppxManifest.template.xml store\crea_msix.ps1 store\splash.png store\icon.ico store\Assets\Square44x44Logo.png store\Assets\Square150x150Logo.png store\Assets\Wide310x150Logo.png store\Assets\StoreLogo.png) do (
  if not exist "%%F" ( echo File mancante: %%F & goto :err )
)
set "LIC="
for %%L in (LICENZA.txt LICENSE) do if exist "%%L" set "LIC=1"
if not defined LIC ( echo File di licenza mancante: LICENZA.txt o LICENSE & goto :err )

python -m venv venv || goto :err
call venv\Scripts\activate.bat

python -m pip install --upgrade pip
pip install playwright ntplib asn1crypto python-docx ttkbootstrap==1.10.1 pyinstaller || goto :err

REM Installa Chromium DENTRO il pacchetto playwright, cosi' PyInstaller lo include
set PLAYWRIGHT_BROWSERS_PATH=0
REM --no-shell: non scarica la seconda copia "headless" di Chromium, che il programma non usa
python -m playwright install chromium --no-shell || goto :err

REM Versione Store: grafica originale (store\), senza emblemi istituzionali
pyinstaller --noconfirm --clean --onedir --windowed ^
  --name WebForensicExtractor ^
  --distpath dist_store --workpath build_store ^
  --icon store\icon.ico ^
  --add-data "store\splash.png;." ^
  --add-data "store\icon.ico;." ^
  --collect-all playwright --collect-all asn1crypto --collect-all docx ^
  --collect-all ttkbootstrap ^
  webacq_gui.py || goto :err

set "APP=dist_store\WebForensicExtractor"

REM Licenza, avvisi e codice sorgente accompagnano sempre il programma (artt. 3 e 5 EUPL)
for %%F in (LICENZA.txt LICENSE AVVISI.txt) do if exist "%%F" copy /Y "%%F" "%APP%\" >nul
if not exist "%APP%\sorgenti" mkdir "%APP%\sorgenti"
for %%F in (webacq_gui.py verbale.py build_windows.bat build_store.bat splash.png LICENZA.txt LICENSE AVVISI.txt README.md) do (
  if exist "%%F" copy /Y "%%F" "%APP%\sorgenti\" >nul
)
xcopy /E /I /Y /Q store "%APP%\sorgenti\store" >nul || goto :err

echo.
echo Impronta SHA-256 dell'eseguibile:
certutil -hashfile "%APP%\WebForensicExtractor.exe" SHA256

powershell -NoProfile -ExecutionPolicy Bypass -File store\crea_msix.ps1 -AppDir "%APP%" -OutDir "dist_store" || goto :err

echo.
echo ============================================================================
echo  Fatto. Prossimi passi:
echo   1. prova_store.bat         per installare e provare il pacchetto
echo   2. Windows App Cert Kit    per il test di certificazione
echo   3. Partner Center          per caricare il file .msix in dist_store
echo ============================================================================
pause
exit /b 0

:err
echo.
echo ERRORE durante la creazione del pacchetto per lo Store.
pause
exit /b 1
