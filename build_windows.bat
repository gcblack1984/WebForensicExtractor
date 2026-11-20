@echo off
setlocal
cd /d "%~dp0"
REM ============================================================================
REM  Web Forensic Extractor - creazione della versione PORTABILE per Windows
REM  Copyright (C) 2026 Giovanni Ciccarese
REM  Concesso in licenza a norma dell'EUPL v. 1.2 - SPDX-License-Identifier: EUPL-1.2
REM ============================================================================
REM  Richiede Python 3.10+ a 64 bit (con tkinter, incluso nell'installer ufficiale).
REM  File facoltativi: icon.ico (altrimenti si usa store\icon.ico) e
REM  stemma_repubblica.png (se manca, il verbale non propone lo stemma predefinito).
REM ============================================================================

for %%F in (webacq_gui.py verbale.py splash.png AVVISI.txt) do (
  if not exist "%%F" ( echo File mancante: %%F & goto :err )
)
set "LIC="
for %%L in (LICENZA.txt LICENSE) do if exist "%%L" set "LIC=1"
if not defined LIC ( echo File di licenza mancante: LICENZA.txt o LICENSE & goto :err )

set "ICON=icon.ico"
if not exist "%ICON%" set "ICON=store\icon.ico"
if not exist "%ICON%" ( echo Icona mancante: icon.ico o store\icon.ico & goto :err )
set "STEMMA_ARG="
if exist stemma_repubblica.png set "STEMMA_ARG=--add-data stemma_repubblica.png;."

python -m venv venv || goto :err
call venv\Scripts\activate.bat

python -m pip install --upgrade pip
pip install playwright ntplib asn1crypto python-docx ttkbootstrap==1.10.1 pyinstaller || goto :err

REM Installa Chromium DENTRO il pacchetto playwright, cosi' PyInstaller lo include
set PLAYWRIGHT_BROWSERS_PATH=0
REM --no-shell: non scarica la seconda copia "headless" di Chromium, che il programma non usa
python -m playwright install chromium --no-shell || goto :err

pyinstaller --noconfirm --clean --onedir --windowed ^
  --name WebForensicExtractor ^
  --icon "%ICON%" ^
  --add-data "splash.png;." ^
  --add-data "%ICON%;." ^
  %STEMMA_ARG% ^
  --collect-all playwright --collect-all asn1crypto --collect-all docx ^
  --collect-all ttkbootstrap ^
  webacq_gui.py || goto :err

set "APP=dist\WebForensicExtractor"

REM Licenza, avvisi e codice sorgente accompagnano sempre l'eseguibile (artt. 3 e 5 EUPL)
for %%F in (LICENZA.txt LICENSE AVVISI.txt) do if exist "%%F" copy /Y "%%F" "%APP%\" >nul
if not exist "%APP%\sorgenti" mkdir "%APP%\sorgenti"
for %%F in (webacq_gui.py verbale.py build_windows.bat build_store.bat splash.png icon.ico stemma_repubblica.png LICENZA.txt LICENSE AVVISI.txt README.md) do (
  if exist "%%F" copy /Y "%%F" "%APP%\sorgenti\" >nul
)

echo.
echo Build completata: %APP%\WebForensicExtractor.exe
certutil -hashfile "%APP%\WebForensicExtractor.exe" SHA256
pause
exit /b 0

:err
echo.
echo ERRORE durante la build.
pause
exit /b 1
