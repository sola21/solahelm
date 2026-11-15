@echo off
setlocal
chcp 65001 >nul
title SolaHelm: update panel
rem ------------------------------------------------------------------------------------------
rem  SolaHelm panel updater (Windows + WSL).
rem  1) copies this project folder to the staging folder (default C:\hy2panel), keeping your
rem     .env, data, .venv and databases there untouched;
rem  2) runs the installer inside WSL as root, which updates /opt/hy2panel and restarts the panel.
rem  Usage: double-click, or  update-panel.bat [staging-folder]
rem ------------------------------------------------------------------------------------------
set "SRC=%~dp0"
if "%SRC:~-1%"=="\" set "SRC=%SRC:~0,-1%"
set "DEST=C:\hy2panel"
if not "%~1"=="" set "DEST=%~1"

echo.
echo  Source : %SRC%
echo  Staging: %DEST%
echo.

if /i "%SRC%"=="%DEST%" goto run
if not exist "%DEST%" mkdir "%DEST%"
echo [1/2] Copying files...
robocopy "%SRC%" "%DEST%" /E /XD .venv venv data __pycache__ .git /XF .env *.db *.db-wal *.db-shm *.key *.pem *.pyc /NFL /NDL /NJH /NJS /NP >nul
if errorlevel 8 (
  echo.
  echo  ERROR: copying failed.
  pause
  exit /b 1
)

:run
set "DESTF=%DEST:\=/%"
for /f "usebackq delims=" %%P in (`wsl wslpath -a "%DESTF%"`) do set "WDEST=%%P"
if "%WDEST%"=="" (
  echo.
  echo  ERROR: WSL is not available or the folder path cannot be converted.
  pause
  exit /b 1
)
echo [2/2] Running the installer in WSL: %WDEST%/deploy/install-linux.sh
echo.
wsl -u root -- bash "%WDEST%/deploy/install-linux.sh"
if errorlevel 1 (
  echo.
  echo  ERROR: the installer finished with an error. Read the messages above.
  pause
  exit /b 1
)
echo.
echo  Installed version:
wsl -u root -- grep VERSION /opt/hy2panel/app/version.py
echo.
echo  Done. Refresh the panel page in the browser (Ctrl+F5).
pause
