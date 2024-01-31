@echo off
setlocal enabledelayedexpansion

set RSGSVR_FILENAME=rsgsvr.py
set RSGSVR_PATH=%~dp0\!RSGSVR_FILENAME!

python3 --version 2>&1 | findstr /C:"Python 3." > NUL
if !ERRORLEVEL! EQU 0 (
  set PYTHON=python3
) else (
  python --version 2>&1 | findstr /C:"Python 3." > NUL
  if !ERRORLEVEL! NEQ 0 (
    call :deploy_python3
  ) else (
    set PYTHON=python
  )
)
call :makesure_rsgsvr

!PYTHON! !RSGSVR_PATH!

pause
exit /b 0


:makesure_rsgsvr
if not exist !RSGSVR_PATH! (
  set RSGSVR_DIR=%TEMP%\rsgsvr
  set RSGSVR_SAVE_AS=!RSGSVR_DIR!\!RSGSVR_FILENAME!
  set RSGSVR_URL=https://raw.githubusercontent.com/spearmin10/rsgen/main/!RSGSVR_FILENAME!

  mkdir !RSGSVR_DIR! 2> NUL
  curl -Lo "!RSGSVR_SAVE_AS!" -H "Cache-Control: no-cache, no-store" "!RSGSVR_URL!" 2> NUL

  set RSGSVR_PATH=!RSGSVR_DIR!\!RSGSVR_FILENAME!
)
exit /b 0


:deploy_python3
set PYTHON3_FILENAME=python-3.11.1-embed-win32.zip
set PYTHON3_SAVE_AS=%TEMP%\!PYTHON3_FILENAME!
set PYTHON3_DEPLOYMENT_DIR=%TEMP%\rsgsvr\python3.11.1
set PYTHON3_URL=https://github.com/spearmin10/rsgen/blob/main/bin/!PYTHON3_FILENAME!?raw=true

if not exist !PYTHON3_DEPLOYMENT_DIR!\python.exe (
  curl -Lo "!PYTHON3_SAVE_AS!" -H "Cache-Control: no-cache, no-store" "!PYTHON3_URL!" 2> NUL
  powershell -command "Expand-Archive -Force '!PYTHON3_SAVE_AS!' '!PYTHON3_DEPLOYMENT_DIR!'"
)
set PYTHON=!PYTHON3_DEPLOYMENT_DIR!\python
exit /b 0
