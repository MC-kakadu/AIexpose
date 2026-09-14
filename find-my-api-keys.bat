@echo off
REM Searches the places people actually keep API keys: notes and text files on
REM the Desktop, in Documents and Downloads, plus any folder you name below.
REM
REM This is opt-in on purpose. Reading every text file in your documents is
REM what an information stealer does, so aiexpose only does it when asked.
REM Nothing is uploaded and nothing on this machine is changed. Key values are
REM masked in the report; the full key is never printed or stored.
setlocal
cd /d "%~dp0"

set "EXE="
for %%f in (aiexpose_*_windows_amd64.exe) do set "EXE=%%f"
if not defined EXE for %%f in (aiexpose_*_windows_arm64.exe) do set "EXE=%%f"
if not defined EXE for %%f in (aiexpose.exe) do set "EXE=%%f"

if not defined EXE (
  echo No aiexpose executable was found in this folder.
  echo If you downloaded one, your antivirus may have quarantined it.
  pause
  exit /b 1
)

echo.
echo Desktop, Documents and Downloads will be searched for API keys written
echo into notes and text files. Nothing is uploaded and nothing is changed.
echo Any key found is masked in the report.
echo.
set "EXTRA="
set /p EXTRA=Another folder to search too (e.g. D:\work), or press Enter to skip: 

echo.
if defined EXTRA (
  "%EXE%" --scan-docs --scan-dir "%EXTRA%" --html aiexpose-report.html --open %*
) else (
  "%EXE%" --scan-docs --html aiexpose-report.html --open %*
)
echo.
echo Exit code: %ERRORLEVEL%
pause
