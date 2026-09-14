@echo off
REM Double-click this instead of the .exe if the window still closes too fast.
REM The executable detects a double-click on its own, but a batch file keeping
REM the window open works even if that detection fails on your Windows build.
setlocal
cd /d "%~dp0"

set "EXE="
for %%f in (aiexpose_*_windows_amd64_minimal.exe) do set "EXE=%%f"
if not defined EXE for %%f in (aiexpose_*_windows_amd64.exe) do set "EXE=%%f"
if not defined EXE for %%f in (aiexpose.exe) do set "EXE=%%f"

if not defined EXE (
  echo No aiexpose executable was found in this folder.
  echo.
  echo If you downloaded one, your antivirus may have quarantined it.
  echo See ANTIVIRUS.md next to this file.
  echo.
  pause
  exit /b 1
)

echo Running %EXE% ...
echo.
"%EXE%" %*
echo.
echo Exit code: %ERRORLEVEL%
pause
