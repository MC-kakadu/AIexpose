@echo off
REM Builds the offline malware hash index. Run this once.
REM
REM Put the VirusShare .md5 files in a folder named virusHashDb next to this
REM file, then double-click. It reads about 1.5 GB and writes a single index of
REM roughly 244 MB to %USERPROFILE%\.aiexpose\hashdb.bin. Nothing is downloaded
REM and nothing is uploaded. Every scan afterwards uses it automatically.
setlocal
cd /d "%~dp0"

set "DIR=%~1"
if not defined DIR set "DIR=virusHashDb"

if not exist "%DIR%\" (
  echo Folder "%DIR%" was not found next to this file.
  echo.
  echo Download the MD5 lists from https://virusshare.com/hashes,
  echo put them in a folder called virusHashDb here, and run this again.
  echo.
  pause
  exit /b 1
)

set "EXE="
for %%f in (aiexpose_*_windows_amd64.exe) do set "EXE=%%f"
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

echo Building the malware hash index with %EXE% ...
echo This takes about 20 seconds and uses roughly 400 MB of memory.
echo.
"%EXE%" --build-hashdb "%DIR%"
echo.
echo Exit code: %ERRORLEVEL%
pause
