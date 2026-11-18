@echo off
rem Starter wsiEKSPORT fuld-myndighed-eksporten. Kaldes af Windows Task Scheduler.
rem Kører uafhængigt af den aktuelle arbejdsmappe og returnerer scriptets exit-kode
rem (0 = ok, 1 = mindst én institution fejlede, 2 = konfigurationsfejl).

setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo FEJL: .venv mangler i "%~dp0". Se README.md, afsnittet Installation. 1>&2
    exit /b 3
)

".venv\Scripts\python.exe" "wsieksport_fuld_myndighed.py" %*
exit /b %ERRORLEVEL%
