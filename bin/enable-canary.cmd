@echo off
if "%~1"=="" exit /b 2
set "npaGuardEnv=%TEMP%\npa-guard-%RANDOM%-%RANDOM%.txt"
"%~1" "%~dp0npa.js" canary-guard --auto --cmd-env-file "%npaGuardEnv%"
if errorlevel 1 (
    echo Canary terminal activation failed. 1>&2
    exit 2
)
set "NPA_CANARY_GUARD={"autoProject":true}"
set "NPA_CANARY_ORIGINAL_BASH_ENV="
set /p "NODE_OPTIONS=" < "%npaGuardEnv%"
set /p "BASH_ENV=" < "%npaGuardEnv%.BASH_ENV"
set /p "NPA_CANARY_NODE=" < "%npaGuardEnv%.NPA_CANARY_NODE"
set /p "NPA_CANARY_CLI=" < "%npaGuardEnv%.NPA_CANARY_CLI"
set /p "NPA_CANARY_ORIGINAL_BASH_ENV=" < "%npaGuardEnv%.NPA_CANARY_ORIGINAL_BASH_ENV"
del "%npaGuardEnv%" "%npaGuardEnv%.BASH_ENV" "%npaGuardEnv%.NPA_CANARY_NODE" "%npaGuardEnv%.NPA_CANARY_CLI" "%npaGuardEnv%.NPA_CANARY_ORIGINAL_BASH_ENV"
set "npaGuardEnv="
doskey powershell="%~1" "%~dp0npa.js" canary-run --auto -- powershell.exe $*
doskey pwsh="%~1" "%~dp0npa.js" canary-run --auto -- pwsh.exe $*
doskey bash="%~1" "%~dp0npa.js" canary-run --auto -- bash.exe $*
doskey sh="%~1" "%~dp0npa.js" canary-run --auto -- sh.exe $*
