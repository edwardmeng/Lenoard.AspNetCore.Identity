@echo Off
set config=%1
if "%config%" == "" (
   set config=Release
)
set version=
if not "%PackageVersion%" == "" (
   set version=-Version %PackageVersion%
) else (
   set version=-Version 0.1.0
)
REM Determine msbuild path
set msbuildtmp="%ProgramFiles%\MSBuild\14.0\bin\msbuild"
if exist %msbuildtmp% set msbuild=%msbuildtmp%
set msbuildtmp="%ProgramFiles(x86)%\MSBuild\14.0\bin\msbuild"
if exist %msbuildtmp% set msbuild=%msbuildtmp%
set VisualStudioVersion=14.0

REM Package restore
echo.
echo Running package restore...
call :ExecuteCmd nuget.exe restore ..\Lenoard.AspNetCore.Identity.sln -NonInteractive -ConfigFile nuget.config
IF %ERRORLEVEL% NEQ 0 goto error

echo Building solution...
call :ExecuteCmd %msbuild% "..\Lenoard.AspNetCore.Identity.sln" /p:Configuration="%config%" /m /v:M /fl /flp:LogFile=msbuild.log;Verbosity=Normal /nr:false
IF %ERRORLEVEL% NEQ 0 goto error

echo running unit tests...
dotnet test %cd%\..\build\Lenoard.AspNetCore.Identity.UnitTests
IF %ERRORLEVEL% NEQ 0 goto error

echo Packaging...
set libtmp=%cd%\lib
set packagestmp="%cd%\packages"
if not exist %libtmp% mkdir %libtmp%
if not exist %packagestmp% mkdir %packagestmp%

if not exist %libtmp%\netstandard1.3 mkdir %libtmp%\netstandard1.3
copy ..\build\Lenoard.AspNetCore.Identity\bin\%config%\netstandard1.3\Lenoard.AspNetCore.Identity.dll %libtmp%\netstandard1.3 /Y
copy ..\build\Lenoard.AspNetCore.Identity\bin\%config%\netstandard1.3\Lenoard.AspNetCore.Identity.xml %libtmp%\netstandard1.3 /Y
copy ..\build\Lenoard.AspNetCore.Identity\bin\%config%\netstandard1.3\Lenoard.AspNetCore.Identity.deps.json %libtmp%\netstandard1.3 /Y


call :ExecuteCmd nuget.exe pack "%cd%\Lenoard.AspNetCore.Identity.nuspec" -OutputDirectory %packagestmp% %version%
IF %ERRORLEVEL% NEQ 0 goto error

rmdir %libtmp% /S /Q

goto end

:: Execute command routine that will echo out when error
:ExecuteCmd
setlocal
set _CMD_=%*
call %_CMD_%
if "%ERRORLEVEL%" NEQ "0" echo Failed exitCode=%ERRORLEVEL%, command=%_CMD_%
exit /b %ERRORLEVEL%

:error
endlocal
echo An error has occurred during build.
call :exitSetErrorLevel
call :exitFromFunction 2>nul

:exitSetErrorLevel
exit /b 1

:exitFromFunction
()

:end
endlocal
echo Build finished successfully.