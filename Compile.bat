@echo off

:: Set up directories
set BUILD_DIR=build
set RELEASE_BUILD_DIR=%BUILD_DIR%\Release
set DEBUG_BUILD_DIR=%BUILD_DIR%\Debug

if exist %BUILD_DIR% (
    rmdir /s /q %BUILD_DIR%
    echo Removed previous build.
)

:: Create build directories
if not exist %BUILD_DIR% (
    mkdir %BUILD_DIR%
)
if not exist %RELEASE_BUILD_DIR% (
    mkdir %RELEASE_BUILD_DIR%
)
if not exist %DEBUG_BUILD_DIR% (
    mkdir %DEBUG_BUILD_DIR%
)

:: Configure and build in Release mode
cd %RELEASE_BUILD_DIR%
cmake -DCMAKE_BUILD_TYPE=Release ../..
if errorlevel 1 (
    echo Error: Failed to configure Release build.
    exit /b 1
)
cmake --build . --config Release
if errorlevel 1 (
    echo Error: Failed to build Release.
    exit /b 1
)

:: Configure and build in Debug mode
cd ../Debug
cmake -DCMAKE_BUILD_TYPE=Debug ../..
if errorlevel 1 (
    echo Error: Failed to configure Debug build.
    exit /b 1
)
cmake --build . --config Debug
if errorlevel 1 (
    echo Error: Failed to build Debug.
    exit /b 1
)

:: Return to the original directory
cd ../..

echo Build process complete. Executables are in %BUILD_DIR%\Release and %BUILD_DIR%\Debug.
pause
