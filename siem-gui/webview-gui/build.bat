@echo off
REM FreeKhana Build Script - Builds both EXE versions

echo ============================================
echo FreeKhana SIEM Build Script
echo ============================================
echo.

REM Install PyInstaller if not installed
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
    echo.
)

echo Choose build option:
echo [1] FreeKhana-Browser.exe  - Embedded webview (~201 MB)
echo [2] FreeKhana-Full.exe     - Webview + Flask backend (~312 MB)
echo [3] Build Both
echo.

set /p choice="Enter choice [1-3]: "
if "%choice%"=="1" goto browser
if "%choice%"=="2" goto full
if "%choice%"=="3" goto both
echo Invalid choice
goto end

:browser
echo.
echo Building FreeKhana-Browser.exe...
pyinstaller --clean --noconfirm ^
    --name "FreeKhana-Browser" ^
    --windowed ^
    --onefile ^
    --icon "icon.ico" ^
    main_browser.py
echo.
echo ============================================
echo Build complete!
echo EXE: dist\FreeKhana-Browser.exe
echo ============================================
goto end

:full
echo.
echo Building FreeKhana-Full.exe...
pyinstaller --clean --noconfirm ^
    --name "FreeKhana-Full" ^
    --windowed ^
    --onefile ^
    --hidden-import PySide6.QtWebEngineWidgets ^
    --hidden-import PySide6.QtWebEngineCore ^
    --hidden-import flask ^
    --hidden-import werkzeug ^
    --icon "icon.ico" ^
    main.py
echo.
echo ============================================
echo Build complete!
echo EXE: dist\FreeKhana-Full.exe
echo ============================================
goto end

:both
echo.
echo Building FreeKhana-Browser.exe...
pyinstaller --clean --noconfirm ^
    --name "FreeKhana-Browser" ^
    --windowed ^
    --onefile ^
    --icon "icon.ico" ^
    main_browser.py

echo.
echo Building FreeKhana-Full.exe...
pyinstaller --clean --noconfirm ^
    --name "FreeKhana-Full" ^
    --windowed ^
    --onefile ^
    --hidden-import PySide6.QtWebEngineWidgets ^
    --hidden-import PySide6.QtWebEngineCore ^
    --hidden-import flask ^
    --hidden-import werkzeug ^
    --icon "icon.ico" ^
    main.py

echo.
echo ============================================
echo All builds complete!
echo EXEs in dist\ folder:
echo   - FreeKhana-Browser.exe (~201 MB)
echo   - FreeKhana-Full.exe (~312 MB)
echo ============================================
goto end

:end
echo.
pause
