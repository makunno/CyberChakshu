@echo off
REM Build FreeKhana Browser EXE (Embedded WebView)
echo Building FreeKhana-Browser.exe...

pyinstaller --clean --noconfirm ^
    --name "FreeKhana-Browser" ^
    --windowed ^
    --onefile ^
    main_browser.py

echo.
if exist "dist\FreeKhana-Browser.exe" (
    echo Build complete! EXE: dist/FreeKhana-Browser.exe
    echo Size: ~201 MB (embedded Qt WebEngine)
) else (
    echo Build may have failed. Check dist folder.
)
echo.
pause
