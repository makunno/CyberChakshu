@echo off
REM Build FreeKhana Full EXE (Browser + Flask Backend)
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
if exist "dist\FreeKhana-Full.exe" (
    echo Build complete! EXE: dist/FreeKhana-Full.exe
    echo Size: ~312 MB (embedded webview + Flask backend)
) else (
    echo Build may have failed. Check dist folder.
)
echo.
pause
