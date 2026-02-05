# FreeKhana SIEM - Build Instructions

## Prerequisites

1. Install Python 3.9+
2. Install required packages:
   ```bash
   pip install PySide6 flask werkzeug requests scikit-learn numpy
   pip install pyinstaller
   ```

## Building EXEs

### Using the build script (recommended)

```bash
cd siem-gui/webview-gui
build.bat
```

Choose:
- [1] **FreeKhana-Browser.exe** (~201 MB) - Embedded webview
- [2] **FreeKhana-Full.exe** (~312 MB) - Embedded webview + Flask backend
- [3] Build Both

### Manual build commands

**Browser EXE (Embedded WebView):**
```bash
pyinstaller --clean --name "FreeKhana-Browser" --windowed --onefile main_browser.py
```

**Full EXE (WebView + Flask Backend):**
```bash
pyinstaller --clean --name "FreeKhana-Full" --windowed --onefile ^
    --hidden-import PySide6.QtWebEngineWidgets ^
    --hidden-import PySide6.QtWebEngineCore ^
    --hidden-import flask ^
    --hidden-import werkzeug ^
    main.py
```

## Output

EXEs will be in the `dist/` folder:
- `FreeKhana-Browser.exe` - Opens https://freekhana-frontend.pages.dev in embedded webview
- `FreeKhana-Full.exe` - Full bundled version with Flask backend

## Frontend for Full EXE

For the Full EXE to serve a local frontend (instead of using online):

1. Build the React frontend:
   ```bash
   cd ../../siem-tool/frontend
   npm run build
   ```

2. Copy frontend files to static folder:
   ```bash
   cd ../webview-gui
   copy_frontend.bat
   ```

3. Rebuild the Full EXE

## Notes

- Both EXEs include Qt WebEngine (Chromium-based) for embedded browsing
- Browser EXE is ~201 MB
- Full EXE is ~312 MB (includes Flask, sklearn, numpy)
- EXEs require Windows with proper runtime (included by PyInstaller)
