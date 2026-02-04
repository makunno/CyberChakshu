# FreeKhana SIEM - Build Instructions

## Prerequisites

1. Install Python 3.9+
2. Install required packages:
   ```bash
   pip install PySide6 flask werkzeug requests scikit-learn numpy
   pip install pyinstaller
   ```

## Building EXEs

### Option 1: Using the build script (recommended)

```bash
cd siem-gui/webview-gui
build.bat
```

Choose:
- [1] FreeKhana-Browser.exe - Lightweight, opens online frontend
- [2] FreeKhana-Full.exe - Full bundle with Flask backend
- [3] Build Both

### Option 2: Manual build commands

**Browser EXE (Online Only):**
```bash
pyinstaller --clean --name "FreeKhana-Browser" --windowed --onefile main_simple.py
```

**Full EXE (Bundled Backend):**
```bash
pyinstaller --clean --name "FreeKhana-Full" --windowed --onefile ^
    --collect-all flask ^
    --collect-all sklearn ^
    --hidden-import PySide6.QtWebEngineWidgets ^
    --hidden-import PySide6.QtWebEngineCore ^
    main.py
```

## Frontend Files

For the Full EXE to serve a local frontend:

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

## Output

EXEs will be in the `dist/` folder:
- `FreeKhana-Browser.exe` - Opens https://freekhana-frontend.pages.dev
- `FreeKhana-Full.exe` - Bundled Flask backend (serves from static folder or online)

## Notes

- The Browser EXE is smaller (~50MB) and loads faster
- The Full EXE is larger (~200MB) but works offline
- Both EXEs require Qt WebEngine runtime (included by PyInstaller)
