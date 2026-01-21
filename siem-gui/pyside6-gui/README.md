# FreeKhana SIEM - PySide6 Desktop Application

This directory contains the legacy PySide6-based desktop application. **Note: This implementation is outdated and not recommended for new use.**

## ⚠️ Deprecated

This PySide6 implementation is **no longer maintained**. The recommended desktop application is located in the `../webview-gui/` directory, which provides:

- Modern React UI (same as web app)
- Better user experience
- More complete feature set
- Active maintenance

## Legacy Features

- Basic PySide6 GUI with dark theme
- Limited log parsing (only SSH and Apache initially)
- Basic ML anomaly detection
- Windows-only (due to PySide6 limitations)

## Directory Structure

```
pyside6-gui/
├── src/
│   └── main.py         # Main PySide6 application
├── resources/
│   └── modern_styles.qss  # Qt stylesheet
├── tests/
│   ├── test_core.py    # Core functionality tests
│   └── test_basic.py   # Basic tests
├── sample-ssh.log      # Sample SSH log for testing
├── sample-apache.log   # Sample Apache log for testing
└── setup_production.py # Production setup script
```

## Usage (Not Recommended)

```bash
cd pyside6-gui
python src/main.py
```

## Migration

Please use the WebView implementation in `../webview-gui/` instead:

```bash
cd ../webview-gui
python run.py
```