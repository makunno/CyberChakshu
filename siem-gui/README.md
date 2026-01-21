# FreeKhana SIEM Desktop Applications

This repository contains two different desktop implementations of the FreeKhana SIEM tool. Choose the appropriate implementation based on your needs:

## 🚀 Recommended: WebView + Flask Implementation

**Location**: `webview-gui/` (Recommended)
**Technology**: PyWebView + Flask + React
**Status**: ✅ Active, Full Featured

### Why Choose This?
- **Modern UI**: Same React interface as the web application
- **Complete Features**: All 56+ log parsers, ML analysis, attack chains
- **Cross-Platform**: Works on Windows, macOS, Linux
- **Active Development**: Regularly maintained and updated

### Quick Start
```bash
cd webview-gui
python setup.py    # Install dependencies
python run.py      # Launch application
```

## ⚠️ Legacy: PySide6 Implementation

**Location**: `pyside6-gui/` (Deprecated)
**Technology**: PySide6 (Qt for Python)
**Status**: ❌ Outdated, Limited Features

### Why Avoid This?
- **Outdated UI**: Basic Qt interface, not modern
- **Limited Features**: Only basic parsers and ML
- **Windows Only**: PySide6 has platform limitations
- **Not Maintained**: No longer actively developed

### Directory Structure

```
siem-gui/
├── webview-gui/          # ⭐ RECOMMENDED - Modern desktop app
│   ├── main.py           # PyWebView launcher
│   ├── api/              # Flask backend
│   ├── parsers/          # 56+ log parsers
│   ├── ml/               # ML analysis engine
│   ├── static/           # React frontend
│   └── README.md         # Detailed documentation
│
├── pyside6-gui/          # ❌ DEPRECATED - Legacy Qt app
│   ├── src/              # PySide6 application
│   ├── resources/        # Qt stylesheets
│   └── README.md         # Migration guide
│
└── README.md             # This file
```

## 📊 Feature Comparison

| Feature | WebView + Flask | PySide6 |
|---------|----------------|---------|
| **UI Modernity** | ⭐⭐⭐⭐⭐ React, responsive | ⭐⭐ Basic Qt interface |
| **Log Parsers** | ⭐⭐⭐⭐⭐ 56+ complete | ⭐⭐ Limited (basic) |
| **ML Features** | ⭐⭐⭐⭐⭐ Full anomaly detection | ⭐⭐⭐ Basic isolation forest |
| **Cross-Platform** | ⭐⭐⭐⭐⭐ Windows/macOS/Linux | ⭐⭐ Windows only |
| **Maintenance** | ⭐⭐⭐⭐⭐ Active | ❌ None |
| **Setup Complexity** | ⭐⭐⭐⭐ Simple | ⭐⭐⭐ Moderate |

## 🎯 Which One Should You Use?

### Use `webview-gui/` if you want:
- Modern, professional UI matching the web app
- Complete feature set with all log parsers
- Cross-platform compatibility
- Active development and support
- Future updates and improvements

### Only use `pyside6-gui/` if you:
- Have specific PySide6/Qt requirements
- Need to run on older Windows systems
- Are doing legacy maintenance (not recommended for new projects)

## 🔧 System Requirements

### WebView + Flask (Recommended)
- Python 3.8+
- PyWebView, Flask, Flask-CORS
- NumPy, scikit-learn (for ML features)
- Works on Windows, macOS, Linux

### PySide6 (Legacy)
- Python 3.8+
- PySide6, pandas, numpy, scikit-learn
- Windows only (limited cross-platform support)

## 📝 Contributing

For new development, please contribute to the `webview-gui/` implementation. The PySide6 implementation is legacy code and should not receive new features.

## 📄 License

This project is part of the FreeKhana SIEM suite and follows the same open-source licensing terms.