# 🔍 FreeKhana SIEM GUI Tool

A modern, beautiful Security Information and Event Management tool built with PySide6, featuring a sleek dark theme, advanced log parsing, ML-powered correlation analysis, and interactive visualizations. Inspired by modern web applications with professional styling.

## ✨ Features

### 🎨 **Modern Multi-View UI Design**
- **Welcome Screen**: Clean starting point with upload options and recent history
- **Analysis Dashboard**: Full-featured analysis view with live statistics header
- **Sleek dark theme** with gradient backgrounds and glowing effects
- **Card-based layout** similar to modern web applications
- **Smooth animations** and hover effects
- **Professional typography** and spacing
- **Responsive design** that adapts to window size

### 🔍 **Advanced Log Parsing**
- **56+ log formats supported** including Apache, SSH, firewall logs, and more
- **Dynamic parser** for unknown log formats with automatic field detection
- **Drag & drop interface** for easy file uploads
- **Real-time parsing** with animated progress tracking
- **Multi-file correlation** analysis

### 🤖 **ML-Powered Security Analysis**
- **Isolation Forest anomaly detection** algorithm
- **Attack chain correlation** across multiple log sources
- **Risk scoring dashboard** with visual indicators
- **MITRE ATT&CK framework** mapping and recommendations
- **False positive filtering** with confidence scores
- **Real-time threat assessment**

### 📊 **Interactive Visualizations & History**
- **Real-time statistics header** with live updates
- **Advanced filtering** with search and dropdown controls
- **Attack chain visualization** with detailed analysis
- **Timeline analysis** with anomaly highlighting
- **Comprehensive analytics** with charts and insights
- **Analysis history** with persistent storage
- **Export capabilities** (CSV/JSON)

### 🛡️ **Security Features**
- **Local processing only** - no data sent to external servers
- **No telemetry** - privacy-focused design
- **Open source** - fully auditable codebase

## 🚀 How to Run:

### **First Time Setup (Recommended)**
```bash
cd siem-gui

# Production setup with configuration and shortcuts
python setup_production.py

# This will:
# - Install dependencies automatically
# - Create desktop shortcuts
# - Set up configuration directory
# - Configure user preferences
```

### **Quick Start**
```bash
cd siem-gui

# If dependencies are already installed
python run.py

# Or direct run
python src/main.py
```

### **Manual Installation**
```bash
# Install dependencies
pip install PySide6 pandas numpy scikit-learn matplotlib seaborn

# Run the application
python run.py
```

## 🎨 Modern UI Highlights:

### **Header Dashboard**
- **Gradient background** with live statistics cards
- **Real-time updates** showing risk scores, attack chains, and log counts
- **Color-coded indicators** for different severity levels

### **Upload Interface**
- **Drag & drop zone** with animated hover effects
- **Modern card design** with glowing borders
- **File list** with icons and size indicators
- **Mode selection** with radio buttons for single/multi analysis

### **Logs Table**
- **Fixed width maintenance** (no more layout shifts!)
- **Color-coded severity badges** with icons
- **Advanced filtering** with search and dropdown controls
- **Responsive design** with proper column sizing

### **Dark Theme Features**
- **CSS Variables** for consistent theming
- **Gradient backgrounds** and subtle animations
- **Glowing effects** on interactive elements
- **Professional typography** and spacing
- **Smooth transitions** between states

## 📋 Supported Log Types

- **Web Servers**: Apache, Nginx, IIS, Django, Flask, Express
- **Authentication**: SSH, PAM, FTP, SMTP auth
- **Firewalls**: iptables, ufw, firewalld, Cisco ASA, Palo Alto
- **Databases**: MySQL, PostgreSQL, MongoDB, Oracle, MSSQL
- **System**: syslog, journald, audit logs
- **Network**: DHCP, DNS, proxy logs
- **Mail**: Postfix, Sendmail, Dovecot, Exchange
- **Cloud**: AWS VPC Flow, Azure NSG, GCP VPC

## 🏗️ Architecture

```
siem-gui/
├── src/
│   └── main.py              # Complete PySide6 GUI application
├── tests/
│   ├── test_core.py         # Core logic tests (PASSING ✓)
│   └── test_basic.py        # Full application tests
├── resources/
│   └── modern_styles.qss   # Modern dark theme CSS
├── requirements.txt         # All Python dependencies
├── setup.py                 # Installation and run script
├── run.py                   # Simple run script
├── README.md               # This file
├── sample-apache.log       # Test Apache logs
└── sample-ssh.log          # Test SSH logs
```

## 🛠️ Development & Distribution

### Running Tests
```bash
python tests/test_core.py    # Test core functionality
```

### Building for Distribution
```bash
# Install PyInstaller
pip install pyinstaller

# Create standalone executable
pyinstaller --onefile --windowed src/main.py --name "FreeKhana-SIEM"

# The executable will be in the 'dist' folder
```

### GitHub Release Setup
For GitHub releases, include:
- `setup_production.py` - Production installer
- `requirements.txt` - Dependencies
- Sample log files
- This README

Users can then run:
```bash
python setup_production.py  # Complete setup with shortcuts
```

## 📈 Performance

- **Multi-threaded analysis** - UI remains responsive during processing
- **Memory efficient** - Handles large log files without excessive memory usage
- **Scalable parsing** - Processes thousands of log entries efficiently
- **Fast filtering** - Real-time table updates with advanced search

## 🎯 Usage Example

### **Welcome Screen Flow**
1. **Launch**: `python setup_production.py` (first time) or `python run.py`
2. **Welcome Screen**: Clean interface with upload options
3. **Add Files**: Click "📂 Select Files" or drag & drop log files
4. **View Files**: Selected files appear in the list with sizes
5. **Analyze**: Click "⚡ Analyze File" or "🚀 Analyze X Files"

### **Analysis Dashboard**
6. **Switch to Analysis**: Automatic transition to full dashboard
7. **Explore Tabs**: Logs, Alerts, Attack Chains, Timeline, Analytics, History
8. **Interactive Filtering**: Search, severity filters, real-time updates
9. **Export Options**: CSV/JSON export with one click

### **Persistent History**
10. **Auto-Save**: All analyses saved automatically
11. **Quick Access**: Recent analyses available from welcome screen
12. **Load Previous**: Double-click history items to reload analyses
5. **Export**: Download results as CSV or JSON

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure modern UI standards are maintained
5. Submit a pull request

## 📄 License

This project is part of the FreeKhana SIEM suite and follows the same open-source licensing terms.

---

**Experience the future of log analysis with a modern, beautiful interface!** ✨