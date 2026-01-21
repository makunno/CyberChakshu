# FreeKhana SIEM Desktop - README

A modern desktop Security Information and Event Management tool built with PyWebView + Flask, featuring the same UI as the web version with advanced log parsing and ML-powered analysis.

## 🚀 Quick Start

### Automatic Setup (Recommended)
```bash
cd siem-gui
python setup.py
```

### Manual Setup
```bash
cd siem-gui
pip install -r requirements.txt
python run.py
```

## ✨ Features

### 🎨 **Modern UI Design**
- **Pixel-perfect match** with siem-tool web app
- **Dark theme** with gradient backgrounds
- **Responsive design** that adapts to window size
- **Professional animations** and hover effects

### 🔍 **Advanced Log Parsing**
- **56+ log formats supported** including Apache, SSH, firewall logs, and more
- **Dynamic parser** for unknown log formats with automatic field detection
- **Drag & drop interface** for easy file uploads
- **Real-time parsing** with animated progress tracking

### 🤖 **ML-Powered Security Analysis**
- **Isolation Forest anomaly detection** algorithm
- **Attack chain correlation** across multiple log sources
- **Risk scoring dashboard** with visual indicators
- **MITRE ATT&CK framework** mapping and recommendations
- **False positive filtering** with confidence scores

### 📊 **Interactive Visualizations**
- **Real-time statistics header** with live updates
- **Advanced filtering** with search and dropdown controls
- **Attack chain visualization** with detailed analysis
- **Timeline analysis** with anomaly highlighting
- **Comprehensive analytics** with charts and insights

## 🏗️ Architecture

```
siem-gui/
├── main.py              # PyWebView desktop application
├── api/
│   └── app.py          # Flask backend API
├── parsers/            # Log parsing engine (ported from siem-tool)
├── ml/                 # ML correlation engine
├── detectors/          # Security alert detection
├── static/             # React frontend assets
└── requirements.txt    # Python dependencies
```

## 📋 Supported Log Types

- **Web Servers**: Apache, Nginx, IIS, Django, Flask, Express
- **Authentication**: SSH, PAM, FTP, SMTP auth
- **Firewalls**: iptables, ufw, firewalld, Cisco ASA, Palo Alto
- **Databases**: MySQL, PostgreSQL, MongoDB, Oracle, MSSQL
- **System**: syslog, journald, audit logs
- **Network**: DHCP, DNS, proxy logs
- **Mail**: Postfix, Sendmail, Dovecot, Exchange

## 🔧 Development

### Running in Development Mode
```bash
# Terminal 1 - Start Flask API
cd siem-gui
python api/app.py

# Terminal 2 - Start PyWebView app
python run.py
```

### Testing the API
```bash
# Health check
curl http://localhost:5000/health

# Parse a log file
curl -X POST http://localhost:5000/parse -F "file=@sample.log"
```

## 📄 License

This project is part of the FreeKhana SIEM suite and follows the same open-source licensing terms.