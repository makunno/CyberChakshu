# FreeKhana SIEM GUI Tool

A comprehensive Security Information and Event Management tool built with PySide6, featuring log parsing, correlation analysis, ML-based anomaly detection, and interactive visualizations.

## Features

### 🔍 **Log Parsing**
- **56+ log formats supported** including Apache, SSH, firewall logs, and more
- **Dynamic parser** for unknown log formats with automatic field detection
- **Real-time parsing** with progress tracking

### 🤖 **ML-Powered Analysis**
- **Anomaly detection** using Isolation Forest algorithm
- **Attack chain correlation** across multiple log sources
- **Risk scoring** and threat assessment
- **MITRE ATT&CK framework** mapping

### 📊 **Interactive Dashboard**
- **Tabbed interface** for different analysis views
- **Real-time filtering** by severity and search terms
- **Attack chain visualization** with confidence scores
- **Timeline analysis** with anomaly highlighting
- **Analytics charts** and statistics

### 🎯 **Supported Log Types**
- **Web Servers**: Apache, Nginx, IIS, Django, Flask, Express
- **Authentication**: SSH, PAM, FTP, SMTP auth
- **Firewalls**: iptables, ufw, firewalld, Cisco ASA, Palo Alto
- **Databases**: MySQL, PostgreSQL, MongoDB, Oracle, MSSQL
- **System**: syslog, journald, audit logs
- **Network**: DHCP, DNS, proxy logs
- **Mail**: Postfix, Sendmail, Dovecot, Exchange
- **Cloud**: AWS VPC Flow, Azure NSG, GCP VPC

## Installation

### Prerequisites
- Python 3.8+
- pip package manager

### Install Dependencies
```bash
cd siem-gui
pip install -r requirements.txt
```

### Run the Application
```bash
python src/main.py
```

## Usage

### 1. **File Upload**
- **Single Mode**: Upload one log file for analysis
- **Multi-Log Correlation**: Upload multiple log types for cross-correlation analysis

### 2. **Analysis Modes**
- **Single Log**: Parse and analyze individual log files
- **Correlation**: Analyze relationships between multiple log sources

### 3. **Navigation Tabs**
- **📁 Upload**: File selection and analysis configuration
- **📋 Logs**: Parsed log entries with filtering
- **🚨 Alerts**: Security alerts and high-severity events
- **🎯 Attack Chains**: Detected attack patterns
- **⏰ Timeline**: Event timeline with anomalies
- **📊 Analytics**: Charts and statistics

## Architecture

```
siem-gui/
├── src/
│   ├── main.py              # Main application with PySide6 GUI
│   ├── parsers/             # Log parsing modules
│   ├── ml/                  # ML analysis modules
│   └── utils/               # Utility functions
├── resources/               # Icons, styles, etc.
├── tests/                   # Unit tests
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Key Components

### **LogParserManager**
Manages all log parsers and coordinates parsing operations.

### **CorrelationAnalyzer**
Performs ML-based correlation analysis using:
- Isolation Forest for anomaly detection
- Time-window analysis for attack chains
- Pattern recognition for known attack types

### **MainWindow**
PySide6-based GUI with tabbed interface and interactive components.

## Dependencies

- **PySide6**: Qt6 Python bindings for GUI
- **pandas**: Data manipulation and analysis
- **scikit-learn**: Machine learning algorithms
- **matplotlib**: Plotting and visualization
- **numpy**: Numerical computing
- **requests**: HTTP client (for future API integration)

## Development

### Running Tests
```bash
python -m pytest tests/
```

### Building for Distribution
```bash
# Create executable with PyInstaller
pip install pyinstaller
pyinstaller --onefile --windowed src/main.py
```

## Security Features

- **Local Processing**: All analysis happens locally, no data sent to external servers
- **No Telemetry**: No data collection or tracking
- **Open Source**: Fully auditable codebase

## Performance

- **Multi-threaded**: Analysis runs in background threads
- **Memory Efficient**: Processes large log files without excessive memory usage
- **Scalable**: Handles thousands of log entries efficiently

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

This project is part of the FreeKhana SIEM suite and follows the same open-source licensing terms.