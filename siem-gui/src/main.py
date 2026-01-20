#!/usr/bin/env python3
"""
FreeKhana SIEM GUI Tool
A comprehensive Security Information and Event Management tool built with PySide6.
Includes log parsing, correlation analysis, ML-based anomaly detection, and visualization.
"""

import sys
import os
import json
import re
import datetime
import uuid
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict, Counter
import warnings

# PySide6 imports
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QPushButton, QLabel, QTextEdit, QTableWidget,
    QTableWidgetItem, QFileDialog, QProgressBar, QMessageBox,
    QSplitter, QTreeWidget, QTreeWidgetItem, QComboBox, QLineEdit,
    QGroupBox, QScrollArea, QFrame, QStatusBar, QMenuBar, QMenu,
    QCheckBox, QSpinBox, QListWidget, QListWidgetItem, QTextBrowser,
    QDialog, QFormLayout, QDialogButtonBox, QDateTimeEdit, QPlainTextEdit,
    QRadioButton, QHeaderView
)
from PySide6.QtCore import (
    Qt, QThread, Signal, QTimer, QDateTime, QSize, QPointF, QRectF
)
from PySide6.QtGui import (
    QFont, QPalette, QColor, QIcon, QPixmap, QPainter, QBrush, QPen,
    QAction, QKeySequence
)
from PySide6.QtCore import (
    Qt, QThread, Signal, QTimer, QDateTime, QSize, QPointF, QRectF
)
from PySide6.QtGui import (
    QFont, QPalette, QColor, QIcon, QPixmap, QPainter, QBrush, QPen,
    QAction, QKeySequence
)
from PySide6.QtCharts import (
    QChart, QChartView, QLineSeries, QBarSeries, QBarSet, QPieSeries,
    QValueAxis, QBarCategoryAxis, QDateTimeAxis
)

# Suppress warnings
warnings.filterwarnings('ignore')
plt.style.use('default')

# Constants
SEVERITY_COLORS = {
    'debug': '#64748b',
    'info': '#3b82f6',
    'warning': '#eab308',
    'error': '#ef4444',
    'critical': '#a855f7',
    'unknown': '#94a3b8',
    'low': '#22c55e',
    'medium': '#f59e0b',
    'high': '#ef4444',
}

ATTACK_TYPE_ICONS = {
    'bruteforce': '🔓',
    'password_spray': '💨',
    'credential_stuffing': '🔑',
    'mfa_bypass': '🛡️',
    'mfa_fatigue': '😴',
    'session_hijacking': '🎭',
    'privilege_escalation': '⬆️',
    'lateral_movement': '↔️',
    'data_exfiltration': '📤',
    'sql_injection': '💉',
    'xss_attack': '🌐',
    'path_traversal': '📁',
    'command_injection': '⌨️',
    'port_scan': '🔍',
    'ddos': '🌊',
    'reconnaissance': '👁️',
    'malware_activity': '🦠',
    'c2_communication': '📡',
    'insider_threat': '👤',
    'account_takeover': '🔐',
    'anomaly': '📊',
    'unknown': '❓',
}

STAGE_COLORS = {
    'reconnaissance': '#64748b',
    'initial_access': '#3b82f6',
    'execution': '#8b5cf6',
    'persistence': '#f59e0b',
    'privilege_escalation': '#ef4444',
    'lateral_movement': '#ec4899',
    'exfiltration': '#dc2626',
    'complete': '#7c3aed',
}

class LogEntry:
    """Represents a parsed log entry"""
    def __init__(self, raw_line: str = "", **kwargs):
        self.id = str(uuid.uuid4())
        self.timestamp = kwargs.get('timestamp')
        self.log_type = kwargs.get('log_type', 'unknown')
        self.severity = kwargs.get('severity', 'unknown')
        self.source = kwargs.get('source', {})
        self.user = kwargs.get('user')
        self.action = kwargs.get('action')
        self.outcome = kwargs.get('outcome')
        self.message = kwargs.get('message', raw_line)
        self.raw_line = raw_line
        self.fields = kwargs.get('fields', {})
        self.tags = kwargs.get('tags', [])

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'log_type': self.log_type,
            'severity': self.severity,
            'source': self.source,
            'user': self.user,
            'action': self.action,
            'outcome': self.outcome,
            'message': self.message,
            'raw_line': self.raw_line,
            'fields': self.fields,
            'tags': self.tags
        }

class AttackChain:
    """Represents an attack chain"""
    def __init__(self, attack_type: str, events: List[LogEntry], **kwargs):
        self.id = str(uuid.uuid4())
        self.attack_type = attack_type
        self.stage = kwargs.get('stage', 'unknown')
        self.events = events
        self.source_ips = list(set([e.source.get('ip') for e in events if e.source.get('ip')]))
        self.target_users = list(set([e.user.get('name') for e in events if e.user and e.user.get('name')]))
        self.start_time = min([e.timestamp for e in events if e.timestamp] + [datetime.datetime.now()])
        self.end_time = max([e.timestamp for e in events if e.timestamp] + [datetime.datetime.now()])
        self.prediction = kwargs.get('prediction', {'confidence': 0.0, 'explanation': []})
        self.mitre_tactics = kwargs.get('mitre_tactics', [])
        self.mitre_techniques = kwargs.get('mitre_techniques', [])
        self.recommendation = kwargs.get('recommendation', '')

class LogParser:
    """Base class for log parsers"""
    def __init__(self, name: str, log_type: str):
        self.name = name
        self.log_type = log_type

    def detect(self, line: str) -> bool:
        return False

    def parse(self, line: str) -> Optional[LogEntry]:
        return None

class ApacheAccessParser(LogParser):
    """Parser for Apache access logs"""
    def __init__(self):
        super().__init__("Apache Access", "apache_access")
        self.pattern = re.compile(
            r'(\d+\.\d+\.\d+\.\d+) - ([^ ]+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+|-) "([^"]*)" "([^"]*)"'
        )

    def detect(self, line: str) -> bool:
        return bool(self.pattern.match(line))

    def parse(self, line: str) -> Optional[LogEntry]:
        match = self.pattern.match(line)
        if not match:
            return None

        ip, user, timestamp_str, request, status, size, referer, user_agent = match.groups()

        # Parse timestamp
        try:
            # Convert Apache timestamp format
            timestamp = datetime.datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        except:
            timestamp = None

        # Parse request
        request_parts = request.split()
        method = request_parts[0] if len(request_parts) > 0 else ""
        path = request_parts[1] if len(request_parts) > 1 else ""

        severity = 'info'
        if status.startswith('4'):
            severity = 'warning'
        elif status.startswith('5'):
            severity = 'error'

        return LogEntry(
            line,
            timestamp=timestamp,
            log_type=self.log_type,
            severity=severity,
            source={'ip': ip, 'service': 'apache'},
            user={'name': user} if user != '-' else None,
            action=method,
            outcome=status,
            message=f"{method} {path} {status}",
            fields={
                'method': method,
                'path': path,
                'status': int(status),
                'size': int(size) if size != '-' else 0,
                'referer': referer,
                'user_agent': user_agent
            }
        )

class SSHAuthParser(LogParser):
    """Parser for SSH authentication logs"""
    def __init__(self):
        super().__init__("SSH Authentication", "ssh_auth")
        self.patterns = [
            re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[(\d+)\]:\s+(.+)'),
            re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd:\s+(.+)'),
        ]

    def detect(self, line: str) -> bool:
        return any(pattern.search(line) for pattern in self.patterns) and 'sshd' in line

    def parse(self, line: str) -> Optional[LogEntry]:
        for pattern in self.patterns:
            match = pattern.search(line)
            if match:
                timestamp_str, hostname, pid, message = match.groups()

                # Parse timestamp
                try:
                    timestamp = datetime.datetime.strptime(f"{datetime.datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S")
                except:
                    timestamp = None

                severity = 'info'
                user = None
                ip = None
                action = None

                if 'Failed password' in message:
                    severity = 'warning'
                    user_match = re.search(r'for (\w+)', message)
                    ip_match = re.search(r'from ([^\s:]+)', message)
                    if user_match:
                        user = {'name': user_match.group(1)}
                    if ip_match:
                        ip = ip_match.group(1)
                    action = 'login'
                elif 'Accepted password' in message:
                    severity = 'info'
                    user_match = re.search(r'for (\w+)', message)
                    ip_match = re.search(r'from ([^\s:]+)', message)
                    if user_match:
                        user = {'name': user_match.group(1)}
                    if ip_match:
                        ip = ip_match.group(1)
                    action = 'login'

                return LogEntry(
                    line,
                    timestamp=timestamp,
                    log_type=self.log_type,
                    severity=severity,
                    source={'hostname': hostname, 'service': 'sshd', 'pid': int(pid) if pid.isdigit() else None},
                    user=user,
                    action=action,
                    message=message,
                    fields={'original_message': message}
                )
        return None

class DynamicParser(LogParser):
    """Dynamic parser for unknown log formats"""
    def __init__(self):
        super().__init__("Dynamic Parser", "unknown")
        self.field_patterns = {
            'timestamp': [
                r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}',
                r'\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}',
                r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
            ],
            'ip': [
                r'src[_-]ip[=:]\s*"?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                r'dst[_-]ip[=:]\s*"?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
            ],
            'port': [
                r'src[_-]port[=:]\s*"?(\d{1,5})',
                r'dst[_-]port[=:]\s*"?(\d{1,5})',
                r'port[=:]\s*(\d{1,5})\b',
            ],
            'user': [
                r'user[=:]\s*"?(\w[^"]*)"',
                r'username[=:]\s*"?(\w[^"]*)"',
            ],
            'severity': [
                r'\b(debug|info|notice|warn|warning|error|err|fail|fatal|critical|alert)\b',
            ]
        }

    def detect(self, line: str) -> bool:
        return True  # Fallback parser

    def parse(self, line: str) -> Optional[LogEntry]:
        fields = {}
        message = line

        # Extract fields using patterns
        for field_type, patterns in self.field_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    value = match.group(1) if match.groups() else match.group(0)
                    fields[field_type] = value
                    break

        # Determine severity
        severity = fields.get('severity', 'unknown').lower()
        if severity not in SEVERITY_COLORS:
            severity = 'unknown'

        # Determine timestamp
        timestamp = None
        if 'timestamp' in fields:
            try:
                timestamp = datetime.datetime.fromisoformat(fields['timestamp'].replace(' ', 'T'))
            except:
                pass

        return LogEntry(
            line,
            timestamp=timestamp,
            log_type='unknown',
            severity=severity,
            source={'ip': fields.get('ip')},
            user={'name': fields.get('user')} if fields.get('user') else None,
            fields=fields,
            message=message
        )

class LogParserManager:
    """Manages all log parsers"""
    def __init__(self):
        self.parsers = [
            ApacheAccessParser(),
            SSHAuthParser(),
            DynamicParser()  # Always last as fallback
        ]

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line"""
        for parser in self.parsers:
            if parser.detect(line):
                entry = parser.parse(line)
                if entry:
                    return entry
        return None

    def parse_file(self, file_path: str) -> Tuple[List[LogEntry], Dict[str, Any]]:
        """Parse an entire log file"""
        entries = []
        stats = {
            'total_lines': 0,
            'parsed_lines': 0,
            'by_type': defaultdict(int),
            'by_severity': defaultdict(int),
            'errors': []
        }

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    stats['total_lines'] += 1

                    if not line:
                        continue

                    entry = self.parse_line(line)
                    if entry:
                        entries.append(entry)
                        stats['parsed_lines'] += 1
                        stats['by_type'][entry.log_type] += 1
                        stats['by_severity'][entry.severity] += 1
                    else:
                        stats['errors'].append(f"Line {line_num}: Could not parse")

        except Exception as e:
            stats['errors'].append(f"File read error: {str(e)}")

        return entries, dict(stats)

class CorrelationAnalyzer:
    """Analyzes correlations between log entries"""
    def __init__(self):
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)

    def analyze_correlations(self, entries: List[LogEntry]) -> Dict[str, Any]:
        """Perform correlation analysis on log entries"""
        if len(entries) < 2:
            return {'attack_chains': [], 'summary': {'risk_score': 0, 'critical_alerts': 0, 'false_positives_filtered': 0}}

        # Group entries by time windows
        time_windows = self._group_by_time_windows(entries)

        # Detect anomalies
        anomalies = self._detect_anomalies(entries)

        # Find attack patterns
        attack_chains = self._find_attack_patterns(entries, time_windows, anomalies)

        # Generate summary
        summary = self._generate_summary(entries, attack_chains)

        return {
            'attack_chains': attack_chains,
            'summary': summary,
            'timeline': self._generate_timeline(entries, anomalies),
            'recommendations': self._generate_recommendations(attack_chains)
        }

    def _group_by_time_windows(self, entries: List[LogEntry], window_minutes: int = 5) -> List[List[LogEntry]]:
        """Group entries by time windows"""
        if not entries:
            return []

        # Sort by timestamp
        sorted_entries = sorted([e for e in entries if e.timestamp], key=lambda x: x.timestamp or datetime.datetime.min)
        if not sorted_entries:
            return [entries]

        windows = []
        current_window = [sorted_entries[0]]
        window_start = sorted_entries[0].timestamp

        for entry in sorted_entries[1:]:
            if entry.timestamp and (entry.timestamp - window_start).total_seconds() / 60 <= window_minutes:
                current_window.append(entry)
            else:
                if current_window:
                    windows.append(current_window)
                current_window = [entry]
                window_start = entry.timestamp

        if current_window:
            windows.append(current_window)

        return windows

    def _detect_anomalies(self, entries: List[LogEntry]) -> List[LogEntry]:
        """Detect anomalous log entries using ML"""
        if len(entries) < 10:
            return []

        # Create features
        features = []
        for entry in entries:
            feature_vector = [
                hash(entry.source.get('ip', '')) % 1000 / 1000.0,
                hash(entry.user.get('name', '') if entry.user else '') % 1000 / 1000.0,
                len(entry.message) / 1000.0,
                {'debug': 0, 'info': 1, 'warning': 2, 'error': 3, 'critical': 4}.get(entry.severity, 1),
                len(entry.fields)
            ]
            features.append(feature_vector)

        try:
            features_scaled = self.scaler.fit_transform(features)
            anomaly_scores = self.isolation_forest.fit_predict(features_scaled)

            anomalies = []
            for i, entry in enumerate(entries):
                if anomaly_scores[i] == -1:  # Anomaly
                    entry_copy = LogEntry(**entry.to_dict())
                    entry_copy.fields['anomaly_score'] = float(self.isolation_forest.score_samples([features_scaled[i]])[0])
                    anomalies.append(entry_copy)

            return anomalies
        except:
            return []

    def _find_attack_patterns(self, entries: List[LogEntry], time_windows: List[List[LogEntry]], anomalies: List[LogEntry]) -> List[AttackChain]:
        """Find potential attack patterns"""
        attack_chains = []

        # Simple pattern detection
        for window in time_windows:
            if len(window) < 2:
                continue

            # Look for authentication failures followed by successes
            failed_auths = [e for e in window if 'Failed' in e.message and e.severity in ['warning', 'error']]
            successful_auths = [e for e in window if 'Accepted' in e.message and e.severity == 'info']

            if failed_auths and successful_auths:
                # Potential brute force attack
                chain = AttackChain(
                    'bruteforce',
                    failed_auths + successful_auths,
                    stage='initial_access',
                    prediction={'confidence': 0.7, 'explanation': [
                        f'Detected {len(failed_auths)} failed authentication attempts',
                        f'Followed by {len(successful_auths)} successful authentications',
                        'Pattern suggests potential brute force attack'
                    ]},
                    mitre_tactics=['TA0006'],
                    mitre_techniques=['T1110'],
                    recommendation='Implement account lockout policies and monitor for suspicious login patterns'
                )
                attack_chains.append(chain)

        return attack_chains

    def _generate_summary(self, entries: List[LogEntry], attack_chains: List[AttackChain]) -> Dict[str, Any]:
        """Generate analysis summary"""
        risk_score = min(100, len(attack_chains) * 20 + len([e for e in entries if e.severity in ['error', 'critical']]))
        critical_alerts = len([e for e in entries if e.severity == 'critical'])

        return {
            'risk_score': risk_score,
            'critical_alerts': critical_alerts,
            'false_positives_filtered': 0,  # Placeholder
            'attack_types_detected': list(set(chain.attack_type for chain in attack_chains)),
            'most_active_source_ips': [],  # Would need more analysis
            'most_targeted_users': []  # Would need more analysis
        }

    def _generate_timeline(self, entries: List[LogEntry], anomalies: List[LogEntry]) -> List[Dict[str, Any]]:
        """Generate timeline data"""
        timeline = []
        for entry in entries:
            if entry.timestamp:
                timeline.append({
                    'timestamp': entry.timestamp.isoformat(),
                    'count': 1,
                    'is_anomaly': entry in anomalies,
                    'severity': entry.severity
                })
        return timeline

    def _generate_recommendations(self, attack_chains: List[AttackChain]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        if any(chain.attack_type == 'bruteforce' for chain in attack_chains):
            recommendations.extend([
                'Implement multi-factor authentication (MFA) for all user accounts',
                'Configure account lockout policies after failed login attempts',
                'Monitor and alert on suspicious login patterns',
                'Consider implementing rate limiting on authentication endpoints'
            ])

        if not recommendations:
            recommendations.append('Continue monitoring log files for security events')

        return recommendations

class SIEMWorker(QThread):
    """Worker thread for log processing"""
    progress = Signal(int)
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, file_paths: List[str], correlation: bool = False):
        super().__init__()
        self.file_paths = file_paths
        self.correlation = correlation
        self.parser_manager = LogParserManager()
        self.correlation_analyzer = CorrelationAnalyzer()

    def run(self):
        try:
            all_entries = []
            all_stats = {'total_lines': 0, 'parsed_lines': 0, 'by_type': defaultdict(int), 'by_severity': defaultdict(int), 'errors': []}

            for i, file_path in enumerate(self.file_paths):
                self.progress.emit(int((i / len(self.file_paths)) * 50))

                entries, stats = self.parser_manager.parse_file(file_path)
                all_entries.extend(entries)

                # Merge stats
                all_stats['total_lines'] += stats['total_lines']
                all_stats['parsed_lines'] += stats['parsed_lines']
                for k, v in stats['by_type'].items():
                    all_stats['by_type'][k] += v
                for k, v in stats['by_severity'].items():
                    all_stats['by_severity'][k] += v
                all_stats['errors'].extend(stats['errors'])

            self.progress.emit(50)

            if self.correlation and len(self.file_paths) > 1:
                correlation_result = self.correlation_analyzer.analyze_correlations(all_entries)
                self.progress.emit(100)

                result = {
                    'entries': all_entries,
                    'stats': all_stats,
                    'correlation': correlation_result
                }
            else:
                result = {
                    'entries': all_entries,
                    'stats': all_stats
                }

            self.finished.emit(result)

        except Exception as e:
            self.error.emit(str(e))

class MainWindow(QMainWindow):
    """Main application window"""
    def __init__(self):
        super().__init__()
        self.entries = []
        self.correlation_data = None
        self.current_files = []

        self.init_ui()
        self.setup_connections()

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("FreeKhana SIEM Tool")
        self.setGeometry(100, 100, 1400, 900)

        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        layout = QVBoxLayout(central_widget)

        # Create tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        # Upload tab
        self.create_upload_tab()

        # Logs tab
        self.create_logs_tab()

        # Alerts tab
        self.create_alerts_tab()

        # Attack Chains tab
        self.create_attack_chains_tab()

        # Timeline tab
        self.create_timeline_tab()

        # Analytics tab
        self.create_analytics_tab()

        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")

        # Progress bar (hidden initially)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

    def create_upload_tab(self):
        """Create the file upload tab"""
        upload_widget = QWidget()
        layout = QVBoxLayout(upload_widget)

        # Mode selection
        mode_group = QGroupBox("Analysis Mode")
        mode_layout = QHBoxLayout(mode_group)

        self.single_mode = QRadioButton("Single Log Analysis")
        self.multi_mode = QRadioButton("Multi-Log Correlation")
        self.single_mode.setChecked(True)

        mode_layout.addWidget(self.single_mode)
        mode_layout.addWidget(self.multi_mode)
        mode_layout.addStretch()

        layout.addWidget(mode_group)

        # Upload area
        upload_group = QGroupBox("File Upload")
        upload_layout = QVBoxLayout(upload_group)

        self.upload_text = QTextEdit()
        self.upload_text.setPlaceholderText("Drag and drop log files here, or click 'Select Files' below")
        self.upload_text.setAcceptDrops(True)
        self.upload_text.setMaximumHeight(200)

        upload_layout.addWidget(self.upload_text)

        # File buttons
        button_layout = QHBoxLayout()
        self.select_files_btn = QPushButton("Select Files")
        self.clear_files_btn = QPushButton("Clear")
        self.analyze_btn = QPushButton("Analyze Logs")
        self.analyze_btn.setStyleSheet("QPushButton { background-color: #3b82f6; color: white; padding: 10px; }")

        button_layout.addWidget(self.select_files_btn)
        button_layout.addWidget(self.clear_files_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.analyze_btn)

        upload_layout.addLayout(button_layout)

        # File list
        self.file_list = QListWidget()
        upload_layout.addWidget(self.file_list)

        layout.addWidget(upload_group)
        layout.addStretch()

        self.tab_widget.addTab(upload_widget, "📁 Upload")

    def create_logs_tab(self):
        """Create the logs display tab"""
        logs_widget = QWidget()
        layout = QVBoxLayout(logs_widget)

        # Filters
        filter_group = QGroupBox("Filters")
        filter_layout = QHBoxLayout(filter_group)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search logs...")
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["All Severities", "Critical", "Error", "Warning", "Info", "Debug"])

        filter_layout.addWidget(QLabel("Search:"))
        filter_layout.addWidget(self.search_input)
        filter_layout.addWidget(QLabel("Severity:"))
        filter_layout.addWidget(self.severity_combo)

        layout.addWidget(filter_group)

        # Logs table
        self.logs_table = QTableWidget()
        self.logs_table.setColumnCount(6)
        self.logs_table.setHorizontalHeaderLabels(["Timestamp", "Severity", "Source", "User", "Action", "Message"])
        self.logs_table.horizontalHeader().setStretchLastSection(True)

        # Set minimum width for table
        self.logs_table.setMinimumWidth(800)
        for i in range(6):
            self.logs_table.horizontalHeader().setSectionResizeMode(i, QHeaderView.Stretch)

        layout.addWidget(self.logs_table)

        # Stats label
        self.logs_stats_label = QLabel("No logs loaded")
        layout.addWidget(self.logs_stats_label)

        self.tab_widget.addTab(logs_widget, "📋 Logs")

    def create_alerts_tab(self):
        """Create the alerts display tab"""
        alerts_widget = QWidget()
        layout = QVBoxLayout(alerts_widget)

        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(4)
        self.alerts_table.setHorizontalHeaderLabels(["Severity", "Title", "Description", "Confidence"])
        self.alerts_table.horizontalHeader().setStretchLastSection(True)

        layout.addWidget(self.alerts_table)

        self.alerts_stats_label = QLabel("No alerts detected")
        layout.addWidget(self.alerts_stats_label)

        self.tab_widget.addTab(alerts_widget, "🚨 Alerts")

    def create_attack_chains_tab(self):
        """Create the attack chains tab"""
        chains_widget = QWidget()
        layout = QVBoxLayout(chains_widget)

        self.chains_list = QListWidget()
        layout.addWidget(self.chains_list)

        self.chains_details = QTextBrowser()
        layout.addWidget(self.chains_details)

        self.tab_widget.addTab(chains_widget, "🎯 Attack Chains")

    def create_timeline_tab(self):
        """Create the timeline visualization tab"""
        timeline_widget = QWidget()
        layout = QVBoxLayout(timeline_widget)

        # Placeholder for timeline chart
        self.timeline_view = QLabel("Timeline visualization will be implemented here")
        self.timeline_view.setAlignment(Qt.AlignCenter)
        self.timeline_view.setStyleSheet("QLabel { background-color: #f3f4f6; border: 2px dashed #d1d5db; padding: 40px; }")

        layout.addWidget(self.timeline_view)

        self.tab_widget.addTab(timeline_widget, "⏰ Timeline")

    def create_analytics_tab(self):
        """Create the analytics tab"""
        analytics_widget = QWidget()
        layout = QVBoxLayout(analytics_widget)

        # Placeholder for analytics charts
        self.analytics_view = QLabel("Analytics and charts will be implemented here")
        self.analytics_view.setAlignment(Qt.AlignCenter)
        self.analytics_view.setStyleSheet("QLabel { background-color: #f3f4f6; border: 2px dashed #d1d5db; padding: 40px; }")

        layout.addWidget(self.analytics_view)

        self.tab_widget.addTab(analytics_widget, "📊 Analytics")

    def setup_connections(self):
        """Setup signal connections"""
        self.select_files_btn.clicked.connect(self.select_files)
        self.clear_files_btn.clicked.connect(self.clear_files)
        self.analyze_btn.clicked.connect(self.analyze_logs)
        self.search_input.textChanged.connect(self.filter_logs)
        self.severity_combo.currentTextChanged.connect(self.filter_logs)

    def select_files(self):
        """Select log files"""
        files, _ = QFileDialog.getOpenFileNames(
            self, "Select Log Files", "", "Log files (*.log *.txt);;All files (*)"
        )

        if files:
            self.current_files.extend(files)
            self.update_file_list()

    def clear_files(self):
        """Clear selected files"""
        self.current_files.clear()
        self.update_file_list()

    def update_file_list(self):
        """Update the file list display"""
        self.file_list.clear()
        for file_path in self.current_files:
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            item_text = f"{file_name} ({file_size} bytes)"
            self.file_list.addItem(item_text)

    def analyze_logs(self):
        """Start log analysis"""
        if not self.current_files:
            QMessageBox.warning(self, "No Files", "Please select log files first.")
            return

        correlation = self.multi_mode.isChecked()
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.analyze_btn.setEnabled(False)

        # Start worker thread
        self.worker = SIEMWorker(self.current_files, correlation)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.on_analysis_finished)
        self.worker.error.connect(self.on_analysis_error)
        self.worker.start()

    def on_analysis_finished(self, result):
        """Handle analysis completion"""
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)

        self.entries = result['entries']
        self.correlation_data = result.get('correlation')

        # Update UI
        self.update_logs_table()
        self.update_alerts_table()
        self.update_attack_chains()
        self.update_timeline()
        self.update_analytics()

        # Switch to logs tab
        self.tab_widget.setCurrentIndex(1)

        QMessageBox.information(self, "Analysis Complete",
                              f"Successfully parsed {len(self.entries)} log entries.")

    def on_analysis_error(self, error_msg):
        """Handle analysis error"""
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)
        QMessageBox.critical(self, "Analysis Error", f"Error during analysis: {error_msg}")

    def update_logs_table(self):
        """Update the logs table with parsed entries"""
        self.logs_table.setRowCount(len(self.entries))

        for row, entry in enumerate(self.entries):
            # Timestamp
            timestamp = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if entry.timestamp else "-"
            self.logs_table.setItem(row, 0, QTableWidgetItem(timestamp))

            # Severity
            severity_item = QTableWidgetItem(entry.severity.upper())
            severity_item.setBackground(QColor(SEVERITY_COLORS.get(entry.severity, '#94a3b8')))
            self.logs_table.setItem(row, 1, severity_item)

            # Source
            source = entry.source.get('ip') or entry.source.get('hostname') or entry.source.get('service') or "-"
            self.logs_table.setItem(row, 2, QTableWidgetItem(source))

            # User
            user = entry.user.get('name') if entry.user else "-"
            self.logs_table.setItem(row, 3, QTableWidgetItem(user))

            # Action
            action = entry.action or "-"
            self.logs_table.setItem(row, 4, QTableWidgetItem(action))

            # Message
            message = entry.message[:100] + "..." if len(entry.message) > 100 else entry.message
            self.logs_table.setItem(row, 5, QTableWidgetItem(message))

        # Update stats
        total = len(self.entries)
        by_severity = {}
        for entry in self.entries:
            by_severity[entry.severity] = by_severity.get(entry.severity, 0) + 1

        stats_text = f"Total: {total} entries"
        if by_severity:
            severity_stats = ", ".join([f"{sev}: {count}" for sev, count in by_severity.items()])
            stats_text += f" | {severity_stats}"

        self.logs_stats_label.setText(stats_text)

    def update_alerts_table(self):
        """Update the alerts table"""
        # For now, show high-severity entries as alerts
        alerts = [entry for entry in self.entries if entry.severity in ['error', 'critical', 'warning']]

        self.alerts_table.setRowCount(len(alerts))

        for row, entry in enumerate(alerts):
            # Severity
            severity_item = QTableWidgetItem(entry.severity.upper())
            severity_item.setBackground(QColor(SEVERITY_COLORS.get(entry.severity, '#94a3b8')))
            self.alerts_table.setItem(row, 0, severity_item)

            # Title
            title = f"{entry.action or 'Unknown'} {entry.severity.upper()}"
            self.alerts_table.setItem(row, 1, QTableWidgetItem(title))

            # Description
            self.alerts_table.setItem(row, 2, QTableWidgetItem(entry.message))

            # Confidence (placeholder)
            confidence = "80%" if entry.severity == 'critical' else "60%"
            self.alerts_table.setItem(row, 3, QTableWidgetItem(confidence))

        self.alerts_stats_label.setText(f"Total: {len(alerts)} alerts")

    def update_attack_chains(self):
        """Update the attack chains display"""
        if not self.correlation_data or not self.correlation_data.get('attack_chains'):
            self.chains_list.clear()
            self.chains_details.clear()
            return

        self.chains_list.clear()
        for chain in self.correlation_data['attack_chains']:
            item_text = f"{ATTACK_TYPE_ICONS.get(chain.attack_type, '❓')} {chain.attack_type.replace('_', ' ').upper()}"
            item_text += f" ({len(chain.events)} events, {chain.prediction['confidence']:.1%} confidence)"
            self.chains_list.addItem(item_text)

    def update_timeline(self):
        """Update the timeline visualization"""
        if self.correlation_data and self.correlation_data.get('timeline'):
            self.timeline_view.setText(f"Timeline with {len(self.correlation_data['timeline'])} events")
        else:
            self.timeline_view.setText("No timeline data available")

    def update_analytics(self):
        """Update the analytics display"""
        if not self.entries:
            self.analytics_view.setText("No data for analytics")
            return

        # Simple analytics
        by_type = {}
        by_severity = {}
        for entry in self.entries:
            by_type[entry.log_type] = by_type.get(entry.log_type, 0) + 1
            by_severity[entry.severity] = by_severity.get(entry.severity, 0) + 1

        analytics_text = "Log Analysis Summary:\n\n"
        analytics_text += f"Total Entries: {len(self.entries)}\n\n"
        analytics_text += "By Log Type:\n"
        for log_type, count in by_type.items():
            analytics_text += f"  {log_type}: {count}\n"
        analytics_text += "\nBy Severity:\n"
        for severity, count in by_severity.items():
            analytics_text += f"  {severity}: {count}\n"

        self.analytics_view.setText(analytics_text)

    def filter_logs(self):
        """Filter the logs table based on search and severity"""
        search_text = self.search_input.text().lower()
        severity_filter = self.severity_combo.currentText().lower()

        for row in range(self.logs_table.rowCount()):
            show_row = True

            # Check severity filter
            if severity_filter != "all severities":
                severity_item = self.logs_table.item(row, 1)
                if severity_item and severity_item.text().lower() != severity_filter:
                    show_row = False

            # Check search filter
            if search_text:
                found = False
                for col in range(self.logs_table.columnCount()):
                    item = self.logs_table.item(row, col)
                    if item and search_text in item.text().lower():
                        found = True
                        break
                if not found:
                    show_row = False

            self.logs_table.setRowHidden(row, not show_row)

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)

    # Set application properties
    app.setApplicationName("FreeKhana SIEM Tool")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("FreeKhana")

    # Create and show main window
    window = MainWindow()
    window.show()

    # Start event loop
    sys.exit(app.exec())

if __name__ == "__main__":
    main()