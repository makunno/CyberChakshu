#!/usr/bin/env python3
"""
FreeKhana SIEM GUI Tool
A comprehensive Security Information and Event Management tool built with PySide6.
Includes log parsing, correlation analysis, ML-based anomaly detection, and visualization.
"""

import sys
import os
import re
import json
from pathlib import Path
import datetime
import uuid
from typing import List, Dict, Any, Optional, Tuple

# Optional imports with fallbacks
try:
    import pandas as pd
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import matplotlib.pyplot as plt
    import seaborn as sns
    from collections import defaultdict, Counter
    import warnings
    warnings.filterwarnings('ignore')
    plt.style.use('default')
    ML_AVAILABLE = True
except ImportError:
    # Fallback when ML libraries not available
    pd = None
    np = None
    IsolationForest = None
    StandardScaler = None
    plt = None
    sns = None
    defaultdict = dict
    Counter = dict
    ML_AVAILABLE = False

# PySide6 imports
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QPushButton, QLabel, QTextEdit, QTableWidget,
    QTableWidgetItem, QFileDialog, QProgressBar, QMessageBox,
    QSplitter, QTreeWidget, QTreeWidgetItem, QComboBox, QLineEdit,
    QGroupBox, QScrollArea, QFrame, QStatusBar, QMenuBar, QMenu,
    QCheckBox, QSpinBox, QListWidget, QListWidgetItem, QTextBrowser,
    QDialog, QFormLayout, QDialogButtonBox, QDateTimeEdit, QPlainTextEdit,
    QRadioButton, QHeaderView, QStackedWidget
)
from PySide6.QtCore import (
    Qt, QThread, Signal, QTimer, QDateTime, QSize, QPointF, QRectF
)
from PySide6.QtGui import (
    QFont, QPalette, QColor, QIcon, QPixmap, QPainter, QBrush, QPen,
    QAction, QKeySequence
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
        if ML_AVAILABLE:
            self.scaler = StandardScaler()
            self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        else:
            self.scaler = None
            self.isolation_forest = None

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
        if len(entries) < 10 or not ML_AVAILABLE:
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
            if self.scaler and self.isolation_forest:
                features_scaled = self.scaler.fit_transform(features)
                anomaly_scores = self.isolation_forest.fit_predict(features_scaled)

                anomalies = []
                for i, entry in enumerate(entries):
                    if anomaly_scores[i] == -1:  # Anomaly
                        entry_copy = LogEntry(**entry.to_dict())
                        entry_copy.fields['anomaly_score'] = float(self.isolation_forest.score_samples([features_scaled[i]])[0])
                        anomalies.append(entry_copy)

                return anomalies
            return []
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
        self.analysis_history = []
        self.current_view = "welcome"  # welcome or analysis

        self.init_ui()
        self.apply_modern_styling()
        self.setup_connections()
        self.load_history()

    def apply_modern_styling(self):
        """Apply modern dark theme styling"""
        # Load the modern stylesheet
        style_path = Path(__file__).parent.parent / "resources" / "modern_styles.qss"
        if style_path.exists():
            with open(style_path, 'r') as f:
                self.setStyleSheet(f.read())
        else:
            # Fallback modern styling
            self.setStyleSheet("""
                QMainWindow { background: #0f0f23; }
                QTabWidget { background: #1a1a2e; border-radius: 12px; }
                QPushButton { background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #667eea, stop:1 #764ba2);
                    color: white; border: none; border-radius: 8px;
                    padding: 12px 24px; font-weight: 600; }
                QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #f093fb, stop:1 #f5576c); }
            """)

    def create_modern_header(self, parent_layout):
        """Create a modern gradient header"""
        header_frame = QFrame()
        header_frame.setObjectName("header")
        header_frame.setFixedHeight(100)  # Increased height

        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(24, 16, 24, 16)

        # Logo section
        logo_widget = QWidget()
        logo_layout = QHBoxLayout(logo_widget)
        logo_layout.setContentsMargins(0, 0, 0, 0)

        logo_label = QLabel("🛡️ FreeKhana SIEM")
        logo_label.setObjectName("logo")
        logo_layout.addWidget(logo_label)

        header_layout.addWidget(logo_widget)

        # Stats section - only show if we have data
        self.stats_widget = QWidget()
        self.stats_widget.setVisible(False)  # Hidden initially
        stats_layout = QHBoxLayout(self.stats_widget)
        stats_layout.setContentsMargins(0, 0, 0, 0)
        stats_layout.setSpacing(16)  # Reduced spacing

        # Risk score card
        self.risk_card = self.create_stats_card("Risk Score", "0/100", "#ef4444")
        stats_layout.addWidget(self.risk_card)

        # Attack chains card
        self.chains_card = self.create_stats_card("Attack Chains", "0", "#f59e0b")
        stats_layout.addWidget(self.chains_card)

        # Total logs card
        self.logs_card = self.create_stats_card("Total Logs", "0", "#3b82f6")
        stats_layout.addWidget(self.logs_card)

        # Parsed logs card
        self.parsed_card = self.create_stats_card("Parsed", "0", "#22c55e")
        stats_layout.addWidget(self.parsed_card)

        header_layout.addStretch()
        header_layout.addWidget(self.stats_widget)

        parent_layout.addWidget(header_frame)

    def create_stats_card(self, label, value, color):
        """Create a modern stats card"""
        card = QFrame()
        card.setObjectName("stats-card")
        card.setFixedSize(140, 70)  # Fixed size for consistency

        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)

        value_label = QLabel(value)
        value_label.setObjectName("value")
        value_label.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: bold; text-align: center;")
        value_label.setAlignment(Qt.AlignCenter)

        label_widget = QLabel(label)
        label_widget.setObjectName("label")
        label_widget.setStyleSheet("color: rgba(255, 255, 255, 0.8); font-size: 10px; text-transform: uppercase; text-align: center;")
        label_widget.setAlignment(Qt.AlignCenter)

        layout.addWidget(value_label)
        layout.addWidget(label_widget)

        return card

    def create_welcome_view(self):
        """Create the welcome screen"""
        welcome_widget = QWidget()
        layout = QVBoxLayout(welcome_widget)
        layout.setContentsMargins(48, 48, 48, 48)
        layout.setSpacing(24)

        # Welcome header
        welcome_header = QVBoxLayout()
        title_label = QLabel("🚀 Welcome to FreeKhana SIEM")
        title_label.setStyleSheet("font-size: 32px; font-weight: bold; color: #00d4ff; margin-bottom: 8px;")
        title_label.setAlignment(Qt.AlignCenter)

        subtitle_label = QLabel("Advanced Security Information and Event Management")
        subtitle_label.setStyleSheet("font-size: 16px; color: #b8c5d6; text-align: center;")
        subtitle_label.setAlignment(Qt.AlignCenter)

        welcome_header.addWidget(title_label)
        welcome_header.addWidget(subtitle_label)
        layout.addLayout(welcome_header)

        # Quick actions
        actions_card = QGroupBox("Get Started")
        actions_layout = QVBoxLayout(actions_card)

        # Upload section
        upload_section = QVBoxLayout()

        upload_label = QLabel("📁 Upload Log Files")
        upload_label.setStyleSheet("font-size: 18px; font-weight: 600; color: #00d4ff; margin-bottom: 8px;")

        upload_desc = QLabel("Start by uploading your log files for analysis. Supports Apache, SSH, firewall, database, and system logs.")
        upload_desc.setStyleSheet("color: #94a3b8; line-height: 1.4; margin-bottom: 16px;")
        upload_desc.setWordWrap(True)

        upload_section.addWidget(upload_label)
        upload_section.addWidget(upload_desc)

        # Upload buttons
        upload_buttons = QHBoxLayout()
        upload_buttons.setSpacing(12)

        self.welcome_select_files_btn = QPushButton("📂 Select Files")
        self.welcome_select_files_btn.setObjectName("btn-primary")
        self.welcome_select_files_btn.clicked.connect(self.select_files)

        upload_buttons.addWidget(self.welcome_select_files_btn)
        self.welcome_analyze_btn = QPushButton("⚡ Analyze Files")
        self.welcome_analyze_btn.setObjectName("btn-primary")
        self.welcome_analyze_btn.clicked.connect(self.analyze_from_welcome)
        self.welcome_analyze_btn.setVisible(False)
        upload_buttons.addWidget(self.welcome_analyze_btn)
        upload_buttons.addStretch()

        # File list for welcome screen
        self.welcome_file_list = QListWidget()
        self.welcome_file_list.setMaximumHeight(120)
        self.welcome_file_list.setStyleSheet("""
            QListWidget {
                background: rgba(26, 26, 46, 0.8);
                border: 1px solid rgba(42, 42, 78, 0.5);
                border-radius: 8px;
                color: #ffffff;
            }
            QListWidget::item {
                padding: 6px 10px;
                border-bottom: 1px solid rgba(42, 42, 78, 0.3);
            }
            QListWidget::item:hover {
                background: rgba(15, 52, 96, 0.5);
            }
        """)
        upload_section.addWidget(self.welcome_file_list)

        upload_section.addLayout(upload_buttons)
        actions_layout.addLayout(upload_section)

        # Recent history section
        if self.analysis_history:
            history_section = QVBoxLayout()

            history_label = QLabel("📚 Recent Analysis")
            history_label.setStyleSheet("font-size: 18px; font-weight: 600; color: #00d4ff; margin: 24px 0 8px 0;")

            history_section.addWidget(history_label)

            self.history_list = QListWidget()
            self.history_list.setMaximumHeight(150)
            self.history_list.itemDoubleClicked.connect(self.load_from_history)

            for item in self.analysis_history[-5:]:  # Show last 5
                list_item = QListWidgetItem(f"📊 {item['timestamp']} - {item['file_count']} files, {item['entry_count']} entries")
                list_item.setData(Qt.UserRole, item)
                self.history_list.addItem(list_item)

            history_section.addWidget(self.history_list)
            actions_layout.addLayout(history_section)

        layout.addWidget(actions_card)
        layout.addStretch()

        self.stacked_widget.addWidget(welcome_widget)

    def create_analysis_view(self):
        """Create the analysis view with tabs"""
        analysis_widget = QWidget()
        layout = QVBoxLayout(analysis_widget)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Back to welcome button
        back_layout = QHBoxLayout()
        self.back_to_welcome_btn = QPushButton("⬅️ Back to Welcome")
        self.back_to_welcome_btn.setObjectName("btn-secondary")
        self.back_to_welcome_btn.clicked.connect(self.show_welcome_view)
        back_layout.addWidget(self.back_to_welcome_btn)
        back_layout.addStretch()
        layout.addLayout(back_layout)

        # Create tab widget with modern styling
        self.tab_widget = QTabWidget()
        self.tab_widget.setObjectName("mainTabs")
        layout.addWidget(self.tab_widget)

        self.stacked_widget.addWidget(analysis_widget)

        self.setWindowTitle("🔍 FreeKhana SIEM Tool")

    def show_analysis_view(self):
        """Show the analysis view"""
        self.current_view = "analysis"
        self.stats_widget.setVisible(True)
        self.stacked_widget.setCurrentIndex(1)
        self.setWindowTitle("🔍 FreeKhana SIEM Tool - Analysis")

    def load_history(self):
        """Load analysis history from file"""
        try:
            history_file = Path.home() / ".freekhana_siem" / "history.json"
            if history_file.exists():
                with open(history_file, 'r') as f:
                    self.analysis_history = json.load(f)
        except:
            self.analysis_history = []

    def save_to_history(self):
        """Save current analysis to history"""
        if not self.entries:
            return

        history_item = {
            'timestamp': datetime.datetime.now().isoformat(),
            'file_count': len(self.current_files),
            'entry_count': len(self.entries),
            'files': [os.path.basename(f) for f in self.current_files],
            'stats': {
                'total_lines': len(self.entries),
                'by_type': dict(Counter(e.log_type for e in self.entries)),
                'by_severity': dict(Counter(e.severity for e in self.entries))
            }
        }

        self.analysis_history.append(history_item)

        # Keep only last 20 items
        self.analysis_history = self.analysis_history[-20:]

        # Save to file
        try:
            history_dir = Path.home() / ".freekhana_siem"
            history_dir.mkdir(exist_ok=True)
            history_file = history_dir / "history.json"

            with open(history_file, 'w') as f:
                json.dump(self.analysis_history, f, indent=2)
        except Exception as e:
            print(f"Failed to save history: {e}")

    def load_from_history(self, item):
        """Load analysis from history"""
        history_data = item.data(Qt.UserRole)
        # This would need more implementation to actually reload the analysis
        QMessageBox.information(self, "History", f"Loading analysis from {history_data['timestamp']}\n(This feature needs full implementation)")

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("🔍 FreeKhana SIEM Tool")
        self.setGeometry(100, 100, 1400, 900)
        self.setWindowIcon(QIcon())  # Add icon if available

        # Create central widget
        central_widget = QWidget()
        central_widget.setObjectName("centralWidget")
        self.setCentralWidget(central_widget)

        # Main layout with modern spacing
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Modern header
        self.create_modern_header(layout)

        # Create stacked widget for different views
        self.stacked_widget = QStackedWidget()
        layout.addWidget(self.stacked_widget)

        # Create welcome screen
        self.create_welcome_view()

        # Create analysis view
        self.create_analysis_view()

        # Create tab contents for analysis view
        self.create_upload_tab()
        self.create_logs_tab()
        self.create_alerts_tab()
        self.create_attack_chains_tab()
        self.create_timeline_tab()
        self.create_analytics_tab()
        self.create_history_tab()

        # Show welcome screen initially
        self.show_welcome_view()

        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")

        # Progress bar (hidden initially)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

    def create_upload_tab(self):
        """Create the modern file upload tab"""
        upload_widget = QWidget()
        layout = QVBoxLayout(upload_widget)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)

        # Mode selection card
        mode_card = QGroupBox("🎯 Analysis Mode")
        mode_layout = QHBoxLayout(mode_card)

        self.single_mode = QRadioButton("📄 Single Log Analysis")
        self.multi_mode = QRadioButton("🔗 Multi-Log Correlation")
        self.single_mode.setChecked(True)

        # Style radio buttons
        self.single_mode.setStyleSheet("QRadioButton { font-size: 14px; font-weight: 500; }")
        self.multi_mode.setStyleSheet("QRadioButton { font-size: 14px; font-weight: 500; }")

        mode_layout.addWidget(self.single_mode)
        mode_layout.addWidget(self.multi_mode)
        mode_layout.addStretch()

        layout.addWidget(mode_card)

        # Upload area card
        upload_card = QFrame()
        upload_card.setObjectName("drop-zone")
        upload_layout = QVBoxLayout(upload_card)

        # Upload icon and text
        upload_header = QVBoxLayout()
        icon_label = QLabel("📤")
        icon_label.setStyleSheet("font-size: 48px; margin-bottom: 16px;")
        icon_label.setAlignment(Qt.AlignCenter)

        title_label = QLabel("Drop Your Log Files Here")
        title_label.setStyleSheet("font-size: 20px; font-weight: bold; color: #00d4ff; margin-bottom: 8px;")
        title_label.setAlignment(Qt.AlignCenter)

        subtitle_label = QLabel("Drag & drop files or click to browse\nSupports 56+ log formats: Apache, SSH, Firewall, Database, System logs")
        subtitle_label.setStyleSheet("color: #b8c5d6; text-align: center; line-height: 1.5;")
        subtitle_label.setAlignment(Qt.AlignCenter)

        upload_header.addWidget(icon_label)
        upload_header.addWidget(title_label)
        upload_header.addWidget(subtitle_label)

        self.upload_text = QTextEdit()
        self.upload_text.setPlaceholderText("Drop files here...")
        self.upload_text.setAcceptDrops(True)
        self.upload_text.setMaximumHeight(120)
        self.upload_text.setStyleSheet("""
            QTextEdit {
                background: rgba(26, 26, 46, 0.8);
                border: 2px dashed rgba(0, 212, 255, 0.3);
                border-radius: 8px;
                color: #b8c5d6;
                font-family: 'Consolas', monospace;
            }
        """)

        upload_layout.addLayout(upload_header)
        upload_layout.addWidget(self.upload_text)

        # Action buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(12)

        self.select_files_btn = QPushButton("📂 Select Files")
        self.select_files_btn.setObjectName("btn-secondary")

        self.clear_files_btn = QPushButton("🗑️ Clear")
        self.clear_files_btn.setObjectName("btn-secondary")

        self.analyze_btn = QPushButton("⚡ Analyze Logs")
        self.analyze_btn.setObjectName("btn-primary")

        button_layout.addWidget(self.select_files_btn)
        button_layout.addWidget(self.clear_files_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.analyze_btn)

        upload_layout.addLayout(button_layout)

        layout.addWidget(upload_card)

        # File list card
        files_card = QGroupBox("📋 Selected Files")
        files_layout = QVBoxLayout(files_card)

        self.file_list = QListWidget()
        self.file_list.setMaximumHeight(200)
        self.file_list.setStyleSheet("""
            QListWidget {
                background: rgba(26, 26, 46, 0.8);
                border: 1px solid rgba(42, 42, 78, 0.5);
                border-radius: 8px;
                color: #ffffff;
            }
            QListWidget::item {
                padding: 8px 12px;
                border-bottom: 1px solid rgba(42, 42, 78, 0.3);
            }
            QListWidget::item:hover {
                background: rgba(15, 52, 96, 0.5);
            }
            QListWidget::item:selected {
                background: rgba(0, 212, 255, 0.2);
                color: #00d4ff;
            }
        """)

        files_layout.addWidget(self.file_list)

        # Multi-file correlation button
        self.correlation_btn = QPushButton("🚀 Run ML Correlation Analysis")
        self.correlation_btn.setObjectName("btn-primary")
        self.correlation_btn.setVisible(False)
        files_layout.addWidget(self.correlation_btn)

        layout.addWidget(files_card)
        layout.addStretch()

        self.tab_widget.addTab(upload_widget, "📁 Upload")

    def create_logs_tab(self):
        """Create the modern logs display tab"""
        logs_widget = QWidget()
        layout = QVBoxLayout(logs_widget)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Filters card
        filter_card = QGroupBox("🔍 Filters & Search")
        filter_layout = QHBoxLayout(filter_card)
        filter_layout.setSpacing(16)

        # Search input with icon
        search_container = QWidget()
        search_layout = QHBoxLayout(search_container)
        search_layout.setContentsMargins(0, 0, 0, 0)

        search_icon = QLabel("🔍")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search logs, IPs, users, messages...")

        search_layout.addWidget(search_icon)
        search_layout.addWidget(self.search_input)

        # Severity filter
        severity_container = QWidget()
        severity_layout = QHBoxLayout(severity_container)
        severity_layout.setContentsMargins(0, 0, 0, 0)

        severity_icon = QLabel("⚠️")
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["All Severities", "Critical", "Error", "Warning", "Info", "Debug"])

        severity_layout.addWidget(severity_icon)
        severity_layout.addWidget(self.severity_combo)

        filter_layout.addWidget(search_container)
        filter_layout.addWidget(severity_container)
        filter_layout.addStretch()

        layout.addWidget(filter_card)

        # Logs table card
        table_card = QGroupBox("📊 Parsed Log Entries")
        table_layout = QVBoxLayout(table_card)

        # Table container for consistent width
        table_container = QWidget()
        table_container.setObjectName("table-container")
        table_layout_inner = QVBoxLayout(table_container)
        table_layout_inner.setContentsMargins(0, 0, 0, 0)

        self.logs_table = QTableWidget()
        self.logs_table.setColumnCount(6)
        self.logs_table.setHorizontalHeaderLabels(["🕐 Timestamp", "⚠️ Severity", "🌐 Source", "👤 User", "⚡ Action", "💬 Message"])

        # Modern table styling
        self.logs_table.setAlternatingRowColors(True)
        self.logs_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.logs_table.setSortingEnabled(True)

        # Ensure table maintains width
        self.logs_table.setMinimumWidth(800)
        self.logs_table.horizontalHeader().setStretchLastSection(True)
        self.logs_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)

        # Set column widths
        self.logs_table.setColumnWidth(0, 180)  # Timestamp
        self.logs_table.setColumnWidth(1, 100)  # Severity
        self.logs_table.setColumnWidth(2, 150)  # Source
        self.logs_table.setColumnWidth(3, 120)  # User
        self.logs_table.setColumnWidth(4, 100)  # Action

        table_layout_inner.addWidget(self.logs_table)
        table_layout.addWidget(table_container)

        # Stats display
        stats_container = QWidget()
        stats_layout = QHBoxLayout(stats_container)
        stats_layout.setContentsMargins(0, 0, 0, 0)

        self.logs_stats_label = QLabel("📊 No logs loaded")
        self.logs_stats_label.setStyleSheet("""
            QLabel {
                color: #00d4ff;
                font-size: 14px;
                font-weight: 500;
                padding: 8px 16px;
                background: rgba(0, 212, 255, 0.1);
                border-radius: 6px;
                border: 1px solid rgba(0, 212, 255, 0.3);
            }
        """)

        stats_layout.addWidget(self.logs_stats_label)
        stats_layout.addStretch()

        table_layout.addWidget(stats_container)

        layout.addWidget(table_card)

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

    def create_history_tab(self):
        """Create the history tab"""
        history_widget = QWidget()
        layout = QVBoxLayout(history_widget)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # History header
        history_header = QHBoxLayout()

        title_label = QLabel("📚 Analysis History")
        title_label.setStyleSheet("font-size: 20px; font-weight: bold; color: #00d4ff;")

        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.setObjectName("btn-secondary")
        refresh_btn.clicked.connect(self.load_history)

        history_header.addWidget(title_label)
        history_header.addStretch()
        history_header.addWidget(refresh_btn)

        layout.addLayout(history_header)

        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels(["🕐 Date & Time", "📁 Files", "📊 Entries", "⚠️ Types", "🔍 Actions"])
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.setAlternatingRowColors(True)

        # Set column widths
        self.history_table.setColumnWidth(0, 180)
        self.history_table.setColumnWidth(1, 120)
        self.history_table.setColumnWidth(2, 100)
        self.history_table.setColumnWidth(3, 150)

        layout.addWidget(self.history_table)

        # Load history data
        self.refresh_history_table()

        self.tab_widget.addTab(history_widget, "📖 History")

    def refresh_history_table(self):
        """Refresh the history table with current data"""
        self.history_table.setRowCount(len(self.analysis_history))

        for row, item in enumerate(reversed(self.analysis_history)):  # Most recent first
            # Timestamp
            timestamp = datetime.datetime.fromisoformat(item['timestamp'])
            self.history_table.setItem(row, 0, QTableWidgetItem(timestamp.strftime("%Y-%m-%d %H:%M:%S")))

            # Files count
            self.history_table.setItem(row, 1, QTableWidgetItem(str(item['file_count'])))

            # Entries count
            self.history_table.setItem(row, 2, QTableWidgetItem(str(item['entry_count'])))

            # Log types
            stats = item.get('stats', {})
            types_str = ", ".join([f"{k}: {v}" for k, v in stats.get('by_type', {}).items()][:3])
            if len(stats.get('by_type', {})) > 3:
                types_str += "..."
            self.history_table.setItem(row, 3, QTableWidgetItem(types_str))

            # Actions button
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(4, 4, 4, 4)

            load_btn = QPushButton("📂 Load")
            load_btn.setObjectName("btn-secondary")
            load_btn.setFixedWidth(60)
            # Store reference to item for loading
            load_btn.setProperty("history_item", item)

            actions_layout.addWidget(load_btn)
            actions_layout.addStretch()

            self.history_table.setCellWidget(row, 4, actions_widget)

    def setup_connections(self):
        """Setup signal connections"""
        self.select_files_btn.clicked.connect(self.select_files)
        self.clear_files_btn.clicked.connect(self.clear_files)
        self.analyze_btn.clicked.connect(self.analyze_logs)
        self.correlation_btn.clicked.connect(self.run_correlation)
        self.search_input.textChanged.connect(self.filter_logs)
        self.severity_combo.currentTextChanged.connect(self.filter_logs)

        # Mode change connections
        self.single_mode.toggled.connect(self.on_mode_changed)
        self.multi_mode.toggled.connect(self.on_mode_changed)

        # File drag and drop
        self.upload_text.dragEnterEvent = self.drag_enter_event
        self.upload_text.dropEvent = self.drop_event

    def on_mode_changed(self):
        """Handle mode change between single and multi"""
        is_multi = self.multi_mode.isChecked()
        self.correlation_btn.setVisible(is_multi and len(self.current_files) > 1)
        self.analyze_btn.setText("📄 Analyze Single Log" if not is_multi else "🔗 Start Multi-Log Analysis")

    def run_correlation(self):
        """Run correlation analysis on uploaded files"""
        self.analyze_logs()

    def drag_enter_event(self, event):
        """Handle drag enter events"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.upload_text.setStyleSheet("""
                QTextEdit {
                    background: rgba(0, 212, 255, 0.1);
                    border: 2px solid #00d4ff;
                    border-radius: 8px;
                    color: #00d4ff;
                }
            """)

    def drop_event(self, event):
        """Handle file drop events"""
        self.upload_text.setStyleSheet("""
            QTextEdit {
                background: rgba(26, 26, 46, 0.8);
                border: 2px dashed rgba(0, 212, 255, 0.3);
                border-radius: 8px;
                color: #b8c5d6;
                font-family: 'Consolas', monospace;
            }
        """)

        urls = event.mimeData().urls()
        files = [url.toLocalFile() for url in urls if url.isLocalFile()]

        if files:
            if self.multi_mode.isChecked():
                self.current_files.extend(files)
            else:
                self.current_files = [files[0]]

            self.update_file_list()
            self.on_mode_changed()

    def select_files(self):
        """Open file dialog to select log files"""
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Log Files",
            "",
            "Log Files (*.log *.txt *.json);;All Files (*)"
        )

        if files:
            if self.multi_mode.isChecked():
                self.current_files.extend(files)
            else:
                self.current_files = [files[0]]

            self.update_file_list()
            self.on_mode_changed()

            # Update welcome screen list if on welcome view
            if self.current_view == "welcome":
                self.welcome_file_list.clear()
                for file_path in self.current_files:
                    self.welcome_file_list.addItem(f"📄 {os.path.basename(file_path)}")

                # Show analyze button
                self.welcome_analyze_btn.setVisible(True)

    def analyze_from_welcome(self):
        """Analyze files from welcome screen"""
        if self.current_files:
            self.show_analysis_view()
            self.analyze_logs()

    def clear_files(self):
        """Clear selected files"""
        self.current_files = []
        self.file_list.clear()

        if hasattr(self, 'welcome_file_list'):
            self.welcome_file_list.clear()
            self.welcome_analyze_btn.setVisible(False)

        self.on_mode_changed()
        self.status_bar.showMessage("Files cleared")

    def analyze_logs(self):
        """Start log analysis in background thread"""
        if not self.current_files:
            QMessageBox.warning(self, "No Files", "Please select log files first")
            return

        # Disable buttons
        self.analyze_btn.setEnabled(False)
        self.select_files_btn.setEnabled(False)

        # Show progress bar
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        # Create worker thread
        correlation = self.multi_mode.isChecked() and len(self.current_files) > 1
        self.worker = SIEMWorker(self.current_files, correlation=correlation)
        self.worker.progress.connect(self.on_analysis_progress)
        self.worker.finished.connect(self.on_analysis_finished)
        self.worker.error.connect(self.on_analysis_error)
        self.worker.start()

        self.status_bar.showMessage("Analyzing logs...")

    def on_analysis_progress(self, value):
        """Update progress during analysis"""
        self.progress_bar.setValue(value)

    def on_analysis_finished(self, result):
        """Handle analysis completion"""
        self.entries = result['entries']
        stats = result['stats']
        self.correlation_data = result.get('correlation')

        # Update logs table
        self.update_logs_table()

        # Update header stats
        self.update_header_stats(stats)

        # Update alerts if correlation data exists
        if self.correlation_data:
            self.update_alerts_tab()
            self.update_attack_chains_tab()

        # Save to history
        self.save_to_history()

        # Re-enable buttons
        self.analyze_btn.setEnabled(True)
        self.select_files_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

        self.status_bar.showMessage(f"Analysis complete: {len(self.entries)} entries parsed")

        # Switch to logs tab
        self.tab_widget.setCurrentIndex(1)

    def on_analysis_error(self, error_msg):
        """Handle analysis error"""
        QMessageBox.critical(self, "Analysis Error", f"Error during analysis:\n{error_msg}")
        self.analyze_btn.setEnabled(True)
        self.select_files_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_bar.showMessage("Analysis failed")

    def update_logs_table(self):
        """Update logs table with parsed entries"""
        self.logs_table.setRowCount(0)
        self.logs_table.setRowCount(len(self.entries))

        for row, entry in enumerate(self.entries):
            # Timestamp
            timestamp_item = QTableWidgetItem(entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if entry.timestamp else "N/A")
            self.logs_table.setItem(row, 0, timestamp_item)

            # Severity
            severity_item = QTableWidgetItem(entry.severity.upper())
            severity_color = SEVERITY_COLORS.get(entry.severity, '#94a3b8')
            severity_item.setForeground(QColor(severity_color))
            self.logs_table.setItem(row, 1, severity_item)

            # Source
            source_str = entry.source.get('ip', 'N/A') if entry.source else 'N/A'
            self.logs_table.setItem(row, 2, QTableWidgetItem(source_str))

            # User
            user_str = entry.user.get('name', 'N/A') if entry.user and entry.user.get('name') else 'N/A'
            self.logs_table.setItem(row, 3, QTableWidgetItem(user_str))

            # Action
            action_str = entry.action or 'N/A'
            self.logs_table.setItem(row, 4, QTableWidgetItem(action_str))

            # Message
            message_str = entry.message[:100] + "..." if len(entry.message) > 100 else entry.message
            self.logs_table.setItem(row, 5, QTableWidgetItem(message_str))

        # Update stats
        self.logs_stats_label.setText(f"📊 Showing {len(self.entries)} log entries")

    def update_header_stats(self, stats):
        """Update header statistics"""
        # Show stats widget
        self.stats_widget.setVisible(True)

        # Update risk score
        risk_score = 0
        if self.correlation_data:
            risk_score = self.correlation_data.get('summary', {}).get('risk_score', 0)

        risk_value = self.risk_card.findChild(QLabel, "value")
        if risk_value:
            risk_value.setText(f"{risk_score}/100")
            risk_color = '#ef4444' if risk_score > 70 else '#f59e0b' if risk_score > 40 else '#22c55e'
            risk_value.setStyleSheet(f"color: {risk_color}; font-size: 18px; font-weight: bold; text-align: center;")

        # Update attack chains
        attack_chains = len(self.correlation_data.get('attack_chains', [])) if self.correlation_data else 0
        chains_value = self.chains_card.findChild(QLabel, "value")
        if chains_value:
            chains_value.setText(str(attack_chains))

        # Update total logs
        logs_value = self.logs_card.findChild(QLabel, "value")
        if logs_value:
            logs_value.setText(str(stats.get('total_lines', 0)))

        # Update parsed
        parsed_value = self.parsed_card.findChild(QLabel, "value")
        if parsed_value:
            parsed_value.setText(str(stats.get('parsed_lines', 0)))

    def update_alerts_tab(self):
        """Update alerts tab with correlation results"""
        if not self.correlation_data:
            return

        summary = self.correlation_data.get('summary', {})
        self.alerts_table.setRowCount(0)

        alerts = []

        # Add alerts from attack chains
        for chain in self.correlation_data.get('attack_chains', []):
            alert = [
                'HIGH' if chain.stage == 'initial_access' else 'MEDIUM',
                f"{chain.attack_type.replace('_', ' ').title()} Attack",
                f"Detected {len(chain.events)} related events from {len(chain.source_ips)} sources",
                f"{chain.prediction.get('confidence', 0) * 100:.1f}%"
            ]
            alerts.append(alert)

        # Add alerts for critical severity logs
        critical_entries = [e for e in self.entries if e.severity == 'critical']
        if critical_entries:
            alerts.append([
                'CRITICAL',
                f'{len(critical_entries)} Critical Events',
                'Critical severity logs detected that require immediate attention',
                '100%'
            ])

        # Add alerts for errors
        error_entries = [e for e in self.entries if e.severity == 'error']
        if error_entries:
            alerts.append([
                'MEDIUM',
                f'{len(error_entries)} Error Events',
                'Multiple error events detected in logs',
                'N/A'
            ])

        self.alerts_table.setRowCount(len(alerts))

        for row, alert in enumerate(alerts):
            for col, value in enumerate(alert):
                item = QTableWidgetItem(value)
                if col == 0:
                    alert_color = '#ef4444' if value == 'CRITICAL' else '#f59e0b' if value == 'HIGH' else '#3b82f6'
                    item.setForeground(QColor(alert_color))
                self.alerts_table.setItem(row, col, item)

        self.alerts_stats_label.setText(f"🚨 {len(alerts)} alerts generated")

    def update_attack_chains_tab(self):
        """Update attack chains tab with correlation results"""
        if not self.correlation_data:
            return

        self.chains_list.clear()

        for chain in self.correlation_data.get('attack_chains', []):
            icon = ATTACK_TYPE_ICONS.get(chain.attack_type, '❓')
            stage_color = STAGE_COLORS.get(chain.stage, '#94a3b8')

            item_text = f"{icon} {chain.attack_type.replace('_', ' ').title()}"
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, chain)

            self.chains_list.addItem(item)

        if self.correlation_data.get('attack_chains'):
            self.chains_list.setCurrentRow(0)
            self.show_chain_details(self.correlation_data['attack_chains'][0])

        self.chains_list.itemClicked.connect(self.on_chain_selected)

    def on_chain_selected(self, item):
        """Handle attack chain selection"""
        chain = item.data(Qt.UserRole)
        self.show_chain_details(chain)

    def show_chain_details(self, chain):
        """Show details of selected attack chain"""
        details = f"""
        <h2>{ATTACK_TYPE_ICONS.get(chain.attack_type, '❓')} {chain.attack_type.replace('_', ' ').title()}</h2>

        <h3>📍 Stage</h3>
        <p style="color: {STAGE_COLORS.get(chain.stage, '#94a3b8')}; font-weight: bold;">{chain.stage.upper()}</p>

        <h3>📊 Statistics</h3>
        <ul>
            <li>Events: {len(chain.events)}</li>
            <li>Source IPs: {', '.join(chain.source_ips[:5])}{'...' if len(chain.source_ips) > 5 else ''}</li>
            <li>Target Users: {', '.join(chain.target_users[:5])}{'...' if len(chain.target_users) > 5 else ''}</li>
        </ul>

        <h3>🔍 Prediction</h3>
        <p><strong>Confidence:</strong> {chain.prediction.get('confidence', 0) * 100:.1f}%</p>
        <ul>
        {"".join(f"<li>{exp}</li>" for exp in chain.prediction.get('explanation', []))}
        </ul>

        <h3>🎯 MITRE ATT&CK</h3>
        <p><strong>Tactics:</strong> {', '.join(chain.mitre_tactics)}</p>
        <p><strong>Techniques:</strong> {', '.join(chain.mitre_techniques)}</p>

        <h3>💡 Recommendation</h3>
        <p>{chain.recommendation}</p>
        """

        self.chains_details.setHtml(details)

    def filter_logs(self):
        """Filter logs based on search and severity"""
        search_text = self.search_input.text().lower()
        severity_filter = self.severity_combo.currentText()

        for row in range(self.logs_table.rowCount()):
            should_show = True

            # Check severity
            if severity_filter != "All Severities":
                severity_item = self.logs_table.item(row, 1)
                if severity_item and severity_item.text().lower() != severity_filter.lower():
                    should_show = False

            # Check search text
            if search_text:
                row_matches = False
                for col in range(self.logs_table.columnCount()):
                    item = self.logs_table.item(row, col)
                    if item and search_text in item.text().lower():
                        row_matches = True
                        break

                if not row_matches:
                    should_show = False

            self.logs_table.setRowHidden(row, not should_show)

        # Update stats to show filtered count
        visible_count = sum(1 for row in range(self.logs_table.rowCount()) if not self.logs_table.isRowHidden(row))
        self.logs_stats_label.setText(f"📊 Showing {visible_count} of {len(self.entries)} log entries")

    def show_welcome_view(self):
        """Show the welcome view"""
        self.current_view = "welcome"
        self.stats_widget.setVisible(False)
        self.stacked_widget.setCurrentIndex(0)
        self.setWindowTitle("🔍 FreeKhana SIEM Tool")

    def update_file_list(self):
        """Update file list display"""
        self.file_list.clear()

        for file_path in self.current_files:
            item = QListWidgetItem(f"📄 {os.path.basename(file_path)}")
            item.setData(Qt.UserRole, file_path)
            self.file_list.addItem(item)

        # Show correlation button if multi-mode and multiple files
        self.correlation_btn.setVisible(self.multi_mode.isChecked() and len(self.current_files) > 1)

if __name__ == "__main__":
    import sys
    try:
        from PySide6.QtWidgets import QApplication
        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        print("Failed to start GUI:", e)
        sys.exit(1)
