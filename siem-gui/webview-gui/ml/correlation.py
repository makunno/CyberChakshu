"""ML Module - Feature Extraction, Classification, and Correlation"""

import numpy as np
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from parsers.types import LogEntry


def extract_features(entries: List[dict]) -> np.ndarray:
    """Extract ML features from log entries"""
    if not entries:
        return np.array([])

    features = []
    for entry in entries:
        # Create feature vector
        vector = []

        # IP address hash
        ip = entry.get('source', {}).get('ip', '')
        vector.append(hash(ip) % 1000 / 1000.0 if ip else 0.0)

        # User hash
        user = entry.get('user', {}).get('name', '')
        vector.append(hash(user) % 1000 / 1000.0 if user else 0.0)

        # Message length
        message = entry.get('message', '')
        vector.append(len(message) / 1000.0)

        # Severity encoding
        severity = entry.get('severity', 'info')
        severity_map = {'debug': 0, 'info': 1, 'warning': 2, 'error': 3, 'critical': 4}
        vector.append(severity_map.get(severity, 1))

        # Number of fields
        fields = entry.get('fields', {})
        vector.append(len(fields) / 10.0)

        # Hour of day
        timestamp = entry.get('timestamp')
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                vector.append(dt.hour / 24.0)
            except:
                vector.append(0.5)
        else:
            vector.append(0.5)

        # Day of week
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                vector.append(dt.weekday() / 7.0)
            except:
                vector.append(0.5)
        else:
            vector.append(0.5)

        features.append(vector)

    return np.array(features)


def detect_anomalies(entries: List[dict]) -> List[dict]:
    """Detect anomalies using Isolation Forest"""
    if not ML_AVAILABLE or len(entries) < 10:
        return []

    features = extract_features(entries)

    try:
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)

        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        anomaly_scores = iso_forest.fit_predict(features_scaled)

        anomalies = []
        for i, (entry, score) in enumerate(zip(entries, anomaly_scores)):
            if score == -1:  # Anomaly
                anomaly_score = iso_forest.score_samples([features_scaled[i]])[0]
                anomalies.append({
                    'entry': entry,
                    'anomaly_score': float(abs(anomaly_score))
                })

        return anomalies
    except Exception as e:
        print(f"Anomaly detection error: {e}")
        return []


def correlate_multiple_logs(sources: List[dict]) -> dict:
    """Correlate multiple log sources and detect attack chains"""
    all_entries = []
    for source in sources:
        entries = source.get('entries', [])
        # Tag with source name
        for entry in entries:
            entry['logSource'] = source.get('name', 'unknown')
        all_entries.extend(entries)

    if not all_entries:
        return {
            'attackChains': [],
            'timeline': [],
            'summary': {
                'riskScore': 0,
                'criticalAlerts': 0,
                'falsePositivesFiltered': 0,
                'attackTypesDetected': [],
                'mostActiveSourceIps': [],
                'mostTargetedUsers': []
            },
            'totalEvents': 0,
            'recommendations': []
        }

    # Sort by timestamp
    sorted_entries = sorted(
        [e for e in all_entries if e.get('timestamp')],
        key=lambda x: x.get('timestamp', '')
    )

    # Detect anomalies
    anomalies = detect_anomalies(sorted_entries)
    anomaly_entry_ids = {a['entry'].get('id') for a in anomalies}

    # Find attack patterns
    attack_chains = find_attack_patterns(sorted_entries, anomalies)

    # Generate timeline
    timeline = generate_timeline(sorted_entries, anomalies)

    # Generate summary
    summary = generate_summary(sorted_entries, attack_chains, anomalies)

    # Generate recommendations
    recommendations = generate_recommendations(attack_chains)

    return {
        'attackChains': attack_chains,
        'timeline': timeline,
        'summary': summary,
        'totalEvents': len(all_entries),
        'recommendations': recommendations
    }


def find_attack_patterns(entries: List[dict], anomalies: List[dict]) -> List[dict]:
    """Find attack patterns across log entries"""
    attack_chains = []

    # Group by time windows (5 minutes)
    time_windows = group_by_time_window(entries, 5)

    # Pattern detection within windows
    for window in time_windows:
        if len(window) < 2:
            continue

        # Detect brute force patterns
        bf_chains = detect_bruteforce_chain(window, anomalies)
        attack_chains.extend(bf_chains)

        # Detect password spray patterns
        spray_chains = detect_password_spray_chain(window, anomalies)
        attack_chains.extend(spray_chains)

    return attack_chains


def detect_bruteforce_chain(window: List[dict], anomalies: List[dict]) -> List[dict]:
    """Detect brute force attack chain"""
    chains = []

    # Group failures by (IP, user)
    failures_by_ip_user = defaultdict(list)
    for entry in window:
        if entry.get('outcome') == 'failure' and entry.get('source', {}).get('ip'):
            key = f"{entry['source']['ip']}|{entry.get('user', {}).get('name', '')}"
            failures_by_ip_user[key].append(entry)

    # Check for brute force patterns
    for (ip_user, events) in failures_by_ip_user.items():
        if len(events) >= 5:  # Threshold
            ip, user = ip_user.split('|', 1) if '|' in ip_user else (ip_user, '')

            # Check time span
            timestamps = [e.get('timestamp') for e in events if e.get('timestamp')]
            if len(timestamps) >= 2:
                start = datetime.fromisoformat(timestamps[0].replace('Z', '+00:00'))
                end = datetime.fromisoformat(timestamps[-1].replace('Z', '+00:00'))
                span_minutes = (end - start).total_seconds() / 60

                if span_minutes <= 10:  # Within 10 minutes
                    # Create attack chain
                    chain = {
                        'id': f"bf_{ip}_{len(events)}",
                        'attackType': 'bruteforce',
                        'stage': 'initial_access',
                        'events': events[:10],
                        'sourceIps': [ip],
                        'targetUsers': [user] if user else [],
                        'startTime': timestamps[0],
                        'endTime': timestamps[-1],
                        'prediction': {
                            'confidence': min(0.7 + (len(events) / 50), 0.95),
                            'explanation': [
                                f'Detected {len(events)} failed authentication attempts',
                                f'All within {span_minutes:.1f} minutes',
                                f'Suggests brute force attack'
                            ]
                        },
                        'mitreTactics': ['TA0006'],
                        'mitreTechniques': ['T1110'],
                        'recommendation': 'Implement account lockout policies and monitor for suspicious login patterns'
                    }
                    chains.append(chain)

    return chains


def detect_password_spray_chain(window: List[dict], anomalies: List[dict]) -> List[dict]:
    """Detect password spray attack chain"""
    chains = []

    # Group failures by IP
    failures_by_ip = defaultdict(list)
    for entry in window:
        if entry.get('outcome') == 'failure' and entry.get('source', {}).get('ip'):
            failures_by_ip[entry['source']['ip']].append(entry)

    # Check for spray patterns (many unique users)
    for (ip, events) in failures_by_ip.items():
        unique_users = set()
        for e in events:
            user = e.get('user', {}).get('name')
            if user:
                unique_users.add(user)

        if len(unique_users) >= 10:  # Threshold
            # Check time span
            timestamps = [e.get('timestamp') for e in events if e.get('timestamp')]
            if timestamps:
                start = datetime.fromisoformat(timestamps[0].replace('Z', '+00:00'))
                end = datetime.fromisoformat(timestamps[-1].replace('Z', '+00:00'))
                span_minutes = (end - start).total_seconds() / 60

                if span_minutes <= 15:  # Within 15 minutes
                    chain = {
                        'id': f"spray_{ip}_{len(unique_users)}",
                        'attackType': 'password_spray',
                        'stage': 'initial_access',
                        'events': events[:10],
                        'sourceIps': [ip],
                        'targetUsers': list(unique_users),
                        'startTime': timestamps[0],
                        'endTime': timestamps[-1],
                        'prediction': {
                            'confidence': min(0.7 + (len(unique_users) / 50), 0.95),
                            'explanation': [
                                f'Detected {len(unique_users)} unique targeted users',
                                f'All within {span_minutes:.1f} minutes',
                                f'Suggests password spray attack'
                            ]
                        },
                        'mitreTactics': ['TA0006'],
                        'mitreTechniques': ['T1110'],
                        'recommendation': 'Implement MFA and monitor for authentication anomalies across multiple accounts'
                    }
                    chains.append(chain)

    return chains


def group_by_time_window(entries: List[dict], window_minutes: int) -> List[List[dict]]:
    """Group entries by time windows"""
    if not entries:
        return []

    # Filter entries with timestamps and sort
    sorted_entries = sorted(
        [e for e in entries if e.get('timestamp')],
        key=lambda x: datetime.fromisoformat(x['timestamp'].replace('Z', '+00:00'))
    )

    if not sorted_entries:
        return [entries]

    windows = []
    current_window = [sorted_entries[0]]
    window_start = datetime.fromisoformat(sorted_entries[0]['timestamp'].replace('Z', '+00:00'))

    for entry in sorted_entries[1:]:
        if entry.get('timestamp'):
            entry_time = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00'))
            if (entry_time - window_start).total_seconds() / 60 <= window_minutes:
                current_window.append(entry)
            else:
                if current_window:
                    windows.append(current_window)
                current_window = [entry]
                window_start = entry_time

    if current_window:
        windows.append(current_window)

    return windows


def generate_timeline(entries: List[dict], anomalies: List[dict]) -> List[dict]:
    """Generate timeline for visualization"""
    timeline = []
    anomaly_map = {a['entry'].get('id'): a for a in anomalies}

    for entry in entries[:500]:  # Limit to 500 for performance
        if entry.get('timestamp'):
            anomaly_data = anomaly_map.get(entry.get('id'))
            timeline.append({
                'id': entry.get('id'),
                'timestamp': entry['timestamp'],
                'count': 1,
                'isAnomaly': anomaly_data is not None,
                'severity': entry.get('severity', 'info'),
                'logSource': entry.get('logSource', 'unknown'),
                'title': entry.get('action', entry.get('message', '')[:50]),
                'description': entry.get('message', ''),
                'sourceIp': entry.get('source', {}).get('ip'),
                'anomalyScore': anomaly_data.get('anomaly_score') if anomaly_data else None,
                'correlationScore': anomaly_data.get('anomaly_score') if anomaly_data else None
            })

    return timeline


def generate_summary(entries: List[dict], attack_chains: List[dict], anomalies: List[dict]) -> dict:
    """Generate summary statistics"""
    # Count by severity
    severity_counts = defaultdict(int)
    for entry in entries:
        severity_counts[entry.get('severity', 'info')] += 1

    # Count source IPs
    ip_counts = defaultdict(int)
    for entry in entries:
        ip = entry.get('source', {}).get('ip')
        if ip:
            ip_counts[ip] += 1

    # Count users
    user_counts = defaultdict(int)
    for entry in entries:
        user = entry.get('user', {}).get('name')
        if user:
            user_counts[user] += 1

    # Calculate risk score
    risk_score = min(100, len(attack_chains) * 20 + severity_counts.get('critical', 0) * 10 + severity_counts.get('error', 0) * 5)

    # Top source IPs with threat scores
    most_active_ips = []
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        threat_score = 0
        for chain in attack_chains:
            if ip in chain.get('sourceIps', []):
                threat_score += chain['prediction']['confidence']
        most_active_ips.append({
            'ip': ip,
            'count': count,
            'threatScore': min(threat_score, 1.0)
        })

    # Top users
    most_targeted_users = []
    for user, count in sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        most_targeted_users.append({
            'user': user,
            'count': count
        })

    # Attack types detected
    attack_types = list(set(chain.get('attackType') for chain in attack_chains))

    return {
        'riskScore': int(risk_score),
        'criticalAlerts': severity_counts.get('critical', 0),
        'falsePositivesFiltered': int(len(anomalies) * 0.1),  # Assume 10% false positives
        'attackTypesDetected': attack_types,
        'mostActiveSourceIps': most_active_ips,
        'mostTargetedUsers': most_targeted_users
    }


def generate_recommendations(attack_chains: List[dict]) -> List[str]:
    """Generate security recommendations"""
    recommendations = []

    if any(chain.get('attackType') == 'bruteforce' for chain in attack_chains):
        recommendations.extend([
            'Implement multi-factor authentication (MFA) for all user accounts',
            'Configure account lockout policies after failed login attempts',
            'Monitor and alert on suspicious login patterns',
            'Consider implementing rate limiting on authentication endpoints'
        ])

    if any(chain.get('attackType') == 'password_spray' for chain in attack_chains):
        recommendations.extend([
            'Implement MFA to prevent password spray attacks',
            'Use strong password policies and regular rotation',
            'Monitor for login attempts from unusual locations',
            'Consider using CAPTCHA for failed login attempts'
        ])

    if not recommendations:
        recommendations.append('Continue monitoring log files for security events')

    return recommendations
