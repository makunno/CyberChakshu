"""
Alert Detection System
"""

from typing import List, Dict, Any

def run_detections(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run detection rules on parsed entries"""
    alerts = []
    
    for entry in entries:
        # Check for failed logins
        if entry.get('outcome') == 'failure':
            alerts.append({
                'id': entry.get('id'),
                'type': 'failed_login',
                'severity': 'medium',
                'message': f"Failed login attempt from {entry.get('source', {}).get('ip', 'unknown')}",
                'entry': entry,
            })
        
        # Check for attack type
        if entry.get('attackType'):
            alerts.append({
                'id': entry.get('id'),
                'type': 'attack_detected',
                'severity': 'high',
                'message': f"Attack detected: {entry.get('attackType')} (confidence: {entry.get('attackConfidence', 0):.0%})",
                'entry': entry,
            })
    
    return alerts

def generate_stats(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate statistics from entries"""
    by_severity = {}
    by_outcome = {}
    by_type = {}
    source_ips = set()
    users = set()
    
    for entry in entries:
        # By severity
        severity = entry.get('severity', 'unknown')
        by_severity[severity] = by_severity.get(severity, 0) + 1
        
        # By outcome
        outcome = entry.get('outcome', 'unknown')
        by_outcome[outcome] = by_outcome.get(outcome, 0) + 1
        
        # By type
        log_type = entry.get('logType', 'unknown')
        by_type[log_type] = by_type.get(log_type, 0) + 1
        
        # Source IPs
        if entry.get('source', {}).get('ip'):
            source_ips.add(entry['source']['ip'])
        
        # Users
        if entry.get('user', {}).get('name'):
            users.add(entry['user']['name'])
    
    return {
        'bySeverity': by_severity,
        'byOutcome': by_outcome,
        'byType': by_type,
        'uniqueSources': len(source_ips),
        'uniqueUsers': len(users),
    }
