"""
Log Parsers - Auto-detection and parsing for various log types
Uses ISEA-style detection from log_detector.py
"""

from typing import Dict, Any, Optional, List
import re
import json
import uuid
from datetime import datetime
from .log_detector import LogDetector, preprocess_json_array
from .log_parsers import LogParsers


def detect_log_type(content: str) -> str:
    """Auto-detect log type from content using ISEA-style detection"""
    processed = preprocess_json_array(content)
    return LogDetector.detect(processed)


def auto_parse(content: str, force_type: Optional[str] = None) -> Dict[str, Any]:
    """Auto-parse log content with full field extraction"""
    log_type = force_type or detect_log_type(content)
    processed = preprocess_json_array(content)
    lines = [l for l in processed.split('\n') if l.strip()]
    
    entries = []
    for line in lines:
        entry = parse_line(line, log_type)
        if entry:
            entries.append(entry)
    
    stats = generate_stats(entries)
    
    return {
        'detectedType': log_type,
        'entries': entries,
        'stats': stats
    }


def parse_line(line: str, log_type: str) -> Optional[Dict[str, Any]]:
    """Parse a single log line with full field extraction"""
    try:
        parsed_data = LogParsers.parse_by_type(line, log_type)
        
        # If no specific parser matched, try generic parsing
        if not parsed_data:
            parsed_data = generic_parse(line)
        
        entry: Dict[str, Any] = {
            'id': str(uuid.uuid4()),
            'timestamp': extract_timestamp(line, parsed_data),
            'logType': map_log_type(log_type),
            'severity': extract_severity(line, log_type),
            'source': extract_source(line, parsed_data),
            'user': extract_user(line, parsed_data),
            'action': extract_action(line, parsed_data, log_type),
            'outcome': extract_outcome(line, parsed_data, log_type),
            'message': line,
            'rawLine': line,
            'fields': parsed_data or {},
            'tags': generate_tags(log_type, line),
        }
        
        return entry
    except Exception:
        return None


def generic_parse(line: str) -> Optional[Dict[str, Any]]:
    """Generic parser for any log format - extracts common fields"""
    result = {}
    
    # Extract IP addresses
    ip_patterns = [
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        r'src[=_]?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    ]
    for pattern in ip_patterns:
        match = re.search(pattern, line)
        if match:
            result['ip'] = match.group(1)
            break
    
    # Extract port
    port_match = re.search(r'port\s*[:=]?\s*(\d+)', line, re.IGNORECASE)
    if port_match:
        result['port'] = int(port_match.group(1))
    
    # Extract user
    user_patterns = [
        r'for\s+(\S+?)\s+from',
        r'user[=:\s]+(\w+)',
        r'User:\s*(\S+)',
        r'account[=:\s]+(\w+)',
    ]
    for pattern in user_patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            result['user'] = match.group(1)
            break
    
    # Extract status code
    status_match = re.search(r'\s(\d{3})\s', line)
    if status_match:
        result['status'] = int(status_match.group(1))
    
    # Extract HTTP method
    http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
    for method in http_methods:
        if f'"{method}' in line:
            result['method'] = method
            break
    
    # Extract request path
    request_match = re.search(r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)', line)
    if request_match:
        result['request'] = f"{request_match.group(1)} {request_match.group(2)}"
    
    # Extract service/program
    service_match = re.search(r'(\w+)(?:\[\d+\])?:', line)
    if service_match and not service_match.group(1).isdigit():
        result['service'] = service_match.group(1)
    
    # Extract bytes
    bytes_match = re.search(r'(\d+)\s*$', line)
    if bytes_match and result.get('status'):
        try:
            result['bytes'] = int(bytes_match.group(1))
        except:
            pass
    
    return result if result else None


def extract_timestamp(line: str, parsed: Optional[Dict[str, Any]]) -> str:
    """Extract timestamp from log line"""
    if parsed and 'timestamp' in parsed:
        ts = parsed['timestamp']
        try:
            return datetime.strptime(ts[:19], '%Y-%m-%d %H:%M:%S').isoformat()
        except:
            pass
    
    patterns = [
        (r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', '%Y-%m-%dT%H:%M:%S'),
        (r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})', '%d/%b/%Y:%H:%M:%S'),
        (r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})', '%b %d %H:%M:%S'),
        (r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', '%Y-%m-%d %H:%M:%S'),
    ]
    
    for pattern, fmt in patterns:
        match = re.search(pattern, line)
        if match:
            try:
                return datetime.strptime(match.group(1)[:19], fmt).isoformat()
            except:
                pass
    
    return datetime.now().isoformat()


def extract_severity(line: str, log_type: str) -> str:
    """Extract severity from log line"""
    line_lower = line.lower()
    
    if any(x in line_lower for x in ['critical', 'fatal', 'crit']):
        return 'critical'
    if any(x in line_lower for x in ['error', 'err', 'fail', 'failed', 'denied', 'reject']):
        return 'error'
    if any(x in line_lower for x in ['warning', 'warn', 'alert']):
        return 'warning'
    if any(x in line_lower for x in ['debug', 'trace']):
        return 'debug'
    return 'info'


def extract_source(line: str, parsed: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract source information (IP, hostname, etc.)"""
    source: Dict[str, Any] = {}
    
    ip_patterns = [
        r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        r'SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        r'srcip=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        r'src_ip=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    ]
    
    for pattern in ip_patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            source['ip'] = match.group(1)
            break
    
    port_patterns = [
        r'port\s+(\d+)',
        r'DPT=(\d+)',
        r'dstport=(\d+)',
    ]
    
    for pattern in port_patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            source['port'] = int(match.group(1))
            break
    
    if parsed:
        if 'host' in parsed:
            source['hostname'] = parsed['host']
        if 'ip' in parsed:
            source['ip'] = parsed['ip']
        if 'src_ip' in parsed:
            source['ip'] = parsed['src_ip']
        if 'server_ip' in parsed:
            source['ip'] = parsed['server_ip']
    
    return source


def extract_user(line: str, parsed: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract user information"""
    user: Dict[str, Any] = {}
    
    user_patterns = [
        r'for\s+(\S+)\s+from',
        r'user[=:\s]+(\w+)',
        r'User:\s*(\S+)',
    ]
    
    for pattern in user_patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            user['name'] = match.group(1)
            break
    
    if parsed and 'user' in parsed:
        user['name'] = parsed['user']
    
    return user


def extract_action(line: str, parsed: Optional[Dict[str, Any]], log_type: str) -> str:
    """Extract action from log line"""
    if parsed:
        # Try to get from parsed data
        if 'action' in parsed:
            return parsed['action']
        # Extract HTTP method from request (e.g., "GET /admin HTTP/1.1")
        if 'request' in parsed:
            request = parsed['request']
            method = request.split()[0] if request else ''
            if method:
                return method.lower()
    
    line_lower = line.lower()
    
    if 'accepted' in line_lower or 'success' in line_lower or 'allow' in line_lower:
        return 'allow'
    if 'failed' in line_lower or 'denied' in line_lower or 'reject' in line_lower or 'drop' in line_lower:
        return 'deny'
    if 'connect' in line_lower or 'login' in line_lower:
        return 'connect'
    if 'disconnect' in line_lower or 'logout' in line_lower:
        return 'disconnect'
    
    return 'unknown'


def extract_outcome(line: str, parsed: Optional[Dict[str, Any]], log_type: str) -> str:
    """Extract outcome (success/failure)"""
    # Use status code from parsed data if available
    if parsed and 'status' in parsed:
        status = parsed['status']
        if isinstance(status, int):
            if 200 <= status < 300:
                return 'success'
            elif status >= 400:
                return 'failure'
    
    line_lower = line.lower()
    
    if any(x in line_lower for x in ['accepted', 'success', 'allowed', 'completed']):
        return 'success'
    if any(x in line_lower for x in ['failed', 'denied', 'reject', 'error', 'deny', 'drop']):
        return 'failure'
    
    return 'unknown'


def generate_tags(log_type: str, line: str) -> List[str]:
    """Generate tags based on log type"""
    tags = []
    
    type_tag = map_log_type(log_type)
    if type_tag:
        tags.append(type_tag)
    
    line_lower = line.lower()
    if any(x in line_lower for x in ['error', 'fail', 'critical']):
        tags.append('error')
    if any(x in line_lower for x in ['warning', 'warn']):
        tags.append('warning')
    if any(x in line_lower for x in ['auth', 'login', 'password', 'ssh']):
        tags.append('auth')
    if any(x in line_lower for x in ['attack', 'injection', 'exploit']):
        tags.append('security')
    
    return tags


def map_log_type(detected_type: str) -> str:
    """Map detected type to normalized log type"""
    mapping = {
        'Apache': 'apache',
        'Apache Error': 'apache',
        'NGINX': 'nginx',
        'Nginx Error': 'nginx',
        'Django': 'django',
        'Flask': 'flask',
        'Node.js': 'express',
        'Express.js': 'express',
        'Laravel': 'laravel',
        'Ruby on Rails': 'rails',
        'Gunicorn': 'gunicorn',
        'Uvicorn': 'uvicorn',
        'FastAPI': 'fastapi',
        'IIS': 'iis',
        'Postfix': 'postfix',
        'Sendmail': 'sendmail',
        'Exim': 'exim',
        'Dovecot': 'dovecot',
        'iptables': 'iptables',
        'UFW': 'ufw',
        'nftables': 'nftables',
        'firewalld': 'firewalld',
        'Palo Alto Firewall': 'palo_alto',
        'FortiGate': 'fortigate',
        'Cisco ASA': 'cisco_asa',
        'Check Point Firewall': 'checkpoint',
        'AWS VPC Flow Logs': 'aws_vpc_flow',
        'Azure NSG Flow Logs': 'azure_nsg',
        'GCP VPC Firewall': 'gcp_vpc',
        'MySQL Error': 'mysql_error',
        'MySQL Query': 'mysql_query',
        'MySQL Slow Query': 'mysql_slow',
        'PostgreSQL Error': 'postgres_error',
        'PostgreSQL Auth': 'postgres_auth',
        'PostgreSQL Statement': 'postgres_statement',
        'Oracle Alert': 'oracle_alert',
        'Oracle Listener': 'oracle_listener',
        'Oracle Audit': 'oracle_audit',
        'SQL Server Error': 'sqlserver_error',
        'SQL Server Audit': 'sqlserver_audit',
        'SQL Server Transaction': 'sqlserver_transaction',
        'MongoDB Server': 'mongodb_server',
        'MongoDB Audit': 'mongodb_audit',
        'Linux SSHD Failed': 'ssh_auth',
        'Linux SSHD Accepted': 'ssh_auth',
        'Linux Syslog': 'syslog',
        'Linux Systemd': 'systemd',
        'Linux Kernel': 'kernel',
        'Linux Audit': 'audit',
        'Windows Event': 'windows_event',
        'Windows Security': 'windows_security',
        'Windows Application': 'windows_application',
        'Windows System': 'windows_system',
        'VSFTPD': 'vsftpd',
        'ProFTPD': 'proftpd',
        'FileZilla FTP': 'vsftpd',
        'IIS FTP': 'iis_ftp',
        'xferlog': 'vsftpd',
        'DHCP': 'dhcp',
        'DNS': 'dns',
        'Proxy': 'proxy',
        'Cloudflare': 'cloudflare',
        'AWS CloudTrail': 'cloudtrail',
        'AWS GuardDuty': 'aws_guardduty',
        'Azure Activity': 'azure_activity',
        'GCP Audit': 'gcp_audit',
        'Kubernetes': 'kubernetes',
        'Docker': 'docker',
        'Elasticsearch': 'elasticsearch',
        'Redis': 'redis',
        'RabbitMQ': 'rabbitmq',
        'Kafka': 'kafka',
        'Zookeeper': 'zookeeper',
        'Squid': 'squid',
        'Suricata': 'suricata',
        'Zeek': 'zeek',
        'Ossec': 'ossec',
        'Fail2ban': 'fail2ban',
        'Auth0': 'auth0',
    }
    
    return mapping.get(detected_type, 'raw')


def generate_stats(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate statistics from parsed entries"""
    if not entries:
        return {
            'total': 0,
            'parsed': 0,
            'failed': 0,
        }
    
    by_severity: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    by_outcome: Dict[str, int] = {}
    top_sources: List[Dict[str, Any]] = []
    top_users: List[Dict[str, Any]] = []
    timeline_counts: Dict[str, int] = {}
    
    ip_counts: Dict[str, int] = {}
    user_counts: Dict[str, int] = {}
    
    for entry in entries:
        severity = entry.get('severity', 'unknown')
        by_severity[severity] = by_severity.get(severity, 0) + 1
        
        log_type = entry.get('logType', 'unknown')
        by_type[log_type] = by_type.get(log_type, 0) + 1
        
        outcome = entry.get('outcome', 'unknown')
        by_outcome[outcome] = by_outcome.get(outcome, 0) + 1
        
        # Extract timestamp for timeline
        timestamp = entry.get('timestamp', '')
        if timestamp:
            # Group by hour: minute
            time_key = timestamp[:16] if len(timestamp) >= 16 else timestamp
            timeline_counts[time_key] = timeline_counts.get(time_key, 0) + 1
        
        source = entry.get('source', {})
        if source.get('ip'):
            ip = source['ip']
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        user = entry.get('user', {})
        if user.get('name'):
            username = user['name']
            user_counts[username] = user_counts.get(username, 0) + 1
    
    top_sources = [{'ip': ip, 'count': count} for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]]
    top_users = [{'user': user, 'count': count} for user, count in sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]]
    
    # Sort timeline by time
    timeline = [{'time': time, 'count': count} for time, count in sorted(timeline_counts.items())]
    
    return {
        'total': len(entries),
        'parsed': len(entries),
        'failed': 0,
        'bySeverity': by_severity,
        'byType': by_type,
        'byOutcome': by_outcome,
        'topSources': top_sources,
        'topUsers': top_users,
        'timeline': timeline,
    }


all_parsers = {
    'apache': parse_line,
    'nginx': parse_line,
    'ssh_auth': parse_line,
    'iptables': parse_line,
    'syslog': parse_line,
    'systemd': parse_line,
    'mysql_error': parse_line,
    'postgres_error': parse_line,
    'windows_event': parse_line,
    'raw': parse_line,
}
