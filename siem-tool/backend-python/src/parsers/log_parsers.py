"""
LogParsers - ISEA-style static parser methods returning simple structures
Migrated from siem-gui/webview-gui/parsers/log_parsers.py
"""

import re
import json
from typing import Optional, Dict, Any
from datetime import datetime


class LogParsers:
    
    @staticmethod
    def apache(line: str) -> Optional[Dict[str, Any]]:
        # Standard Apache/Nginx format
        m = re.match(r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)', line)
        if not m:
            # Flask access log format: 10.0.5.71 - - [2026-01-15T16:14:37.848Z] "POST /api/search HTTP/1.1" 201 -
            m = re.match(r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\S+)', line)
        if not m:
            return None
        ip, timestamp, request, status, bytes_sent = m.groups()
        try:
            status_code = int(status)
        except:
            status_code = 0
        try:
            bytes_val = int(bytes_sent) if bytes_sent != '-' else 0
        except:
            bytes_val = 0
        return {
            'ip': ip,
            'timestamp': timestamp,
            'request': request,
            'status': status_code,
            'bytes': bytes_val
        }
    
    @staticmethod
    def nginx(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'(\S+) - (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+)', line)
        if not m:
            return None
        ip, user, timestamp, request, status, bytes_sent = m.groups()
        return {
            'ip': ip,
            'user': user if user != '-' else None,
            'timestamp': timestamp,
            'request': request,
            'status': int(status),
            'bytes': int(bytes_sent)
        }
    
    @staticmethod
    def sshd_failed(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(
            r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+'
            r'Failed\s+(?P<method>\w+)\s+for\s+(invalid\s+user\s+)?(?P<user>\S+)\s+'
            r'from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)',
            line
        )
        if not m:
            return None
        return m.groupdict()
    
    @staticmethod
    def sshd_accepted(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(
            r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+'
            r'Accepted\s+(?P<method>\w+)\s+for\s+(?P<user>\S+)\s+'
            r'from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)',
            line
        )
        if not m:
            return None
        return m.groupdict()
    
    @staticmethod
    def postfix(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(
            r'^[A-Z][a-z]{2}\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+postfix\/(smtpd|smtp|cleanup|qmgr)\[(\d+)\]:\s+(.+)$',
            line
        )
        if not m:
            return None
        date, time, host, service, pid, message = m.groups()
        return {
            'timestamp': f'{date} {time}',
            'host': host,
            'service': f'postfix/{service}',
            'pid': int(pid),
            'message': message
        }
    
    @staticmethod
    def iptables(line: str) -> Optional[Dict[str, Any]]:
        # Standard: Jan 15 16:15:15 mail-01 kernel: IPTABLES DROP: ...
        # Test format: Jan 15 16:15:15 mail-01 kernel: [439.623500] iptables ACCEPT: ...
        m = re.match(
            r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:\s*(?:\[[\d.]+\])?\s*iptables\s+(DROP|ACCEPT):\s+IN=(\S*)\s+OUT=(\S*)\s+.*SRC=(\d+\.\d+\.\d+\.\d+)\s+DST=(\d+\.\d+\.\d+\.\d+).*PROTO=(TCP|UDP|ICMP).*',
            line, re.IGNORECASE
        )
        if not m:
            return None
        timestamp, host, action, in_iface, out_iface, src_ip, dst_ip, proto = m.groups()
        return {
            'timestamp': timestamp,
            'host': host,
            'action': action.lower(),
            'in_iface': in_iface if in_iface else '-',
            'out_iface': out_iface if out_iface else '-',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': proto
        }
    
    @staticmethod
    def mysql_error(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s+(\d+)\s+\[(ERROR|Warning|Note)\]\s+\[MY-(\d+)\]\s+\[(\w+)\]\s+(.*)', line)
        if not m:
            return None
        timestamp, thread_id, level, error_code, component, message = m.groups()
        return {
            'timestamp': timestamp,
            'thread_id': int(thread_id),
            'error_level': level.lower(),
            'error_code': error_code,
            'component': component,
            'error_message': message
        }
    
    @staticmethod
    def mysql_query(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s+(\d+)\s+(Query|Connect|Execute)\s+(.*)', line)
        if not m:
            return None
        timestamp, thread_id, query_type, sql_statement = m.groups()
        return {
            'timestamp': timestamp,
            'thread_id': int(thread_id),
            'query_type': query_type,
            'sql_statement': sql_statement
        }
    
    @staticmethod
    def mysql_slow(block: str) -> Optional[Dict[str, Any]]:
        time_match = re.search(r'# Time: (\S+)', block)
        user_match = re.search(r'# User@Host: (\w+)\[\w+\] @ (\S+) \[(.*?)\]', block)
        query_match = re.search(r'# Query_time: ([\d.]+).*Rows_examined: (\d+)', block)
        sql_match = re.search(r'\n(SELECT.*);', block)
        
        if not (time_match and user_match and query_match and sql_match):
            return None
        
        return {
            'timestamp': time_match.group(1),
            'user': user_match.group(1),
            'host': user_match.group(2),
            'ip': user_match.group(3),
            'query_time': float(query_match.group(1)),
            'rows_examined': int(query_match.group(2)),
            'sql_statement': sql_match.group(1).strip()
        }
    
    @staticmethod
    def postgres_error(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'^(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s+\[(\d+)\]\s+(\S+)\s+(\S+)\s+(LOG|ERROR|FATAL):\s+(.*)', line)
        if not m:
            return None
        timestamp, pid, host, process, level, message = m.groups()
        return {
            'timestamp': timestamp,
            'pid': int(pid),
            'host': host,
            'process': process,
            'level': level.lower(),
            'message': message
        }
    
    @staticmethod
    def postgres_auth(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'^(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s+\[(\d+)\]\s+(\S+)\s+(\S+)\s+LOG:\s+connection received:.*host=(\d+\.\d+\.\d+\.\d+)\s+port=(\d+)', line)
        if not m:
            return None
        timestamp, pid, host, process, src_ip, src_port = m.groups()
        return {
            'timestamp': timestamp,
            'host': host,
            'process': process,
            'pid': int(pid),
            'ip': src_ip,
            'port': int(src_port)
        }
    
    @staticmethod
    def syslog(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w\-\/]+)\[(\d+)\]:\s+(.*)', line)
        if not m:
            return None
        timestamp, host, process, pid, message = m.groups()
        return {
            'timestamp': timestamp,
            'host': host,
            'process': process,
            'pid': int(pid),
            'message': message
        }
    
    @staticmethod
    def systemd(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+systemd\[(\d+)\]:\s+(.*)', line)
        if not m:
            return None
        timestamp, host, pid, message = m.groups()
        return {
            'timestamp': timestamp,
            'host': host,
            'pid': int(pid),
            'message': message
        }
    
    @staticmethod
    def iis(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(GET|POST|PUT|DELETE)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.*)', line)
        if not m:
            return None
        date, time, server_ip, method, path, query, status, bytes_sent, referer, user_agent, message = m.groups()
        return {
            'date': date,
            'time': time,
            'server_ip': server_ip,
            'method': method,
            'path': path,
            'query': query,
            'status': int(status),
            'bytes': int(bytes_sent),
            'referer': referer,
            'user_agent': user_agent
        }
    
    @staticmethod
    def windows_event(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*,?\s*(INFO|WARNING|ERROR|DEBUG)\s*,?\s*(\S+)\s*,?\s*(\d+)\s*,?\s*(.*)', line)
        if not m:
            return None
        timestamp, level, source, event_id, message = m.groups()
        return {
            'timestamp': timestamp,
            'level': level.lower(),
            'source': source,
            'event_id': int(event_id),
            'message': message
        }
    
    @staticmethod
    def windows_security(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(INFO|WARNING|ERROR)\s+Security\s+(\d+)\s+(?:User:\s*(\S+))?\s*(.*)?', line)
        if not m:
            return None
        timestamp, level, event_id, user, message = m.groups()
        return {
            'timestamp': timestamp,
            'level': level.lower(),
            'event_id': int(event_id),
            'user': user,
            'message': message or ''
        }
    
    @staticmethod
    def ufw(line: str) -> Optional[Dict[str, Any]]:
        # Test format: Jan 15 16:14:35 firewall-01 kernel: [41232.961766] [UFW ALLOW] IN=eth0 OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=109.191.241.53 DST=10.0.1.7
        m = re.match(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:\s*\[\d+\.\d+\]\s*\[UFW\s+(ALLOW|BLOCK)\]\s+IN=(\S*)\s+OUT=(\S*)\s+.*SRC=(?:\d{1,3}\.){3}\d{1,3}\s+DST=(?:\d{1,3}\.){3}\d{1,3}', line, re.IGNORECASE)
        if not m:
            return None
        timestamp, host, action, iface = m.groups()
        return {
            'timestamp': timestamp,
            'host': host,
            'action': action.lower(),
            'interface': iface
        }
    
    @staticmethod
    def palo_alto(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'^(\d{4}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(allow|deny|drop)\s+(tcp|udp|icmp)\s+(\S+)\s+(\S+)\s+rule=(\S+).*$', line)
        if not m:
            return None
        date, time, action, proto, src_ip, dst_ip, rule = m.groups()
        return {
            'timestamp': f'{date} {time}',
            'action': action,
            'protocol': proto,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'rule': rule
        }
    
    @staticmethod
    def fortigate(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'^date=(\d{4}-\d{2}-\d{2})\s+time=(\d{2}:\d{2}:\d{2})\s+action=(allow|deny)\s+srcip=(?:\d{1,3}\.){3}\d{1,3}\s+dstip=(?:\d{1,3}\.){3}\d{1,3}.*$', line)
        if not m:
            return None
        date, time, action = m.groups()
        return {
            'timestamp': f'{date} {time}',
            'action': action
        }
    
    @staticmethod
    def cisco_asa(line: str) -> Optional[Dict[str, Any]]:
        m = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+%ASA-\d-\d+:\s+access-list\s+\S+\s+(denied|permitted)\s+(tcp|udp|icmp)\s+\S+\/(?:\d{1,3}\.){3}\d{1,3}\s+to\s+\S+\/(?:\d{1,3}\.){3}\d{1,3}.*$').match(line)
        if not m:
            return None
        action, proto = m.groups()
        return {
            'action': action,
            'protocol': proto
        }
    
    @staticmethod
    def vsftpd(line: str) -> Optional[Dict[str, Any]]:
        m = re.match(r'^(\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+\[pid\s+(\d+)\](?:\s+\[\s*\])?\s*(.*)', line)
        if not m:
            return None
        timestamp, host, pid, message = m.groups()
        return {
            'timestamp': timestamp,
            'host': host,
            'pid': int(pid),
            'message': message
        }
    
    @staticmethod
    def django(line: str) -> Optional[Dict[str, Any]]:
        # Format: [2026-01-15T16:14:40.793Z] INFO [django.request] "GET /static/css/style.css" 200
        # Format: [2026-01-15T16:14:42.793Z] INFO [myapp.views] Permission denied for user
        # Format: [2026-01-15T16:15:05.793Z] DEBUG [django.db.backends] (0.163) SELECT * FROM users WHERE id = 1
        
        # Request log format
        m = re.match(r'\[([^\]]+)\] (\w+)\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)"\s+(\d+)', line)
        if m:
            timestamp, level, module, method, path, status = m.groups()
            return {
                'timestamp': timestamp,
                'level': level.lower(),
                'module': module,
                'method': method,
                'path': path,
                'status': int(status),
            }
        
        # Database query format
        m = re.match(r'\[([^\]]+)\]\s+(\w+)\s+\[([^\]]+)\]\s+\(([\d.]+)\)\s+(.+)', line)
        if m:
            timestamp, level, module, duration, query = m.groups()
            return {
                'timestamp': timestamp,
                'level': level.lower(),
                'module': module,
                'duration_sec': float(duration),
                'query': query.strip(),
            }
        
        # General log format
        m = re.match(r'\[([^\]]+)\]\s+(\w+)\s+\[([^\]]+)\]\s+(.+)', line)
        if m:
            timestamp, level, module, message = m.groups()
            return {
                'timestamp': timestamp,
                'level': level.lower(),
                'module': module,
                'message': message,
            }
        
        return None
    
    @staticmethod
    def json_log(line: str) -> Optional[Dict[str, Any]]:
        try:
            return json.loads(line)
        except:
            return None
    
    @staticmethod
    def json_ftp(line: str) -> Optional[Dict[str, Any]]:
        """Parse JSON FTP log format [[{timestamp:...}]]"""
        try:
            data = json.loads(line)
            if isinstance(data, list) and len(data) > 0 and isinstance(data[0], list):
                # Extract first entry from nested list format [[{...}]]
                entry = data[0][0] if data[0] else None
                if entry and isinstance(entry, dict):
                    return {
                        'timestamp': entry.get('timestamp', ''),
                        'user': entry.get('user', ''),
                        'ip': entry.get('ip', ''),
                        'action': entry.get('action', ''),
                        'file': entry.get('file', '')
                    }
            return None
        except:
            return None
    
    @staticmethod
    def parse_by_type(line: str, log_type: str) -> Optional[Dict[str, Any]]:
        """Parse a line based on its detected type"""
        parsers = {
            'Apache': LogParsers.apache,
            'NGINX': LogParsers.nginx,
            'Django': LogParsers.django,
            'Flask': LogParsers.django,
            'Node.js': LogParsers.django,
            'Express.js': LogParsers.django,
            'FastAPI': LogParsers.django,
            'Gunicorn': LogParsers.django,
            'Linux SSHD Failed': LogParsers.sshd_failed,
            'Linux SSHD Accepted': LogParsers.sshd_accepted,
            'Postfix': LogParsers.postfix,
            'Sendmail': LogParsers.postfix,
            'Exim': LogParsers.postfix,
            'Dovecot': LogParsers.postfix,
            'iptables': LogParsers.iptables,
            'UFW': LogParsers.iptables,
            'nftables': LogParsers.iptables,
            'firewalld': LogParsers.iptables,
            'Palo Alto Firewall': LogParsers.palo_alto,
            'FortiGate': LogParsers.fortigate,
            'Cisco ASA': LogParsers.cisco_asa,
            'VSFTPD': LogParsers.vsftpd,
            'ProFTPD': LogParsers.vsftpd,
            'MySQL Error': LogParsers.mysql_error,
            'MySQL Query': LogParsers.mysql_query,
            'PostgreSQL Error': LogParsers.postgres_error,
            'PostgreSQL Auth': LogParsers.postgres_auth,
            'PostgreSQL Statement': LogParsers.postgres_auth,
            'Oracle Alert': LogParsers.postgres_error,
            'SQL Server Error': LogParsers.postgres_error,
            'Linux Syslog': LogParsers.syslog,
            'Linux Systemd': LogParsers.systemd,
            'Linux Kernel': LogParsers.syslog,
            'Linux Audit': LogParsers.syslog,
            'IIS': LogParsers.iis,
            'Windows Event': LogParsers.windows_event,
            'Windows Security CSV': LogParsers.windows_security_csv,
            'Windows Application CSV': LogParsers.windows_application_csv,
            'JSON FTP Logs': LogParsers.json_ftp,
            'AWS CloudTrail': LogParsers.aws_cloudtrail,
            'AWS GuardDuty': LogParsers.aws_cloudtrail,
            'Azure Activity': LogParsers.aws_cloudtrail,
            'GCP Audit': LogParsers.aws_cloudtrail,
            'Kubernetes': LogParsers.kubernetes,
            'Docker': LogParsers.docker,
            'Squid': LogParsers.squid,
            'Suricata': LogParsers.suricata,
            'Redis': LogParsers.redis,
            'Elasticsearch': LogParsers.elasticsearch,
        }
        
        parser = parsers.get(log_type)
        if parser:
            return parser(line)
        
        # Try matching by partial type name
        for type_name, parser_func in parsers.items():
            if type_name.lower() in log_type.lower():
                return parser_func(line)
        
        return None
    
    @staticmethod
    def windows_security_csv(line: str) -> Optional[Dict[str, Any]]:
        # Windows Security CSV format: TimeCreated,EventID,LevelDisplayName,LogName,MachineName,Message,...
        # Skip header lines
        if line.startswith('TimeCreated,') or line.startswith('EventID,'):
            return None
        if not line or ',' not in line:
            return None
        parts = line.split(',')
        if len(parts) < 8:
            return None
        try:
            # Check if first part is a timestamp
            first = parts[0].strip()
            if not re.match(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', first):
                return None
            return {
                'timestamp': first,
                'event_id': int(parts[1]) if parts[1].isdigit() else 0,
                'level': parts[2].strip().lower() if len(parts) > 2 else 'info',
                'log_name': parts[3].strip() if len(parts) > 3 else '',
                'machine_name': parts[4].strip() if len(parts) > 4 else '',
                'message': parts[5].strip() if len(parts) > 5 else '',
                'account_name': parts[6].strip() if len(parts) > 6 else '',
                'logon_type': parts[7].strip() if len(parts) > 7 else '',
                'ip_address': parts[8].strip() if len(parts) > 8 else '',
            }
        except:
            return None
    
    @staticmethod
    def windows_application_csv(line: str) -> Optional[Dict[str, Any]]:
        # Windows Application CSV format
        # Skip header lines
        if line.startswith('TimeCreated,') or line.startswith('EventID,') or line.startswith('Level,'):
            return None
        if not line or ',' not in line:
            return None
        parts = line.split(',')
        if len(parts) < 6:
            return None
        try:
            first = parts[0].strip()
            if not re.match(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', first):
                return None
            return {
                'timestamp': first,
                'event_id': int(parts[1]) if parts[1].isdigit() else 0,
                'level': parts[2].strip().lower() if len(parts) > 2 else 'info',
                'log_name': parts[3].strip() if len(parts) > 3 else '',
                'machine_name': parts[4].strip() if len(parts) > 4 else '',
                'provider_name': parts[5].strip() if len(parts) > 5 else '',
                'message': parts[6].strip() if len(parts) > 6 else '',
            }
        except:
            return None
    
    @staticmethod
    def postgres_statement(line: str) -> Optional[Dict[str, Any]]:
        # PostgreSQL statement format: 2026-01-15T16:14:34.022Z [9590] host LOG: duration: X ms statement: ...
        m = re.match(r'^(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s+\[(\d+)\]\s+(\S+)\s+(\S+)\s+LOG:\s+duration:\s+([\d.]+)\s+ms\s+statement:\s+(.*)', line)
        if not m:
            return None
        timestamp, pid, host, process, duration, statement = m.groups()
        return {
            'timestamp': timestamp,
            'pid': int(pid),
            'host': host,
            'process': process,
            'duration_ms': float(duration),
            'statement': statement
        }
    
    @staticmethod
    def aws_cloudtrail(line: str) -> Optional[Dict[str, Any]]:
        # AWS CloudTrail JSON format
        try:
            if line.strip().startswith('{'):
                data = json.loads(line)
                return {
                    'timestamp': data.get('eventTime', ''),
                    'event_name': data.get('eventName', ''),
                    'event_source': data.get('eventSource', ''),
                    'user_identity': data.get('userIdentity', {}).get('arn', ''),
                    'source_ip': data.get('sourceIPAddress', ''),
                    'user_agent': data.get('userAgent', ''),
                    'request_params': data.get('requestParameters', {}),
                    'response_elements': data.get('responseElements', {}),
                }
        except:
            pass
        return None
    
    @staticmethod
    def kubernetes(line: str) -> Optional[Dict[str, Any]]:
        # Kubernetes JSON log format
        try:
            if line.strip().startswith('{'):
                data = json.loads(line)
                return {
                    'timestamp': data.get('time', ''),
                    'stream': data.get('stream', ''),
                    'message': data.get('log', ''),
                    'container': data.get('container', {}).get('name', ''),
                    'pod': data.get('pod', {}).get('name', ''),
                    'namespace': data.get('pod', {}).get('namespace', ''),
                }
        except:
            pass
        return None
    
    @staticmethod
    def docker(line: str) -> Optional[Dict[str, Any]]:
        # Docker JSON log format
        try:
            if line.strip().startswith('{'):
                data = json.loads(line)
                return {
                    'timestamp': data.get('time', ''),
                    'stream': data.get('stream', ''),
                    'message': data.get('log', ''),
                }
        except:
            pass
        return None
    
    @staticmethod
    def squid(line: str) -> Optional[Dict[str, Any]]:
        # Squid format: timestamp duration IP/Status Code/Method/URL/Peer/...
        m = re.match(r'(\d+\.\d+)\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(TCP_|UDP_|CONNECT)\s*(\d+)?\s*(\d+)?\s*(\S+)\s+(.*)', line)
        if m:
            return {
                'timestamp': m.group(1),
                'duration': m.group(2),
                'ip': m.group(3),
                'code': m.group(4),
                'status': m.group(5),
                'method': m.group(6),
                'url': m.group(7),
                'message': m.group(8),
            }
        return None
    
    @staticmethod
    def suricata(line: str) -> Optional[Dict[str, Any]]:
        # Suricata eve.json format
        try:
            if line.strip().startswith('{'):
                data = json.loads(line)
                return {
                    'timestamp': data.get('timestamp', ''),
                    'event_type': data.get('event_type', ''),
                    'src_ip': data.get('src_ip', ''),
                    'dest_ip': data.get('dest_ip', ''),
                    'src_port': data.get('src_port', 0),
                    'dest_port': data.get('dest_port', 0),
                    'proto': data.get('proto', ''),
                    'alert': data.get('alert', {}),
                    'signature': data.get('alert', {}).get('signature', ''),
                }
        except:
            pass
        return None
    
    @staticmethod
    def redis(line: str) -> Optional[Dict[str, Any]]:
        # Redis log format: timestamp level: message
        m = re.match(r'(\d+:)?(\d+\s+\S+\s+\d+)\s+(\d+)\s+(\S+)\s+(.*)', line)
        if m:
            return {
                'timestamp': m.group(2),
                'pid': m.group(3),
                'level': m.group(4),
                'message': m.group(5),
            }
        return None
    
    @staticmethod
    def elasticsearch(line: str) -> Optional[Dict[str, Any]]:
        # Elasticsearch JSON format
        try:
            if line.strip().startswith('{'):
                data = json.loads(line)
                return {
                    'timestamp': data.get('@timestamp', ''),
                    'level': data.get('log.level', ''),
                    'logger': data.get('log.logger', ''),
                    'message': data.get('message', ''),
                    'host': data.get('host', {}).get('name', ''),
                }
        except:
            pass
        return None
