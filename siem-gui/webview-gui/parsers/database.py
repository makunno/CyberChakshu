"""Database Log Parsers - MySQL, PostgreSQL, Oracle, SQL Server, MongoDB"""

import re
from datetime import datetime
from ..base import Parser
from ..types import LogType, LogEntry, Severity


class MySQLErrorParser(Parser):
    """Parser for MySQL Error Log"""

    def __init__(self):
        super().__init__("MySQL Error Log", LogType.MYSQL_ERROR)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+\d+\s+\[ERROR\]\s+\[MY-\d+\]', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(r'(\S+Z)\s+(\d+)\s+\[(ERROR|Warning|Note)\]\s+\[MY-(\d+)\]\s+\[(\w+)\]\s+(.*)', line)
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, thread_id, level, error_code, component, message = match.groups()

        # Parse timestamp
        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).isoformat()
        except:
            pass

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=self._parse_severity(level),
            source={'service': 'mysql', 'pid': int(thread_id)},
            message=message,
            fields={
                'thread_id': int(thread_id),
                'error_code': error_code,
                'component': component,
                'error_level': level,
            },
            tags=['database', 'mysql']
        )

    def _parse_severity(self, level: str) -> Severity:
        level_lower = level.lower()
        if level_lower == 'error':
            return Severity.ERROR
        elif level_lower == 'warning':
            return Severity.WARNING
        elif level_lower == 'note':
            return Severity.INFO
        return Severity.INFO


class MySQLQueryParser(Parser):
    """Parser for MySQL Query Log"""

    def __init__(self):
        super().__init__("MySQL Query Log", LogType.MYSQL_QUERY)

    def detect(self, line: str) -> bool:
        return 'Query' in line and bool(re.search(r'\S+Z\s+\d+\s+Query\s+', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(r'(\S+Z)\s+(\d+)\s+Query\s+(.*);?', line)
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, thread_id, sql_statement = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).isoformat()
        except:
            pass

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=Severity.INFO,
            source={'service': 'mysql', 'pid': int(thread_id)},
            message=sql_statement,
            fields={
                'thread_id': int(thread_id),
                'sql_statement': sql_statement,
            },
            tags=['database', 'mysql', 'query']
        )


class MySQLSlowParser(Parser):
    """Parser for MySQL Slow Query Log"""

    def __init__(self):
        super().__init__("MySQL Slow Query Log", LogType.MYSQL_SLOW)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^#\s+Time:\s+\S+Z', line) or re.search(r'^#\s+User@Host:', line))

    def parse(self, line: str) -> LogEntry:
        if line.startswith('# Time:'):
            match = re.search(r'# Time:\s+(\S+Z)', line)
            if match:
                timestamp = match.group(1)
                timestamp_parsed = None
                try:
                    timestamp_parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).isoformat()
                except:
                    pass

                return LogEntry(
                    line,
                    timestamp=timestamp_parsed,
                    log_type=self.log_type,
                    severity=Severity.WARNING,
                    source={'service': 'mysql'},
                    message='Slow query detected',
                    fields={},
                    tags=['database', 'mysql', 'slow_query', 'performance']
                )

        return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)


class PostgresErrorParser(Parser):
    """Parser for PostgreSQL Error Log"""

    def __init__(self):
        super().__init__("PostgreSQL Error Log", LogType.POSTGRES_ERROR)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}.*\[\d+\].*(?:ERROR|FATAL):', line))

    def parse(self, line: str) -> LogEntry:
        match = re.search(
            r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\w+)\s+\[(\d+)\]\s+(?:\S+@\S+\s+)?(ERROR|FATAL):\s+([0-9A-Z]{5}):\s+(.*)$',
            line
        )
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, pid, level, error_code, message = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(timestamp.strip(), '%Y-%m-%d %H:%M:%S').isoformat()
        except:
            pass

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=self._parse_severity(level),
            source={'service': 'postgresql', 'pid': int(pid)},
            message=message,
            fields={
                'pid': int(pid),
                'error_code': error_code,
                'error_level': level,
            },
            tags=['database', 'postgresql']
        )

    def _parse_severity(self, level: str) -> Severity:
        if level.upper() in ['ERROR', 'FATAL']:
            return Severity.ERROR
        return Severity.WARNING


class PostgresAuthParser(Parser):
    """Parser for PostgreSQL Auth Log"""

    def __init__(self):
        super().__init__("PostgreSQL Auth Log", LogType.POSTGRES_AUTH)

    def detect(self, line: str) -> bool:
        return 'user=' in line and 'database=' in line

    def parse(self, line: str) -> LogEntry:
        match = re.search(r'(\S+)\s+(\S+)\s+\[(\d+)\].*user=(\w+)\s+database=(\w+)', line)
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        date, timezone, pid, user, database = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(f"{date} {timezone}", '%Y-%m-%d %Z').isoformat()
        except:
            pass

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=Severity.INFO,
            source={'service': 'postgresql', 'pid': int(pid)},
            user={'name': user},
            action='authentication',
            outcome='success',
            message=f'User {user} connected to database {database}',
            fields={
                'pid': int(pid),
                'user': user,
                'database': database,
            },
            tags=['database', 'postgresql', 'auth']
        )


class PostgresStatementParser(Parser):
    """Parser for PostgreSQL Statement Log"""

    def __init__(self):
        super().__init__("PostgreSQL Statement Log", LogType.POSTGRES_STATEMENT)

    def detect(self, line: str) -> bool:
        return 'STATEMENT:' in line

    def parse(self, line: str) -> LogEntry:
        match = re.search(r'(\S+)\s+(\S+)\s+\[(\d+)\]\s+STATEMENT:\s+(.*);?', line)
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        date, timezone, pid, statement = match.groups()

        timestamp_parsed = None
        try:
            timestamp_parsed = datetime.strptime(f"{date} {timezone}", '%Y-%m-%d %Z').isoformat()
        except:
            pass

        return LogEntry(
            line,
            timestamp=timestamp_parsed,
            log_type=self.log_type,
            severity=Severity.INFO,
            source={'service': 'postgresql', 'pid': int(pid)},
            message=statement,
            fields={
                'pid': int(pid),
                'sql_statement': statement,
            },
            tags=['database', 'postgresql', 'query']
        )


class OracleAlertParser(Parser):
    """Parser for Oracle Alert Log"""

    def __init__(self):
        super().__init__("Oracle Alert Log", LogType.ORACLE_ALERT)

    def detect(self, line: str) -> bool:
        return bool(re.search(r'^ORA-\d+:', line) or re.search(r'^[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}', line))

    def parse(self, line: str) -> LogEntry:
        # Oracle ORA error
        match = re.search(r'^ORA-(\d+):\s+(.*)$', line)
        if match:
            error_code, message = match.groups()
            return LogEntry(
                line,
                timestamp=None,
                log_type=self.log_type,
                severity=Severity.ERROR,
                source={'service': 'oracle'},
                message=message,
                fields={
                    'error_code': error_code,
                    'error_message': message,
                },
                tags=['database', 'oracle', 'alert']
            )

        return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)


class SQLServerErrorParser(Parser):
    """Parser for SQL Server Error Log"""

    def __init__(self):
        super().__init__("SQL Server Error Log", LogType.SQLSERVER_ERROR)

    def detect(self, line: str) -> bool:
        return 'Server Error:' in line and 'Severity:' in line and 'State:' in line

    def parse(self, line: str) -> LogEntry:
        match = re.search(r'(.*?)\s+Server Error:\s+(\d+),\s+Severity:\s+(\d+),\s+State:\s+(\d+)', line)
        if not match:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

        timestamp, error_code, severity, state = match.groups()
        severity_num = int(severity)

        # Determine severity level
        if severity_num >= 20:
            sev_level = Severity.CRITICAL
        elif severity_num >= 16:
            sev_level = Severity.ERROR
        elif severity_num >= 11:
            sev_level = Severity.WARNING
        else:
            sev_level = Severity.INFO

        return LogEntry(
            line,
            timestamp=None,  # Would need proper timestamp parsing
            log_type=self.log_type,
            severity=sev_level,
            source={'service': 'sqlserver'},
            message=f'Error {error_code} with severity {severity}',
            fields={
                'error_code': int(error_code),
                'severity': severity_num,
                'state': int(state),
            },
            tags=['database', 'sqlserver']
        )


class MongoDBServerParser(Parser):
    """Parser for MongoDB Server Log"""

    def __init__(self):
        super().__init__("MongoDB Server Log", LogType.MONGODB_SERVER)

    def detect(self, line: str) -> bool:
        try:
            import json
            json.loads(line)
            return True
        except:
            return False

    def parse(self, line: str) -> LogEntry:
        try:
            import json
            j = json.loads(line)
            if not (j.get('t') and j.get('s') and j.get('c') and j.get('msg')):
                return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

            # Extract IP and port
            ip = None
            port = None
            if j.get('attr', {}).get('remote'):
                ip_port = j['attr']['remote'].split(':')
                if len(ip_port) == 2:
                    ip, port = ip_port[0], int(ip_port[1])

            return LogEntry(
                line,
                timestamp=j.get('t', {}).get('$date') if isinstance(j.get('t'), dict) else j.get('t'),
                log_type=self.log_type,
                severity=self._parse_mongo_severity(j.get('s', 'I')),
                source={'service': 'mongodb', 'ip': ip, 'port': port},
                message=j.get('msg', ''),
                fields={
                    'component': j.get('c'),
                    'context': j.get('ctx'),
                    **j.get('attr', {}),
                },
                tags=['database', 'mongodb']
            )
        except:
            return LogEntry(line, log_type=self.log_type, severity=Severity.INFO, message=line)

    def _parse_mongo_severity(self, level: str) -> Severity:
        level_map = {
            'F': Severity.CRITICAL,  # Fatal
            'E': Severity.ERROR,     # Error
            'W': Severity.WARNING,   # Warning
            'I': Severity.INFO,      # Info
            'D': Severity.DEBUG,     # Debug
        }
        return level_map.get(level.upper(), Severity.INFO)


# Export all database parsers
PARSERS = [
    MySQLErrorParser(),
    MySQLQueryParser(),
    MySQLSlowParser(),
    PostgresErrorParser(),
    PostgresAuthParser(),
    PostgresStatementParser(),
    OracleAlertParser(),
    SQLServerErrorParser(),
    MongoDBServerParser(),
]