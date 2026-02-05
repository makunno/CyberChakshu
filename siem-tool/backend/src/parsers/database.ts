import { Parser, ParsedLogEntry } from '../types';
import { generateId, parseTimestamp, parseSeverity, createBaseEntry } from '../utils/helpers';

export const mysqlErrorParser: Parser = {
  name: 'MySQL Error Log',
  logType: 'mysql_error',
  detect: (line: string) => /^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+\d+\s+\[(?:ERROR|Warning|Note)\]\s+\[MY-\d+\]/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(/^(\S+Z)\s+(\d+)\s+\[(ERROR|Warning|Note)\]\s+\[MY-(\d+)\]\s+\[(\w+)\]\s+(.*)/);
    if (!match) return null;

    const [, timestamp, threadId, level, errorCode, component, message] = match;
    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'mysql_error',
      severity: parseSeverity(level),
      source: { service: 'mysql', pid: parseInt(threadId) },
      message,
      rawLine: line,
      fields: {
        thread_id: parseInt(threadId),
        error_code: errorCode,
        component,
        error_level: level,
      },
      tags: ['database', 'mysql'],
    };
  },
};

export const mysqlSlowParser: Parser = {
  name: 'MySQL Slow Query Log',
  logType: 'mysql_slow',
  detect: (line: string) => /^#\s+Time:\s+\S+Z/.test(line) || /^#\s+User@Host:/.test(line) || /^#\s+Query_time:/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    if (line.startsWith('# Time:')) {
      const match = line.match(/# Time:\s+(\S+Z)/);
      return {
        id: generateId(),
        timestamp: parseTimestamp(match?.[1] || ''),
        logType: 'mysql_slow',
        severity: 'warning',
        source: { service: 'mysql' },
        message: 'Slow query detected',
        rawLine: line,
        fields: {},
        tags: ['database', 'mysql', 'slow_query', 'performance'],
      };
    }

    if (line.startsWith('# User@Host:')) {
      const match = line.match(/# User@Host:\s+(\w+)\[(\w+)\]\s+@\s+(\S+)\s+\[\]\s+Id:\s+(\d+)/);
      if (match) {
        return {
          id: generateId(),
          timestamp: parseTimestamp(''),
          logType: 'mysql_slow',
          severity: 'info',
          source: { service: 'mysql', pid: parseInt(match[4]) },
          message: `User ${match[2]} executed slow query`,
          rawLine: line,
          fields: {
            user: match[1],
            account: match[2],
            host: match[3],
            thread_id: parseInt(match[4]),
          },
          tags: ['database', 'mysql', 'slow_query'],
        };
      }
    }

    if (line.startsWith('# Query_time:')) {
      const match = line.match(/# Query_time:\s+([\d.]+)\s+Lock_time:\s+([\d.]+)\s+Rows_sent:\s+(\d+)\s+Rows_examined:\s+(\d+)/);
      if (match) {
        return {
          id: generateId(),
          timestamp: parseTimestamp(''),
          logType: 'mysql_slow',
          severity: 'warning',
          source: { service: 'mysql' },
          message: `Slow query: ${match[1]}s duration`,
          rawLine: line,
          fields: {
            query_time: parseFloat(match[1]),
            lock_time: parseFloat(match[2]),
            rows_sent: parseInt(match[3]),
            rows_examined: parseInt(match[4]),
          },
          tags: ['database', 'mysql', 'slow_query', 'performance'],
        };
      }
    }

    if (!line.startsWith('#') && line.trim().length > 0) {
      return {
        id: generateId(),
        timestamp: parseTimestamp(''),
        logType: 'mysql_slow',
        severity: 'warning',
        source: { service: 'mysql' },
        message: line,
        rawLine: line,
        fields: { sql_statement: line },
        tags: ['database', 'mysql', 'slow_query', 'performance'],
      };
    }

    return null;
  },
};

export const postgresErrorParser: Parser = {
  name: 'PostgreSQL Error Log',
  logType: 'postgres_error',
  detect: (line: string) => /^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+\[\d+\]\s+\S+\s+\S+\s+(?:LOG|ERROR|FATAL|DETAIL):/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(/^(\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s+\[(\d+)\]\s+(\S+)\s+(\S+)\s+(LOG|ERROR|FATAL|DETAIL):\s+(.*)$/);
    if (!match) return null;

    const [, timestamp, pid, host, db, level, message] = match;
    const normalizedLevel = level === 'DETAIL' ? 'ERROR' : level;

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'postgres_error',
      severity: parseSeverity(normalizedLevel),
      source: { service: 'postgresql', pid: parseInt(pid), host, database: db },
      message,
      rawLine: line,
      fields: {
        pid: parseInt(pid),
        host,
        database: db,
        level,
      },
      tags: ['database', 'postgresql'],
    };
  },
};

export const oracleAlertParser: Parser = {
  name: 'Oracle Alert Log',
  logType: 'oracle_alert',
  detect: (line: string) => /^ORA-\d+:/.test(line) || /^[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const oraMatch = line.match(/^ORA-(\d+):\s+(.*)$/);
    if (oraMatch) {
      return {
        id: generateId(),
        timestamp: null,
        logType: 'oracle_alert',
        severity: 'error',
        source: { service: 'oracle' },
        message: oraMatch[2],
        rawLine: line,
        fields: { error_code: oraMatch[1], error_message: oraMatch[2] },
        tags: ['database', 'oracle', 'alert'],
      };
    }

    const dateMatch = line.match(/^([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})/);
    if (dateMatch) {
      return {
        id: generateId(),
        timestamp: null,
        logType: 'oracle_alert',
        severity: 'info',
        source: { service: 'oracle' },
        message: line,
        rawLine: line,
        fields: { raw_message: line },
        tags: ['database', 'oracle', 'alert'],
      };
    }

    return null;
  },
};

export const oracleListenerParser: Parser = {
  name: 'Oracle Listener Log',
  logType: 'oracle_listener',
  detect: (line: string) => /^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+\*\s+\S+\s+\*\s+\S+\s+\*\s+\d+/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(/^(\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s+\*\s+(\S+)\s+\*\s+(\S+)\s+\*\s+(\d+)/);
    if (!match) return null;

    const [, timestamp, action, service, status] = match;
    const hostMatch = line.match(/HOST=(\d+\.\d+\.\d+\.\d+)/);
    const portMatch = line.match(/PORT=(\d+)/);

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'oracle_listener',
      severity: action === 'error' ? 'error' : 'info',
      source: { service: 'oracle_listener', ip: hostMatch?.[1], port: portMatch ? parseInt(portMatch[1]) : undefined },
      message: `${action} for ${service}`,
      rawLine: line,
      fields: { action, service_name: service, status: parseInt(status), host: hostMatch?.[1], port: portMatch?.[1] },
      tags: ['database', 'oracle', 'listener', 'network'],
    };
  },
};

export const oracleAuditParser: Parser = {
  name: 'Oracle Audit Log',
  logType: 'oracle_audit',
  detect: (line: string) => /^Audit trail:/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(/ACTION:\s*'(\w+)'.*DATABASE USER:\s*'(\w+)'.*CLIENT USER:\s*'(\w+)'.*STATUS:\s*(\d+).*TIMESTAMP:\s*(\S+)/);
    if (!match) return null;

    const [, action, dbUser, clientUser, status, timestamp] = match;
    const severity = status !== '0' ? 'error' : 'info';

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'oracle_audit',
      severity,
      source: { service: 'oracle' },
      user: { name: dbUser },
      action,
      outcome: status === '0' ? 'success' : 'failed',
      message: `${action} by ${dbUser}`,
      rawLine: line,
      fields: { action, db_user: dbUser, client_user: clientUser, status: parseInt(status) },
      tags: ['database', 'oracle', 'audit'],
    };
  },
};

export const sqlserverErrorParser: Parser = {
  name: 'SQL Server Error Log',
  logType: 'sqlserver_error',
  detect: (line: string) => /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\S+\s+\S+/.test(line) || /Error:\s*\d+,/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const errorMatch = line.match(/Error:\s*(\d+),\s*Severity:\s*(\d+),\s*State:\s*(\d+)/);
    if (errorMatch) {
      const clientMatch = line.match(/\[CLIENT:\s*([^\]]+)\]/);
      const reasonMatch = line.match(/Reason:\s*(.+?)(?:\s*\[CLIENT|$)/);
      const severityNum = parseInt(errorMatch[2]);
      let severityLevel: ParsedLogEntry['severity'] = 'info';
      if (severityNum >= 20) severityLevel = 'critical';
      else if (severityNum >= 16) severityLevel = 'error';
      else if (severityNum >= 11) severityLevel = 'warning';

      return {
        id: generateId(),
        timestamp: parseTimestamp(line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/)?.[1]?.replace(' ', 'T') + 'Z'),
        logType: 'sqlserver_error',
        severity: severityLevel,
        source: { service: 'sqlserver' },
        message: `Error ${errorMatch[1]}: ${reasonMatch?.[1] || ''}`,
        rawLine: line,
        fields: {
          error_code: parseInt(errorMatch[1]),
          severity: severityNum,
          state: parseInt(errorMatch[3]),
          client: clientMatch?.[1],
          reason: reasonMatch?.[1],
        },
        tags: ['database', 'sqlserver', 'error'],
      };
    }

    const match = line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+(\S+)\s+(\S+)\s+(.*)/);
    if (match) {
      return {
        id: generateId(),
        timestamp: parseTimestamp(match[1].replace(' ', 'T') + 'Z'),
        logType: 'sqlserver_error',
        severity: 'info',
        source: { service: 'sqlserver' },
        message: match[4],
        rawLine: line,
        fields: { component: match[2], spid: match[3], message: match[4] },
        tags: ['database', 'sqlserver'],
      };
    }

    return null;
  },
};

export const sqlserverAuditParser: Parser = {
  name: 'SQL Server Audit Log',
  logType: 'sqlserver_audit',
  detect: (line: string) => /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\|[\w]+\|[\w-]+\|[\w-]+\|[\w]+\|[\d.]+\|\d+$/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const parts = line.split('|');
    if (parts.length >= 7) {
      const [, timestamp, action, database, user, outcome, ip, duration] = parts;
      return {
        id: generateId(),
        timestamp: parseTimestamp(timestamp.replace(' ', 'T') + 'Z'),
        logType: 'sqlserver_audit',
        severity: outcome === 'SUCCEEDED' ? 'info' : 'error',
        source: { service: 'sqlserver', ip },
        user: { name: user },
        action,
        outcome: outcome.toLowerCase(),
        message: `${action} on ${database} by ${user}`,
        rawLine: line,
        fields: { action, database, user, outcome, ip, duration_ms: parseInt(duration) },
        tags: ['database', 'sqlserver', 'audit'],
      };
    }
    return null;
  },
};

export const mongodbServerParser: Parser = {
  name: 'MongoDB Server Log',
  logType: 'mongodb_server',
  detect: (line: string) => /^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+[IWDEC]\s+\S+\s+\[.*\]\s+.*/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(/^(\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s+([IWDEC])\s+(\S+)\s+\[(\w+)\]\s+(.*)/);
    if (!match) return null;

    const [, timestamp, severity, component, context, message] = match;
    const connMatch = message.match(/\[conn(\d+)\]/);
    const ipMatch = message.match(/from\s+(\d+\.\d+\.\d+\.\d+):\d+/);

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'mongodb_server',
      severity: parseSeverity(severity),
      source: { service: 'mongodb', ip: ipMatch?.[1], port: undefined },
      message,
      rawLine: line,
      fields: {
        component,
        context,
        connection_id: connMatch ? parseInt(connMatch[1]) : undefined,
        ip: ipMatch?.[1],
      },
      tags: ['database', 'mongodb'],
    };
  },
};

export const databaseParsers: Parser[] = [
  mysqlErrorParser,
  mysqlSlowParser,
  postgresErrorParser,
  oracleAlertParser,
  oracleListenerParser,
  oracleAuditParser,
  sqlserverErrorParser,
  sqlserverAuditParser,
  mongodbServerParser,
];
