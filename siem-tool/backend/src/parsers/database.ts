// Database Log Parsers - MySQL, PostgreSQL, Oracle, SQL Server, MongoDB
// Based on ~/ISEA/Utsav/LogParser/regexBased.py

import { Parser, ParsedLogEntry } from '../types';
import { generateId, parseTimestamp, parseSeverity, createBaseEntry } from '../utils/helpers';

// ========== MySQL Parsers ==========

export const mysqlErrorParser: Parser = {
  name: 'MySQL Error Log',
  logType: 'mysql_error',
  detect: (line: string) => /\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+\d+\s+\[ERROR\]\s+\[MY-\d+\]/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(/(\S+Z)\s+(\d+)\s+\[(ERROR|Warning|Note)\]\s+\[MY-(\d+)\]\s+\[(\w+)\]\s+(.*)/);
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

export const mysqlQueryParser: Parser = {
  name: 'MySQL Query Log',
  logType: 'mysql_query',
  detect: (line: string) => /\S+Z\s+\d+\s+Query\s+/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(/(\S+Z)\s+(\d+)\s+Query\s+(.*);?/);
    if (!match) return null;

    const [, timestamp, threadId, sqlStatement] = match;
    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'mysql_query',
      severity: 'info',
      source: { service: 'mysql', pid: parseInt(threadId) },
      message: sqlStatement,
      rawLine: line,
      fields: {
        thread_id: parseInt(threadId),
        sql_statement: sqlStatement,
      },
      tags: ['database', 'mysql', 'query'],
    };
  },
};

export const mysqlSlowParser: Parser = {
  name: 'MySQL Slow Query Log',
  logType: 'mysql_slow',
  detect: (line: string) => /^#\s+Time:\s+\S+Z/.test(line) || /^#\s+User@Host:/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    // This parser handles multi-line blocks - for single line detection
    if (line.startsWith('# Time:')) {
      return {
        id: generateId(),
        timestamp: parseTimestamp(line.match(/# Time: (\S+Z)/)?.[1] || ''),
        logType: 'mysql_slow',
        severity: 'warning',
        source: { service: 'mysql' },
        message: 'Slow query detected',
        rawLine: line,
        fields: {},
        tags: ['database', 'mysql', 'slow_query', 'performance'],
      };
    }
    return null;
  },
};

// ========== PostgreSQL Parsers ==========

export const postgresErrorParser: Parser = {
  name: 'PostgreSQL Error Log',
  logType: 'postgres_error',
  detect: (line: string) => /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}.*\[\d+\].*(?:ERROR|FATAL):/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\w+)\s+\[(\d+)\]\s+(?:\S+@\S+\s+)?(ERROR|FATAL):\s+([0-9A-Z]{5}):\s+(.*)$/);
    if (!match) return null;

    const [, timestamp, pid, level, errorCode, message] = match;
    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'postgres_error',
      severity: parseSeverity(level),
      source: { service: 'postgresql', pid: parseInt(pid) },
      message,
      rawLine: line,
      fields: {
        pid: parseInt(pid),
        error_code: errorCode,
        error_level: level,
      },
      tags: ['database', 'postgresql'],
    };
  },
};

export const postgresAuthParser: Parser = {
  name: 'PostgreSQL Auth Log',
  logType: 'postgres_auth',
  detect: (line: string) => /user=\w+\s+database=\w+/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(/(\S+)\s+(\S+)\s+\[(\d+)\].*user=(\w+)\s+database=(\w+)/);
    if (!match) return null;

    const [, date, timezone, pid, user, database] = match;
    return {
      id: generateId(),
      timestamp: parseTimestamp(`${date} ${timezone}`),
      logType: 'postgres_auth',
      severity: 'info',
      source: { service: 'postgresql', pid: parseInt(pid) },
      user: { name: user },
      action: 'authentication',
      outcome: 'success',
      message: `User ${user} connected to database ${database}`,
      rawLine: line,
      fields: {
        pid: parseInt(pid),
        user,
        database,
      },
      tags: ['database', 'postgresql', 'auth'],
    };
  },
};

export const postgresStatementParser: Parser = {
  name: 'PostgreSQL Statement Log',
  logType: 'postgres_statement',
  detect: (line: string) => /STATEMENT:/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(/(\S+)\s+(\S+)\s+\[(\d+)\]\s+STATEMENT:\s+(.*);?/);
    if (!match) return null;

    const [, date, timezone, pid, statement] = match;
    return {
      id: generateId(),
      timestamp: parseTimestamp(`${date} ${timezone}`),
      logType: 'postgres_statement',
      severity: 'info',
      source: { service: 'postgresql', pid: parseInt(pid) },
      message: statement,
      rawLine: line,
      fields: {
        pid: parseInt(pid),
        sql_statement: statement,
      },
      tags: ['database', 'postgresql', 'query'],
    };
  },
};

// ========== Oracle Parsers ==========

export const oracleAlertParser: Parser = {
  name: 'Oracle Alert Log',
  logType: 'oracle_alert',
  detect: (line: string) => /^ORA-\d+:/.test(line) || /^[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    // Oracle ORA error
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
        fields: {
          error_code: oraMatch[1],
          error_message: oraMatch[2],
        },
        tags: ['database', 'oracle', 'alert'],
      };
    }
    return null;
  },
};

export const oracleListenerParser: Parser = {
  name: 'Oracle Listener Log',
  logType: 'oracle_listener',
  detect: (line: string) => /SERVICE_NAME=/.test(line) && /PROTOCOL=/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(/(.*?)\s+\*.*SERVICE_NAME=(\w+).*PROTOCOL=(\w+).*HOST=(\d+\.\d+\.\d+\.\d+).*PORT=(\d+).*\*\s+(\d+)/);
    if (!match) return null;

    const [, timestamp, serviceName, protocol, ip, port, status] = match;
    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'oracle_listener',
      severity: 'info',
      source: { service: 'oracle_listener', ip, port: parseInt(port) },
      message: `Connection to ${serviceName} via ${protocol}`,
      rawLine: line,
      fields: {
        service_name: serviceName,
        protocol,
        ip,
        port: parseInt(port),
        status: parseInt(status),
      },
      tags: ['database', 'oracle', 'listener', 'network'],
    };
  },
};

export const oracleAuditParser: Parser = {
  name: 'Oracle Audit Log',
  logType: 'oracle_audit',
  detect: (line: string) => /^Audit record generated at/.test(line) || /^ACTION\s*:/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    // Handle audit record line
    if (line.includes('ACTION :')) {
      const actionMatch = line.match(/ACTION\s*:\s*(\w+)/);
      if (actionMatch) {
        return {
          id: generateId(),
          timestamp: null,
          logType: 'oracle_audit',
          severity: 'info',
          source: { service: 'oracle' },
          action: actionMatch[1],
          message: line,
          rawLine: line,
          fields: { action: actionMatch[1] },
          tags: ['database', 'oracle', 'audit'],
        };
      }
    }
    return null;
  },
};

// ========== SQL Server Parsers ==========

export const sqlserverErrorParser: Parser = {
  name: 'SQL Server Error Log',
  logType: 'sqlserver_error',
  detect: (line: string) => /Server Error: \d+, Severity: \d+, State: \d+/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(/(.*?)\s+Server Error: (\d+), Severity: (\d+), State: (\d+)/);
    if (!match) return null;

    const [, timestamp, errorCode, severity, state] = match;
    const severityNum = parseInt(severity);
    let severityLevel: ParsedLogEntry['severity'] = 'info';
    if (severityNum >= 20) severityLevel = 'critical';
    else if (severityNum >= 16) severityLevel = 'error';
    else if (severityNum >= 11) severityLevel = 'warning';

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'sqlserver_error',
      severity: severityLevel,
      source: { service: 'sqlserver' },
      message: `Error ${errorCode} with severity ${severity}`,
      rawLine: line,
      fields: {
        error_code: parseInt(errorCode),
        severity: severityNum,
        state: parseInt(state),
      },
      tags: ['database', 'sqlserver'],
    };
  },
};

export const sqlserverAuditParser: Parser = {
  name: 'SQL Server Audit Log',
  logType: 'sqlserver_audit',
  detect: (line: string) => /action_id=\w+.*name=\w+.*database_name=/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(/action_id=(\w+).*name=(\w+).*database_name=(\w+).*statement=(.*)/);
    if (!match) return null;

    const [, actionId, user, database, statement] = match;
    return {
      id: generateId(),
      timestamp: null,
      logType: 'sqlserver_audit',
      severity: 'info',
      source: { service: 'sqlserver' },
      user: { name: user },
      action: actionId,
      message: statement,
      rawLine: line,
      fields: {
        action_id: actionId,
        user,
        database,
        sql_statement: statement,
      },
      tags: ['database', 'sqlserver', 'audit'],
    };
  },
};

export const sqlserverTransactionParser: Parser = {
  name: 'SQL Server Transaction Log',
  logType: 'sqlserver_transaction',
  detect: (line: string) => /\(\d+:\d+:\d+\).*Operation:/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(/\((\d+):(\d+):(\d+)\).*Operation:\s+(.*)/);
    if (!match) return null;

    const [, file, offset, slot, operation] = match;
    return {
      id: generateId(),
      timestamp: null,
      logType: 'sqlserver_transaction',
      severity: 'info',
      source: { service: 'sqlserver' },
      message: operation,
      rawLine: line,
      fields: {
        file: parseInt(file),
        offset: parseInt(offset),
        slot: parseInt(slot),
        operation,
      },
      tags: ['database', 'sqlserver', 'transaction'],
    };
  },
};

// ========== MongoDB Parsers ==========

export const mongodbServerParser: Parser = {
  name: 'MongoDB Server Log',
  logType: 'mongodb_server',
  detect: (line: string) => {
    try {
      const j = JSON.parse(line);
      return j.t && j.s && j.c && j.msg;
    } catch {
      return false;
    }
  },
  parse: (line: string): ParsedLogEntry | null => {
    try {
      const j = JSON.parse(line);
      const [ip, port] = (j.attr?.remote || ':').split(':');
      
      return {
        id: generateId(),
        timestamp: j.t?.$date || null,
        logType: 'mongodb_server',
        severity: parseSeverity(j.s || 'I'),
        source: { service: 'mongodb', ip, port: port ? parseInt(port) : undefined },
        message: j.msg,
        rawLine: line,
        fields: {
          component: j.c,
          context: j.ctx,
          ...j.attr,
        },
        tags: ['database', 'mongodb'],
      };
    } catch {
      return null;
    }
  },
};

export const mongodbAuditParser: Parser = {
  name: 'MongoDB Audit Log',
  logType: 'mongodb_audit',
  detect: (line: string) => {
    try {
      const j = JSON.parse(line);
      return j.atype && j.ts && j.users;
    } catch {
      return false;
    }
  },
  parse: (line: string): ParsedLogEntry | null => {
    try {
      const j = JSON.parse(line);
      const user = j.users?.[0];
      
      return {
        id: generateId(),
        timestamp: j.ts?.$date || null,
        logType: 'mongodb_audit',
        severity: 'info',
        source: { service: 'mongodb' },
        user: user ? { name: user.user, domain: user.db } : undefined,
        action: j.atype,
        message: `${j.atype}: ${j.param?.command || ''}`,
        rawLine: line,
        fields: {
          audit_type: j.atype,
          user: user?.user,
          db: user?.db,
          command: j.param?.command,
        },
        tags: ['database', 'mongodb', 'audit'],
      };
    } catch {
      return null;
    }
  },
};

// Export all database parsers
export const databaseParsers: Parser[] = [
  mysqlErrorParser,
  mysqlQueryParser,
  mysqlSlowParser,
  postgresErrorParser,
  postgresAuthParser,
  postgresStatementParser,
  oracleAlertParser,
  oracleListenerParser,
  oracleAuditParser,
  sqlserverErrorParser,
  sqlserverAuditParser,
  sqlserverTransactionParser,
  mongodbServerParser,
  mongodbAuditParser,
];
