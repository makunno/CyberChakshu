// System Log Parsers - Linux/Unix syslog, systemd, kernel, audit
// Based on ~/ISEA/Radhey/Week1Final.py

import { Parser, ParsedLogEntry } from '../types';
import { generateId, parseTimestamp, parseSeverity, normalizeUser } from '../utils/helpers';

// ========== Syslog Parser ==========

export const syslogParser: Parser = {
  name: 'Syslog',
  logType: 'syslog',
  detect: (line: string) => /^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+[\w\-\/]+\[\d+\]:/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w\-\/]+)\[(\d+)\]:\s+(.*)/
    );
    if (!match) return null;

    const [, timestamp, host, service, pid, message] = match;

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'syslog',
      severity: 'info',
      source: { hostname: host, service, pid: parseInt(pid) },
      message,
      rawLine: line,
      fields: {
        host,
        service,
        pid: parseInt(pid),
      },
      tags: ['system', 'linux', 'syslog'],
    };
  },
};

// ========== Systemd Parser ==========

export const systemdParser: Parser = {
  name: 'Systemd Journal',
  logType: 'systemd',
  detect: (line: string) => /systemd\[\d+\]:/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    // Pattern 1: With timestamp
    const match1 = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+systemd\[(\d+)\]:\s+(.*)/
    );
    if (match1) {
      const [, timestamp, host, pid, message] = match1;
      return {
        id: generateId(),
        timestamp: parseTimestamp(timestamp),
        logType: 'systemd',
        severity: 'info',
        source: { hostname: host, service: 'systemd', pid: parseInt(pid) },
        message,
        rawLine: line,
        fields: { host, pid: parseInt(pid) },
        tags: ['system', 'linux', 'systemd'],
      };
    }

    // Pattern 2: Without timestamp
    const match2 = line.match(/systemd\[(\d+)\]:\s+(.*)/);
    if (match2) {
      return {
        id: generateId(),
        timestamp: null,
        logType: 'systemd',
        severity: 'info',
        source: { service: 'systemd', pid: parseInt(match2[1]) },
        message: match2[2],
        rawLine: line,
        fields: { pid: parseInt(match2[1]) },
        tags: ['system', 'linux', 'systemd'],
      };
    }

    return null;
  },
};

// ========== Kernel Log Parser ==========

export const kernelParser: Parser = {
  name: 'Kernel Log',
  logType: 'kernel',
  detect: (line: string) => /kernel:/.test(line) || /^\[\s*\d+\.\d+\]/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    // Pattern 1: Syslog-style kernel message
    const match1 = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:\s+(.*)/
    );
    if (match1) {
      const [, timestamp, host, message] = match1;
      return {
        id: generateId(),
        timestamp: parseTimestamp(timestamp),
        logType: 'kernel',
        severity: 'info',
        source: { hostname: host, service: 'kernel' },
        message,
        rawLine: line,
        fields: { host },
        tags: ['system', 'linux', 'kernel'],
      };
    }

    // Pattern 2: dmesg-style with uptime
    const match2 = line.match(/^\[\s*(\d+\.\d+)\]\s+(.*)/);
    if (match2) {
      return {
        id: generateId(),
        timestamp: null,
        logType: 'kernel',
        severity: 'info',
        source: { service: 'kernel' },
        message: match2[2],
        rawLine: line,
        fields: { uptime: parseFloat(match2[1]) },
        tags: ['system', 'linux', 'kernel', 'dmesg'],
      };
    }

    return null;
  },
};

// ========== Audit Log Parser ==========

export const auditParser: Parser = {
  name: 'Linux Audit Log',
  logType: 'audit',
  detect: (line: string) => /^type=\w+\s+msg=audit\(/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^type=(\w+)\s+msg=audit\((\d+)\.\d+:(\d+)\):\s*(.*)/
    );
    if (!match) return null;

    const [, eventType, epoch, eventId, rest] = match;
    
    // Parse timestamp from epoch
    let timestamp: string | null = null;
    try {
      timestamp = new Date(parseInt(epoch) * 1000).toISOString();
    } catch {
      // Ignore timestamp parsing errors
    }

    // Extract user info if present
    const userMatch = rest.match(/uid=(\d+)/);
    const auserMatch = rest.match(/auid=(\d+)/);
    const commMatch = rest.match(/comm="([^"]+)"/);
    const exeMatch = rest.match(/exe="([^"]+)"/);
    const resMatch = rest.match(/res=(\w+)/);

    let severity: ParsedLogEntry['severity'] = 'info';
    if (eventType === 'SYSCALL' || eventType === 'EXECVE') severity = 'info';
    if (eventType === 'AVC' || eventType === 'SELINUX_ERR') severity = 'warning';
    if (eventType === 'USER_AUTH' && rest.includes('res=failed')) severity = 'warning';

    return {
      id: generateId(),
      timestamp,
      logType: 'audit',
      severity,
      source: { service: 'auditd' },
      user: userMatch ? { name: userMatch[1] } : undefined,
      action: eventType,
      outcome: resMatch ? (resMatch[1] === 'success' ? 'success' : 'failure') : 'unknown',
      message: rest,
      rawLine: line,
      fields: {
        event_type: eventType,
        event_id: parseInt(eventId),
        uid: userMatch ? parseInt(userMatch[1]) : null,
        auid: auserMatch ? parseInt(auserMatch[1]) : null,
        comm: commMatch?.[1] || null,
        exe: exeMatch?.[1] || null,
        result: resMatch?.[1] || null,
      },
      tags: ['system', 'linux', 'audit', 'security'],
    };
  },
};

// ========== Package Manager Log Parser ==========

export const packageParser: Parser = {
  name: 'Package Manager Log',
  logType: 'package',
  detect: (line: string) => /^\d{4}-\d{2}-\d{2}.*(?:install|upgrade|remove|purge)/i.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(/^(\d{4}-\d{2}-\d{2})\s+(.*)/);
    if (!match) return null;

    const [, date, message] = match;
    
    let action = 'unknown';
    if (/install/i.test(message)) action = 'install';
    else if (/upgrade/i.test(message)) action = 'upgrade';
    else if (/remove|purge/i.test(message)) action = 'remove';

    return {
      id: generateId(),
      timestamp: parseTimestamp(date),
      logType: 'package',
      severity: 'info',
      source: { service: 'package-manager' },
      action,
      message,
      rawLine: line,
      fields: { date, action },
      tags: ['system', 'linux', 'package'],
    };
  },
};

// ========== Cron Log Parser ==========

export const cronParser: Parser = {
  name: 'Cron Log',
  logType: 'cron',
  detect: (line: string) => /CRON\[\d+\]:/.test(line) || /crond\[\d+\]:/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(?:CRON|crond)\[(\d+)\]:\s+\((\w+)\)\s+(.*)/
    );
    if (!match) return null;

    const [, timestamp, host, pid, user, message] = match;

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'cron',
      severity: 'info',
      source: { hostname: host, service: 'cron', pid: parseInt(pid) },
      user: { name: user },
      action: 'cron_job',
      message,
      rawLine: line,
      fields: {
        host,
        pid: parseInt(pid),
        user,
        command: message.match(/CMD \((.*)\)/)?.[1] || message,
      },
      tags: ['system', 'linux', 'cron', 'scheduled'],
    };
  },
};

// ========== Daemon Log Parser (generic) ==========

export const daemonParser: Parser = {
  name: 'Daemon Log',
  logType: 'daemon',
  detect: (line: string) => /^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\w+\[\d+\]:/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\w+)\[(\d+)\]:\s+(.*)/
    );
    if (!match) return null;

    const [, timestamp, host, service, pid, message] = match;

    // Try to detect severity from message
    let severity: ParsedLogEntry['severity'] = 'info';
    if (/error|fail|critical/i.test(message)) severity = 'error';
    else if (/warn/i.test(message)) severity = 'warning';

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'daemon',
      severity,
      source: { hostname: host, service, pid: parseInt(pid) },
      message,
      rawLine: line,
      fields: {
        host,
        service,
        pid: parseInt(pid),
      },
      tags: ['system', 'linux', 'daemon'],
    };
  },
};

// Export all system parsers
export const systemParsers: Parser[] = [
  syslogParser,
  systemdParser,
  kernelParser,
  auditParser,
  packageParser,
  cronParser,
  daemonParser,
];
