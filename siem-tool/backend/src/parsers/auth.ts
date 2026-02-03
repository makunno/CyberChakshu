// Authentication Log Parsers - SSH, PAM, User Auth
// Based on ~/ISEA/Raju-ISEA/auth_dashboard.py

import { Parser, ParsedLogEntry } from '../types';
import { generateId, parseTimestamp, normalizeUser } from '../utils/helpers';
import { FTPParsers } from './ftp';

// ========== SSH Auth Parser (Failed) ==========

export const sshFailedParser: Parser = {
  name: 'SSH Failed Login',
  logType: 'ssh_auth',
  detect: (line: string) => /sshd\[\d+\]:\s+Failed\s+\w+\s+for/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    // Handle both "Failed password for invalid user X" and "Failed password for X"
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[(\d+)\]:\s+Failed\s+(\w+)\s+for\s+(invalid\s+user\s+)?(\S+)\s+from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+port\s+(\d+)/
    );
    if (!match) return null;

    const [, timestamp, host, pid, authMethod, invalidUser, user, ip, port] = match;
    const { name: userName, domain } = normalizeUser(user);
    const isInvalidUser = !!invalidUser;

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'ssh_auth',
      severity: 'warning',
      source: { hostname: host, service: 'sshd', pid: parseInt(pid), ip, port: parseInt(port) },
      user: { name: userName, domain },
      action: 'login',
      outcome: 'failure',
      message: `Failed ${authMethod} login for ${isInvalidUser ? 'invalid user ' : ''}${user} from ${ip}:${port}`,
      rawLine: line,
      fields: {
        host,
        pid: parseInt(pid),
        auth_method: authMethod,
        user,
        src_ip: ip,
        src_port: parseInt(port),
        failure_reason: isInvalidUser ? 'invalid_user' : 'failed_password',
        is_invalid_user: isInvalidUser,
      },
      tags: isInvalidUser 
        ? ['auth', 'ssh', 'failed_login', 'invalid_user', 'security'] 
        : ['auth', 'ssh', 'failed_login', 'security'],
    };
  },
};

// ========== SSH Auth Parser (Accepted) ==========

export const sshAcceptedParser: Parser = {
  name: 'SSH Accepted Login',
  logType: 'ssh_auth',
  detect: (line: string) => /sshd\[\d+\]:\s+Accepted\s+\w+\s+for/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[(\d+)\]:\s+Accepted\s+(\w+)\s+for\s+(\S+)\s+from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+port\s+(\d+)/
    );
    if (!match) return null;

    const [, timestamp, host, pid, authMethod, user, ip, port] = match;
    const { name: userName, domain } = normalizeUser(user);

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'ssh_auth',
      severity: 'info',
      source: { hostname: host, service: 'sshd', pid: parseInt(pid), ip, port: parseInt(port) },
      user: { name: userName, domain },
      action: 'login',
      outcome: 'success',
      message: `Accepted ${authMethod} login for ${user} from ${ip}:${port}`,
      rawLine: line,
      fields: {
        host,
        pid: parseInt(pid),
        auth_method: authMethod,
        user,
        src_ip: ip,
        src_port: parseInt(port),
      },
      tags: ['auth', 'ssh', 'successful_login'],
    };
  },
};

// ========== SSH Disconnect ==========

export const sshDisconnectParser: Parser = {
  name: 'SSH Disconnect',
  logType: 'ssh_auth',
  detect: (line: string) => /sshd\[\d+\]:\s+(Disconnected|Connection closed)/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[(\d+)\]:\s+(Disconnected|Connection closed).*?(?:from\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?/
    );
    if (!match) return null;

    const [, timestamp, host, pid, action, ip] = match;

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'ssh_auth',
      severity: 'info',
      source: { hostname: host, service: 'sshd', pid: parseInt(pid), ip },
      action: 'disconnect',
      outcome: 'success',
      message: `${action} from ${ip || 'unknown'}`,
      rawLine: line,
      fields: {
        host,
        pid: parseInt(pid),
        src_ip: ip || null,
      },
      tags: ['auth', 'ssh', 'disconnect'],
    };
  },
};

// ========== SSH Invalid User ==========

export const sshInvalidUserParser: Parser = {
  name: 'SSH Invalid User',
  logType: 'ssh_auth',
  detect: (line: string) => /sshd\[\d+\]:\s+Invalid user/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[(\d+)\]:\s+Invalid user\s+(\S+)\s+from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/
    );
    if (!match) return null;

    const [, timestamp, host, pid, user, ip] = match;

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'ssh_auth',
      severity: 'warning',
      source: { hostname: host, service: 'sshd', pid: parseInt(pid), ip },
      user: { name: user },
      action: 'login',
      outcome: 'failure',
      message: `Invalid user ${user} from ${ip}`,
      rawLine: line,
      fields: {
        host,
        pid: parseInt(pid),
        user,
        src_ip: ip,
        failure_reason: 'invalid_user',
      },
      tags: ['auth', 'ssh', 'invalid_user', 'security'],
    };
  },
};

// ========== PAM Authentication ==========

export const pamParser: Parser = {
  name: 'PAM Auth',
  logType: 'pam',
  detect: (line: string) => /pam_\w+\(\w+:\w+\):/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\w+)\[(\d+)\]:\s+pam_(\w+)\((\w+):(\w+)\):\s+(.*)/
    );
    if (!match) return null;

    const [, timestamp, host, service, pid, pamModule, pamService, pamType, message] = match;

    let severity: ParsedLogEntry['severity'] = 'info';
    let outcome: ParsedLogEntry['outcome'] = 'unknown';
    
    if (/authentication failure|auth fail/i.test(message)) {
      severity = 'warning';
      outcome = 'failure';
    } else if (/session opened|success/i.test(message)) {
      outcome = 'success';
    } else if (/session closed/i.test(message)) {
      outcome = 'success';
    }

    // Extract user if present
    const userMatch = message.match(/user[=\s]+(\w+)/i);

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'pam',
      severity,
      source: { hostname: host, service, pid: parseInt(pid) },
      user: userMatch ? { name: userMatch[1] } : undefined,
      action: pamType,
      outcome,
      message,
      rawLine: line,
      fields: {
        host,
        service,
        pid: parseInt(pid),
        pam_module: pamModule,
        pam_service: pamService,
        pam_type: pamType,
      },
      tags: ['auth', 'pam', 'linux'],
    };
  },
};

// ========== Sudo Log ==========

export const sudoParser: Parser = {
  name: 'Sudo Log',
  logType: 'pam',
  detect: (line: string) => /sudo\[\d+\]:/.test(line) || /sudo:\s+\w+\s+:/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    // Pattern: sudo: user : TTY=... ; PWD=... ; USER=... ; COMMAND=...
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sudo(?:\[\d+\])?:\s+(\w+)\s+:\s+TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\w+)\s*;\s*COMMAND=(.*)/
    );
    if (!match) return null;

    const [, timestamp, host, user, tty, pwd, targetUser, command] = match;

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'pam',
      severity: 'info',
      source: { hostname: host, service: 'sudo' },
      user: { name: user },
      action: 'sudo',
      outcome: 'success',
      message: `${user} ran command as ${targetUser}: ${command}`,
      rawLine: line,
      fields: {
        host,
        user,
        tty,
        pwd,
        target_user: targetUser,
        command,
      },
      tags: ['auth', 'sudo', 'privilege_escalation', 'linux'],
    };
  },
};

// ========== Su Log ==========

export const suParser: Parser = {
  name: 'Su Log',
  logType: 'pam',
  detect: (line: string) => /su\[\d+\]:/.test(line) && /(Successful|FAILED|session)/i.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+su\[(\d+)\]:\s+(.*)/
    );
    if (!match) return null;

    const [, timestamp, host, pid, message] = match;

    let outcome: ParsedLogEntry['outcome'] = 'unknown';
    let severity: ParsedLogEntry['severity'] = 'info';

    if (/successful/i.test(message)) {
      outcome = 'success';
    } else if (/failed|failure/i.test(message)) {
      outcome = 'failure';
      severity = 'warning';
    }

    // Extract users if present
    const fromUserMatch = message.match(/(\w+)\s+to\s+(\w+)/);

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'pam',
      severity,
      source: { hostname: host, service: 'su', pid: parseInt(pid) },
      user: fromUserMatch ? { name: fromUserMatch[1] } : undefined,
      action: 'su',
      outcome,
      message,
      rawLine: line,
      fields: {
        host,
        pid: parseInt(pid),
        from_user: fromUserMatch?.[1] || null,
        to_user: fromUserMatch?.[2] || null,
      },
      tags: ['auth', 'su', 'privilege_escalation', 'linux'],
    };
  },
};

// ========== FTP Auth Parser (vsftpd) ==========

export const vsftpdParser: Parser = {
  name: 'vsftpd Log',
  logType: 'vsftpd',
  detect: (line: string) => /\[(OK|FAIL)\]\s+(LOGIN|DOWNLOAD|UPLOAD).*Client\s+"[\d.]+"/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2}).*\[(\w+)\]\s+(OK|FAIL)\s+(LOGIN|DOWNLOAD|UPLOAD).*Client\s+"([\d.]+)"/
    );
    if (!match) return null;

    const [, month, day, time, user, status, event, ip] = match;
    const timestamp = `${month} ${day} ${time}`;

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'vsftpd',
      severity: status === 'FAIL' ? 'warning' : 'info',
      source: { service: 'vsftpd', ip },
      user: { name: user },
      action: event.toLowerCase(),
      outcome: status === 'OK' ? 'success' : 'failure',
      message: `${event} ${status} for user ${user} from ${ip}`,
      rawLine: line,
      fields: {
        user,
        status,
        event_type: event,
        client_ip: ip,
      },
      tags: ['auth', 'ftp', 'vsftpd'],
    };
  },
};

// ========== FileZilla Server Parser ==========

export const filezillaParser: Parser = {
  name: 'FileZilla Server Log',
  logType: 'vsftpd',
  detect: (line: string) => /^\(\d+\).*?\d{1,2}\/\d{1,2}\/\d{4}\s+\d{1,2}:\d{2}:\d{2}/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^\((\d+)\)(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{1,2}:\d{2}:\d{2})(?:\s+(?:AM|PM))?\s*-\s+(.+?)\s+\(([\d\.]+)\)\s*(?:>\s+)?(\d{3})/
    );
    if (!match) return null;

    const [, seqNum, month, day, year, time, user, ip, code] = match;
    const timestamp = `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')} ${time}`;
    const outcome = code.startsWith('2') ? 'success' : code.startsWith('4') || code.startsWith('5') ? 'failure' : 'unknown';

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'vsftpd',
      severity: outcome === 'failure' ? 'warning' : 'info',
      source: { service: 'filezilla', ip },
      user: { name: user !== 'not logged in' ? user : null },
      action: 'ftp_session',
      outcome,
      message: line,
      rawLine: line,
      fields: {
        seq_num: parseInt(seqNum),
        response_code: code,
        server: 'filezilla',
      },
      tags: ['auth', 'ftp', 'filezilla'],
    };
  },
};

// ========== Xferlog Parser ==========

export const xferlogParser: Parser = {
  name: 'Xferlog (wu-ftpd)',
  logType: 'vsftpd',
  detect: (line: string) => /^(Sun|Mon|Tue|Wed|Thu|Fri|Sat) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) .* \d{4} .* ftp .* [*] c$/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 14) return null;

    const dayOfWeek = parts[0];
    const month = parts[1];
    const day = parts[2];
    const time = parts[3];
    const year = parts[4];
    const transferId = parts[5];
    const ip = parts[6];
    const fileSize = parts[7];
    const filename = parts[8];
    const typeCode = parts[9];
    const specialCode = parts[10];
    const direction = parts[11];
    const accessMode = parts[12];
    const username = parts[13];
    const serviceName = parts[14];
    const completionStatus = parts[17];
    const timestamp = `${year}-${FTPParsers.monthToNum(month)}-${day.padStart(2, '0')} ${time}`;
    
    const directionMap: Record<string, string> = { 'i': 'download', 'o': 'upload', 'a': 'append' };
    const typeMap: Record<string, string> = { 'b': 'binary', 'a': 'ascii' };

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'vsftpd',
      severity: 'info',
      source: { service: 'ftp', ip },
      user: { name: username },
      action: `ftp_${directionMap[direction] || 'transfer'}`,
      outcome: completionStatus === 'c' ? 'success' : 'failure',
      message: line,
      rawLine: line,
      fields: {
        transfer_id: parseInt(transferId),
        filename,
        bytes: parseInt(fileSize),
        transfer_type: typeMap[typeCode] || typeCode,
        direction: directionMap[direction] || direction,
        access_mode: accessMode,
        username,
        service: serviceName,
        completion_status: completionStatus === 'c' ? 'complete' : 'incomplete',
        protocol: 'ftp',
      },
      tags: ['ftp', 'xferlog', 'file_transfer'],
    };
  },
};

// Export all auth parsers
export const authParsers: Parser[] = [
  sshFailedParser,
  sshAcceptedParser,
  sshDisconnectParser,
  sshInvalidUserParser,
  pamParser,
  sudoParser,
  suParser,
  vsftpdParser,
  filezillaParser,
  xferlogParser,
];
