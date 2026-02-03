// Mail Server Log Parsers - Postfix, Sendmail, Exim, Dovecot, Exchange
// Based on ~/ISEA/Tanubhav/Prototype3.py

import { Parser, ParsedLogEntry } from '../types';
import { generateId, parseTimestamp } from '../utils/helpers';

// ========== Postfix Parser ==========

export const postfixParser: Parser = {
  name: 'Postfix Log',
  logType: 'postfix',
  detect: (line: string) => /postfix\/(smtpd|smtp|cleanup|qmgr|pickup|local)\[\d+\]:/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+postfix\/(\w+)\[(\d+)\]:\s+(.*)/
    );
    if (!match) return null;

    const [, timestamp, host, process, pid, message] = match;

    // Extract queue ID if present
    const queueIdMatch = message.match(/^([A-F0-9]+):/);
    
    // Extract email addresses
    const fromMatch = message.match(/from=<([^>]*)>/);
    const toMatch = message.match(/to=<([^>]*)>/);
    
    // Extract status
    const statusMatch = message.match(/status=(\w+)/);
    
    // Detect severity
    let severity: ParsedLogEntry['severity'] = 'info';
    if (statusMatch?.[1] === 'bounced' || statusMatch?.[1] === 'deferred') severity = 'warning';
    if (/reject|error|fatal/i.test(message)) severity = 'error';

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'postfix',
      severity,
      source: { hostname: host, service: `postfix/${process}`, pid: parseInt(pid) },
      action: process,
      outcome: statusMatch?.[1] === 'sent' ? 'success' : statusMatch?.[1] === 'bounced' ? 'failure' : 'unknown',
      message,
      rawLine: line,
      fields: {
        host,
        process,
        pid: parseInt(pid),
        queue_id: queueIdMatch?.[1] || null,
        from: fromMatch?.[1] || null,
        to: toMatch?.[1] || null,
        status: statusMatch?.[1] || null,
      },
      tags: ['mail', 'postfix', 'smtp'],
    };
  },
};

// ========== Sendmail Parser ==========

export const sendmailParser: Parser = {
  name: 'Sendmail Log',
  logType: 'sendmail',
  detect: (line: string) => /sendmail\[\d+\]:/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sendmail\[(\d+)\]:\s+(.*)/
    );
    if (!match) return null;

    const [, timestamp, host, pid, message] = match;

    const fromMatch = message.match(/from=<([^>]+)>/);
    const toMatch = message.match(/to=<([^>]+)>/);
    const statMatch = message.match(/stat=(\S+)/);
    
    const from = fromMatch ? fromMatch[1] : null;
    const to = toMatch ? toMatch[1] : null;
    const stat = statMatch ? statMatch[1] : null;

    let outcome: 'success' | 'failure' | 'unknown' = 'unknown';
    if (stat) {
      if (/sent|deferred/i.test(stat)) outcome = 'success';
      else if (/bounced|reject|fail/i.test(stat)) outcome = 'failure';
    }

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'sendmail',
      severity: /error|fail|reject|bounced/i.test(message) ? 'error' : 'info',
      source: { hostname: host, service: 'sendmail', pid: parseInt(pid) },
      user: from ? { name: from } : undefined,
      action: 'send',
      outcome,
      message,
      rawLine: line,
      fields: {
        host,
        pid: parseInt(pid),
        from,
        to,
        stat,
      },
      tags: ['mail', 'sendmail', 'smtp'],
    };
  },
};

// ========== Exim Parser ==========

export const eximParser: Parser = {
  name: 'Exim Log',
  logType: 'exim',
  detect: (line: string) => /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+[A-Z0-9]{6,}\s+(<=|=>|\*\*)/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+([A-Z0-9]+)\s+(<=|=>|\*\*)\s+(\S+)\s*(.*)/
    );
    if (!match) return null;

    const [, date, time, msgId, direction, address, rest] = match;

    let action = 'unknown';
    let severity: ParsedLogEntry['severity'] = 'info';
    if (direction === '<=') action = 'received';
    else if (direction === '=>') action = 'delivered';
    else if (direction === '**') {
      action = 'bounced';
      severity = 'warning';
    }

    return {
      id: generateId(),
      timestamp: parseTimestamp(`${date} ${time}`),
      logType: 'exim',
      severity,
      source: { service: 'exim' },
      action,
      outcome: direction === '**' ? 'failure' : 'success',
      message: `${direction} ${address} ${rest}`,
      rawLine: line,
      fields: {
        date,
        time,
        message_id: msgId,
        direction,
        address,
      },
      tags: ['mail', 'exim', 'smtp'],
    };
  },
};

// ========== Dovecot Parser ==========

export const dovecotParser: Parser = {
  name: 'Dovecot Log',
  logType: 'dovecot',
  detect: (line: string) => /dovecot:\s+(imap|pop3|lmtp|auth)-login:/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+dovecot:\s+(imap|pop3|lmtp|auth)-login:\s+(.*)/
    );
    if (!match) return null;

    const [, timestamp, host, service, message] = match;

    // Extract login info
    const userMatch = message.match(/user=<([^>]*)>/);
    const lipMatch = message.match(/lip=(\d+\.\d+\.\d+\.\d+)/);
    const ripMatch = message.match(/rip=(\d+\.\d+\.\d+\.\d+)/);

    let outcome: ParsedLogEntry['outcome'] = 'unknown';
    let severity: ParsedLogEntry['severity'] = 'info';
    if (/Login:/.test(message)) outcome = 'success';
    if (/failed|error/i.test(message)) {
      outcome = 'failure';
      severity = 'warning';
    }

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'dovecot',
      severity,
      source: { hostname: host, service: `dovecot/${service}`, ip: ripMatch?.[1] },
      user: userMatch ? { name: userMatch[1] } : undefined,
      action: 'login',
      outcome,
      message,
      rawLine: line,
      fields: {
        host,
        service,
        user: userMatch?.[1] || null,
        local_ip: lipMatch?.[1] || null,
        remote_ip: ripMatch?.[1] || null,
      },
      tags: ['mail', 'dovecot', 'imap', 'pop3', 'auth'],
    };
  },
};

// ========== Microsoft Exchange Parser ==========

export const exchangeParser: Parser = {
  name: 'Microsoft Exchange Log',
  logType: 'exchange',
  detect: (line: string) => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z,SMTP(Receive|Send|Deliver),/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z),(SMTP(?:Receive|Send|Deliver|Submit)),([^,]*),?(.*)/
    );
    if (!match) return null;

    const [, timestamp, source, action, rest] = match;

    return {
      id: generateId(),
      timestamp,
      logType: 'exchange',
      severity: 'info',
      source: { service: 'exchange' },
      action: source.toLowerCase(),
      message: `${source}: ${action} ${rest}`,
      rawLine: line,
      fields: {
        timestamp,
        source,
        action,
      },
      tags: ['mail', 'exchange', 'microsoft', 'smtp'],
    };
  },
};

// Export all mail parsers
export const mailParsers: Parser[] = [
  postfixParser,
  sendmailParser,
  eximParser,
  dovecotParser,
  exchangeParser,
];
