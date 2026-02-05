// Web Server Log Parsers - Apache, Nginx, IIS, Django, Flask, Express, etc.
// Based on ~/ISEA/Tanubhav/Prototype*.py

import { Parser, ParsedLogEntry } from '../types';
import { generateId, parseTimestamp, parseSeverity } from '../utils/helpers';

// ========== Apache/Nginx Combined Log Format ==========

export const apacheParser: Parser = {
  name: 'Apache Access Log',
  logType: 'apache',
  detect: (line: string) => /^\S+\s+-\s+-\s+\[.*?\]\s+"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\S+)\s+-\s+-\s+\[(.*?)\]\s+"(\w+)\s+(\S+)\s+HTTP\/[\d.]+"\s+(\d+)\s+(\d+)/
    );
    if (!match) return null;

    const [, ip, timestamp, method, path, status, size] = match;
    const statusCode = parseInt(status);
    let severity: ParsedLogEntry['severity'] = 'info';
    if (statusCode >= 500) severity = 'error';
    else if (statusCode >= 400) severity = 'warning';

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'apache',
      severity,
      source: { ip, service: 'apache' },
      action: method,
      outcome: statusCode < 400 ? 'success' : 'failure',
      message: `${method} ${path} - ${status}`,
      rawLine: line,
      fields: {
        method,
        path,
        status: statusCode,
        size: parseInt(size),
        user_agent: line.match(/"([^"]*)"$/)?.[1] || null,
      },
      tags: ['webserver', 'apache', 'http'],
    };
  },
};

export const nginxParser: Parser = {
  name: 'Nginx Access Log',
  logType: 'nginx',
  detect: (line: string) => /^\S+\s+-\s+\S+\s+\[.*?\]\s+"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\S+)\s+-\s+(\S+)\s+\[(.*?)\]\s+"(\w+)\s+(\S+)\s+HTTP\/[\d.]+"\s+(\d+)\s+(\d+)/
    );
    if (!match) return null;

    const [, ip, user, timestamp, method, path, status, size] = match;
    const statusCode = parseInt(status);
    let severity: ParsedLogEntry['severity'] = 'info';
    if (statusCode >= 500) severity = 'error';
    else if (statusCode >= 400) severity = 'warning';

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'nginx',
      severity,
      source: { ip, service: 'nginx' },
      user: user !== '-' ? { name: user } : undefined,
      action: method,
      outcome: statusCode < 400 ? 'success' : 'failure',
      message: `${method} ${path} - ${status}`,
      rawLine: line,
      fields: {
        method,
        path,
        status: statusCode,
        size: parseInt(size),
      },
      tags: ['webserver', 'nginx', 'http'],
    };
  },
};

// ========== IIS Log ==========

export const iisParser: Parser = {
  name: 'IIS Log',
  logType: 'iis',
  detect: (line: string) => /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d+\.\d+\.\d+\.\d+\s+(GET|POST|PUT|DELETE)/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\w+)\s+(\S+)\s+.*\s+(\d{3})\s*$/
    );
    if (!match) return null;

    const [, date, time, serverIp, method, path, status] = match;
    const statusCode = parseInt(status);

    return {
      id: generateId(),
      timestamp: parseTimestamp(`${date} ${time}`),
      logType: 'iis',
      severity: statusCode >= 500 ? 'error' : statusCode >= 400 ? 'warning' : 'info',
      source: { ip: serverIp, service: 'iis' },
      action: method,
      outcome: statusCode < 400 ? 'success' : 'failure',
      message: `${method} ${path} - ${status}`,
      rawLine: line,
      fields: {
        date,
        time,
        server_ip: serverIp,
        method,
        path,
        status: statusCode,
      },
      tags: ['webserver', 'iis', 'http', 'windows'],
    };
  },
};

// ========== Django Log ==========

export const djangoParser: Parser = {
  name: 'Django Log',
  logType: 'django',
  detect: (line: string) => /^\[.*?\]\s+"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+\S+"\s+\d+/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(/^\[(.*?)\]\s+"(\w+)\s+(\S+)"\s+(\d+)/);
    if (!match) return null;

    const [, timestamp, method, path, status] = match;
    const statusCode = parseInt(status);

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'django',
      severity: statusCode >= 500 ? 'error' : statusCode >= 400 ? 'warning' : 'info',
      source: { service: 'django' },
      action: method,
      outcome: statusCode < 400 ? 'success' : 'failure',
      message: `${method} ${path} - ${status}`,
      rawLine: line,
      fields: { method, path, status: statusCode },
      tags: ['webserver', 'django', 'python', 'http'],
    };
  },
};

// ========== Flask Log ==========

export const flaskParser: Parser = {
  name: 'Flask Log',
  logType: 'flask',
  detect: (line: string) => {
    return (
      /^\[[\d/]+ [\d:]+\]\s+"\w+\s+\S+\s+\S+"\s+\d+/.test(line) ||  // [2024-01-15 10:30:45] "GET /path HTTP/1.1" 200
      /^\d+\.\d+\.\d+\.\d+\s+-\s+-\s+\[.*?\]\s+"\w+\s+\S+\s+\S+"\s+\d+/.test(line) ||  // 127.0.0.1 - - [15/Jan/2024...] "GET /path HTTP/1.1" 200
      /^\*\s+(Running on|Restarting)/.test(line) ||  // * Running on http://127.0.0.1:5000
      /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\/\S*\s+\d{3}$/.test(line)  // Simple: PUT /settings 200
    );
  },
  parse: (line: string): ParsedLogEntry | null => {
    // Check for startup message
    const startupMatch = line.match(/^\*\s+(Running on|Restarting)\s+(http\S+)/);
    if (startupMatch) {
      return {
        id: generateId(),
        timestamp: new Date().toISOString(),
        logType: 'flask',
        severity: 'info',
        source: { service: 'flask', ip: '127.0.0.1' },
        action: 'startup',
        outcome: 'success',
        message: line,
        rawLine: line,
        fields: { message: startupMatch[1], url: startupMatch[2] },
        tags: ['webserver', 'flask', 'python', 'startup'],
      };
    }

    // Standard log format: [2024-01-15 10:30:45] "GET /path HTTP/1.1" 200
    const match1 = line.match(/^\[([\d/]+ [\d:]+)\]\s+"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+(\S+)"\s+(\d+)/);
    if (match1) {
      const [, timestamp, method, path, protocol, status] = match1;
      const statusCode = parseInt(status);
      return {
        id: generateId(),
        timestamp: timestamp.replace(/(\d{4})-(\d{2})-(\d{2})/, '$3/$2/$1').replace(' ', 'T') + 'Z',
        logType: 'flask',
        severity: statusCode >= 500 ? 'error' : statusCode >= 400 ? 'warning' : 'info',
        source: { service: 'flask' },
        action: method,
        outcome: statusCode < 400 ? 'success' : 'failure',
        message: `${method} ${path} - ${status}`,
        rawLine: line,
        fields: { method, path, protocol, status: statusCode },
        tags: ['webserver', 'flask', 'python', 'http'],
      };
    }

    // Apache combined style: 127.0.0.1 - - [15/Jan/2024:10:30:45 +0000] "GET /path HTTP/1.1" 200 1234
    const match2 = line.match(/^\d+\.\d+\.\d+\.\d+\s+-\s+-\s+\[(\d+\/\w+\/\d+:\d+:\d+:\d+\s*[+-]?\d*)\]\s+"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+(\S+)"\s+(\d+)/);
    if (match2) {
      const [, timestampStr, method, path, protocol, status] = match2;
      const statusCode = parseInt(status);
      // Convert timestamp format
      const ts = timestampStr.replace(/:/, ' ').replace(/(\d+)\/(\w+)\/(\d+)/, '$2 $1, $3');
      return {
        id: generateId(),
        timestamp: new Date(ts).toISOString() || null,
        logType: 'flask',
        severity: statusCode >= 500 ? 'error' : statusCode >= 400 ? 'warning' : 'info',
        source: { service: 'flask' },
        action: method,
        outcome: statusCode < 400 ? 'success' : 'failure',
        message: `${method} ${path} - ${status}`,
        rawLine: line,
        fields: { method, path, protocol, status: statusCode },
        tags: ['webserver', 'flask', 'python', 'http'],
      };
    }

    // Simple format: PUT /settings 200
    const match3 = line.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+(\d+)/);
    if (match3) {
      const [, method, path, status] = match3;
      const statusCode = parseInt(status);
      return {
        id: generateId(),
        timestamp: null,
        logType: 'flask',
        severity: statusCode >= 500 ? 'error' : statusCode >= 400 ? 'warning' : 'info',
        source: { service: 'flask' },
        action: method,
        outcome: statusCode < 400 ? 'success' : 'failure',
        message: `${method} ${path} - ${status}`,
        rawLine: line,
        fields: { method, path, status: statusCode },
        tags: ['webserver', 'flask', 'python', 'http'],
      };
    }

    return null;
  },
};

// ========== Laravel Log ==========

export const laravelParser: Parser = {
  name: 'Laravel Log',
  logType: 'laravel',
  detect: (line: string) => /^\[\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\]\s+\w+\.\w+:/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(/^\[(.*?)\]\s+(\w+)\.(\w+):\s+(.*)/);
    if (!match) return null;

    const [, timestamp, env, level, message] = match;

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'laravel',
      severity: parseSeverity(level),
      source: { service: 'laravel' },
      message,
      rawLine: line,
      fields: { env, level, message },
      tags: ['webserver', 'laravel', 'php'],
    };
  },
};

// ========== Express.js / JSON Logs ==========

export const expressParser: Parser = {
  name: 'Express.js Log',
  logType: 'express',
  detect: (line: string) => {
    try {
      const j = JSON.parse(line);
      return j.method && j.url && j.status !== undefined;
    } catch {
      return false;
    }
  },
  parse: (line: string): ParsedLogEntry | null => {
    try {
      const j = JSON.parse(line);
      const statusCode = parseInt(j.status) || 0;

      return {
        id: generateId(),
        timestamp: j.timestamp || j.time || null,
        logType: 'express',
        severity: statusCode >= 500 ? 'error' : statusCode >= 400 ? 'warning' : 'info',
        source: { service: 'express', ip: j.ip || j.remoteAddress },
        action: j.method,
        outcome: statusCode < 400 ? 'success' : 'failure',
        message: `${j.method} ${j.url} - ${j.status}`,
        rawLine: line,
        fields: { ...j },
        tags: ['webserver', 'express', 'nodejs', 'http'],
      };
    } catch {
      return null;
    }
  },
};

// ========== Gunicorn Log ==========

export const gunicornParser: Parser = {
  name: 'Gunicorn Log',
  logType: 'gunicorn',
  detect: (line: string) => /^\[\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}.*\]\s+\[\d+\]\s+\[(INFO|ERROR|WARNING|DEBUG)\]/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(/^\[([\d\-:\s\+]+)\]\s+\[(\d+)\]\s+\[(\w+)\]\s+(.*)/);
    if (!match) return null;

    const [, timestamp, pid, level, message] = match;
    
    // Extract HTTP info if present
    const httpMatch = message.match(/(GET|POST|PUT|DELETE)\s+(\S+)/);

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'gunicorn',
      severity: parseSeverity(level),
      source: { service: 'gunicorn', pid: parseInt(pid) },
      action: httpMatch?.[1],
      message,
      rawLine: line,
      fields: {
        pid: parseInt(pid),
        level,
        method: httpMatch?.[1] || null,
        path: httpMatch?.[2] || null,
      },
      tags: ['webserver', 'gunicorn', 'python'],
    };
  },
};

// ========== Uvicorn Log ==========

export const uvicornParser: Parser = {
  name: 'Uvicorn Log',
  logType: 'uvicorn',
  detect: (line: string) => /^(INFO|ERROR|WARNING):\s+\d+\.\d+\.\d+\.\d+:\d+\s+-\s+"/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\w+):\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+-\s+"(\w+)\s+(\S+)\s+HTTP\/[\d.]+"\s+(\d+)/
    );
    if (!match) return null;

    const [, level, clientIp, clientPort, method, path, status] = match;
    const statusCode = parseInt(status);

    return {
      id: generateId(),
      timestamp: null,
      logType: 'uvicorn',
      severity: parseSeverity(level),
      source: { service: 'uvicorn', ip: clientIp, port: parseInt(clientPort) },
      action: method,
      outcome: statusCode < 400 ? 'success' : 'failure',
      message: `${method} ${path} - ${status}`,
      rawLine: line,
      fields: {
        level,
        client_ip: clientIp,
        client_port: parseInt(clientPort),
        method,
        path,
        status: statusCode,
      },
      tags: ['webserver', 'uvicorn', 'python', 'http'],
    };
  },
};

// ========== Rails Log ==========

export const railsParser: Parser = {
  name: 'Rails Log',
  logType: 'rails',
  detect: (line: string) => /Processing by \S+#\S+/.test(line) || /Started (GET|POST|PUT|DELETE)/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const processingMatch = line.match(/Processing by (\S+)#(\S+)/);
    if (processingMatch) {
      return {
        id: generateId(),
        timestamp: null,
        logType: 'rails',
        severity: 'info',
        source: { service: 'rails' },
        action: processingMatch[2],
        message: line,
        rawLine: line,
        fields: {
          controller: processingMatch[1],
          action: processingMatch[2],
        },
        tags: ['webserver', 'rails', 'ruby', 'http'],
      };
    }

    const startedMatch = line.match(/Started (\w+) "(\S+)"/);
    if (startedMatch) {
      return {
        id: generateId(),
        timestamp: null,
        logType: 'rails',
        severity: 'info',
        source: { service: 'rails' },
        action: startedMatch[1],
        message: line,
        rawLine: line,
        fields: {
          method: startedMatch[1],
          path: startedMatch[2],
        },
        tags: ['webserver', 'rails', 'ruby', 'http'],
      };
    }

    return null;
  },
};

// Export all web server parsers
export const webserverParsers: Parser[] = [
  apacheParser,
  nginxParser,
  iisParser,
  djangoParser,
  flaskParser,
  laravelParser,
  expressParser,
  gunicornParser,
  uvicornParser,
  railsParser,
];
