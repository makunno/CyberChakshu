import { ParsedLogEntry, LogType } from '../types';

// Generate unique ID
export function generateId(): string {
  return crypto.randomUUID();
}

// Parse severity from various formats
export function parseSeverity(level: string): ParsedLogEntry['severity'] {
  const l = level.toLowerCase();
  if (['debug', 'trace'].includes(l)) return 'debug';
  if (['info', 'notice', 'log'].includes(l)) return 'info';
  if (['warn', 'warning'].includes(l)) return 'warning';
  if (['error', 'err', 'fail', 'failed'].includes(l)) return 'error';
  if (['critical', 'fatal', 'alert', 'emergency', 'emerg', 'crit'].includes(l)) return 'critical';
  return 'unknown';
}

// Parse timestamp to ISO format
export function parseTimestamp(ts: string): string | null {
  if (!ts) return null;
  
  // Try various timestamp formats
  const formats = [
    // ISO 8601
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/,
    // Common log format
    /^\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}/,
    // Syslog format
    /^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/,
    // MySQL/PostgreSQL format
    /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}/,
  ];

  try {
    const date = new Date(ts);
    if (!isNaN(date.getTime())) {
      return date.toISOString();
    }
  } catch {
    // Continue to manual parsing
  }

  // Handle syslog-style timestamp (add current year)
  const syslogMatch = ts.match(/^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/);
  if (syslogMatch) {
    const [, month, day, hour, min, sec] = syslogMatch;
    const months: Record<string, number> = {
      Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
      Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11
    };
    const year = new Date().getFullYear();
    const date = new Date(year, months[month] ?? 0, parseInt(day), parseInt(hour), parseInt(min), parseInt(sec));
    return date.toISOString();
  }

  return ts; // Return original if parsing fails
}

// Extract IP address from string
export function extractIP(str: string): string | undefined {
  const ipMatch = str.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  return ipMatch ? ipMatch[1] : undefined;
}

// Extract port number
export function extractPort(str: string): number | undefined {
  const portMatch = str.match(/port\s*[=:]?\s*(\d+)/i);
  return portMatch ? parseInt(portMatch[1]) : undefined;
}

// Create base parsed entry
export function createBaseEntry(
  line: string,
  logType: LogType,
  fields: Record<string, string | number | boolean | null> = {}
): ParsedLogEntry {
  return {
    id: generateId(),
    timestamp: null,
    logType,
    severity: 'unknown',
    source: {},
    message: line.trim(),
    rawLine: line,
    fields,
    tags: [],
  };
}

// Normalize user string (handle domain\user or user@domain)
export function normalizeUser(user: string): { name?: string; domain?: string } {
  if (!user) return {};
  
  if (user.includes('\\')) {
    const [domain, name] = user.split('\\');
    return { name: name?.toLowerCase(), domain: domain?.toLowerCase() };
  }
  
  if (user.includes('@')) {
    const [name, domain] = user.split('@');
    return { name: name?.toLowerCase(), domain: domain?.toLowerCase() };
  }
  
  return { name: user.toLowerCase() };
}

// Preprocess single-line JSON array to multiline format
export function preprocessJsonArray(content: string): string {
  const trimmed = content.trim();
  if (!trimmed.startsWith('[[') || !trimmed.endsWith(']]')) {
    return content;
  }

  try {
    const data = JSON.parse(trimmed);
    if (!Array.isArray(data)) {
      return content;
    }

    const lines = data.map((entry: any) => JSON.stringify(entry));
    return lines.join('\n');
  } catch {
    return content;
  }
}
