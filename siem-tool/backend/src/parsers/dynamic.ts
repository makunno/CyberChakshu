// Dynamic Log Detector - Analyzes unknown logs and attempts to identify fields
// This parser acts as a fallback when no specific pattern matches

import { Parser, ParsedLogEntry, LogType } from '../types';
import { generateId, parseTimestamp, parseSeverity, extractIP, extractPort } from '../utils/helpers';

// Export types for external use
export interface FieldAnalysis {
  name: string;
  value: string | number;
  confidence: number;
  label: string;
  category: string;
}

export interface LogStructure {
  separator: string;
  columns: string[];
  hasTimestamp: boolean;
  timestampIndex: number;
  hasKeyPairs: boolean;
}

// Field detection patterns
const FIELD_PATTERNS = {
  // Timestamp patterns
  timestamp: [
    /^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}/,
    /^\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}/,
    /^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/,
    /^\d{2}-\d{2}-\d{2,4}\s+\d{2}:\d{2}:\d{2}/,
    /time[=:]\s*"?\d{4}-\d{2}-\d{2}T?\d{2}:\d{2}:\d{2}/i,
    /timestamp[=:]\s*"?\d{4}-\d{2}-\d{2}T?\d{2}:\d{2}:\d{2}/i,
    /@timestamp[=:]\s*"?\d{4}-\d{2}-\d{2}T?\d{2}:\d{2}:\d{2}/i,
  ],
  
  // IP addresses
  ipAddress: [
    /src[=_]ip[=:]\s*"?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i,
    /dst[=_]ip[=:]\s*"?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i,
    /client[=_]?ip[=:]\s*"?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i,
    /server[=_]?ip[=:]\s*"?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i,
    /remote[=_]?addr[=:]\s*"?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i,
    /host[=:]\s*"?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i,
    /from[=\s]+"?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i,
    /ip[=:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/,
  ],
  
  // Port numbers
  port: [
    /src[=_]port[=:]\s*"?(\d{1,5})/i,
    /dst[=_]port[=:]\s*"?(\d{1,5})/i,
    /port[=:]\s*(\d{1,5})\b/,
    /on\s+port\s+(\d{1,5})/i,
    /:(\d{1,5})\b/,
  ],
  
  // Usernames
  user: [
    /user[=:]\s*"?(\w[ \w.-]*\w)"/i,
    /username[=:]\s*"?(\w[ \w.-]*\w)"/i,
    /login[=:]\s*"?(\w[ \w.-]*\w)"/i,
    /account[=:]\s*"?(\w[ \w.-]*\w)"/i,
    /uid[=:]\s*"?(\w+)"/i,
    /for\s+(\w+)\s+from/i,
    /as\s+user\s+(\w+)/i,
    /by\s+user\s+(\w+)/i,
  ],
  
  // Process IDs
  pid: [
    /pid[=:]\s*"?(\d+)"/i,
    /\[(\d+)\]/,
    /process[=_]?id[=:]\s*"?(\d+)"/i,
    /tid[=:]\s*"?(\d+)"/i,
  ],
  
  // Severity levels
  severity: [
    /\b(debug|trace|info|notice|log|warn|warning|error|err|fail|failed|critical|fatal|alert|emergency|emerg|crit)\b/i,
    /level[=:]\s*"?(\w+)"/i,
    /severity[=:]\s*"?(\w+)"/i,
    /priority[=:]\s*"?(\w+)"/i,
  ],
  
  // Hostnames
  hostname: [
    /host[=:]\s*"?([a-zA-Z0-9.-]+)"/i,
    /hostname[=:]\s*"?([a-zA-Z0-9.-]+)"/i,
    /server[=:]\s*"?([a-zA-Z0-9.-]+)"/i,
    /machine[=:]\s*"?([a-zA-Z0-9.-]+)"/i,
    /node[=:]\s*"?([a-zA-Z0-9.-]+)"/i,
  ],
  
  // Service/Process names
  service: [
    /service[=:]\s*"?(\w+)"/i,
    /process[=:]\s*"?(\w+)"/i,
    /program[=:]\s*"?(\w+)"/i,
    /application[=:]\s*"?(\w+)"/i,
    /daemon[=:]\s*"?(\w+)"/i,
  ],
  
  // Actions/Events
  action: [
    /(started|stopped|started|stopped|created|deleted|modified|updated|accessed|login|logout|connect|disconnect|accept|reject|allow|deny|block|pass|drop|failed|succeeded|completed)/i,
    /action[=:]\s*"?(\w+)"/i,
    /event[=:]\s*"?(\w+)"/i,
    /operation[=:]\s*"?(\w+)"/i,
  ],
  
  // Status codes
  status: [
    /status[=:]\s*"?(\d{3})"/i,
    /code[=:]\s*"?(\d{3,4})"/i,
    /response[=:\s]+(\d{3})/i,
    /\s(\d{3})\s*$/,
  ],
  
  // Protocols
  protocol: [
    /proto[=:]\s*"?(\w+)"/i,
    /protocol[=:]\s*"?(\w+)"/i,
    /\b(tcp|udp|icmp|http|https|ftp|ssh|smtp|dns|tls|ssl)\b/i,
  ],
  
  // Methods (HTTP)
  method: [
    /(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)/,
    /method[=:]\s*"?(\w+)"/i,
  ],
  
  // Paths/URLs
  path: [
    /path[=:]\s*"?([^"\s]+)"/i,
    /url[=:]\s*"?([^"\s]+)"/i,
    /uri[=:]\s*"?([^"\s]+)"/i,
    /(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+([^"\s]+)/,
  ],
  
  // File paths
  filePath: [
    /file[=:]\s*"?([^"\s]+)"/i,
    /filename[=:]\s*"?([^"\s]+)"/i,
    /path[=:]\s*"?([\/\w.-]+)"/i,
  ],
  
  // Error messages
  error: [
    /error[=:]\s*"?([^"]+)"/i,
    /message[=:]\s*"?([^"]+)"/i,
    /msg[=:]\s*"?([^"]+)"/i,
    /exception[=:]\s*"?([^"]+)"/i,
  ],
};

// Column separator patterns for structured logs
const SEPARATORS = [
  { regex: /\|/, name: 'pipe' },
  { regex: /,/, name: 'comma' },
  { regex: /;/, name: 'semicolon' },
  { regex: /\t/, name: 'tab' },
  { regex: /\s{2,}/, name: 'space' },
];

// Analyze log structure to determine format
function analyzeLogStructure(lines: string[]): LogStructure {
  const structure: LogStructure = {
    separator: 'unknown',
    columns: [],
    hasTimestamp: false,
    timestampIndex: -1,
    hasKeyPairs: false,
  };

  if (lines.length === 0) return structure;

  // Sample first few lines
  const sampleLines = lines.slice(0, 5);

  // Check for key=value pairs
  const keyPairCount = sampleLines.filter(line => /[a-zA-Z_][a-zA-Z0-9_]*[=:][^=\s]+/.test(line)).length;
  structure.hasKeyPairs = keyPairCount > sampleLines.length / 2;

  // Detect separator if not key=value format
  if (!structure.hasKeyPairs) {
    for (const sep of SEPARATORS) {
      const sepCount = sampleLines.filter(line => sep.regex.test(line)).length;
      if (sepCount > sampleLines.length * 0.8) {
        structure.separator = sep.name;
        const parts = sampleLines[0].split(sep.regex);
        structure.columns = parts.map((p, i) => `field_${i}`);
        
        // Check for timestamp column
        parts.forEach((part, i) => {
          if (FIELD_PATTERNS.timestamp.some(pattern => pattern.test(part))) {
            structure.hasTimestamp = true;
            structure.timestampIndex = i;
            structure.columns[i] = 'timestamp';
          }
        });
        break;
      }
    }
  }

  return structure;
}

// Detect fields in a line using patterns
function detectFields(line: string, structure?: LogStructure): FieldAnalysis[] {
  const fields: FieldAnalysis[] = [];

  // If structured with separator, parse columns
  if (structure && structure.separator !== 'unknown' && !structure.hasKeyPairs) {
    const separator = SEPARATORS.find(s => s.name === structure.separator);
    if (separator) {
      const parts = line.split(separator.regex);
      parts.forEach((part, index) => {
        const trimmed = part.trim();
        if (!trimmed) return;

        const label = structure.columns[index] || `field_${index}`;
        const field = inferFieldType(trimmed, label);
        if (field) {
          fields.push({
            name: label,
            value: trimmed,
            confidence: 0.8,
            label: field.type,
            category: field.category,
          });
        }
      });
    }
    return fields;
  }

  // Otherwise, use pattern detection for unstructured logs
  for (const [fieldType, patterns] of Object.entries(FIELD_PATTERNS)) {
    for (const pattern of patterns) {
      const match = line.match(pattern);
      if (match) {
        const value = match[1] || match[0];
        fields.push({
          name: fieldType,
          value: value,
          confidence: 0.7,
          label: fieldType,
          category: getFieldTypeCategory(fieldType),
        });
      }
    }
  }

  // Try to detect key=value pairs
  const kvMatches = line.matchAll(/(\w+)[=:]([^,\s]+)/g);
  for (const match of kvMatches) {
    const key = match[1];
    const value = match[2].replace(/^["']|["']$/g, '');
    fields.push({
      name: key,
      value: value,
      confidence: 0.6,
      label: key,
      category: 'custom',
    });
  }

  return fields;
}

// Infer field type from value
function inferFieldType(value: string, label?: string): { type: string; category: string } | null {
  const trimmed = value.trim();
  if (!trimmed) return null;

  // Check timestamp
  if (FIELD_PATTERNS.timestamp.some(p => p.test(trimmed))) {
    return { type: 'timestamp', category: 'temporal' };
  }

  // Check IP
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmed)) {
    return { type: 'ip_address', category: 'network' };
  }

  // Check port
  if (/^\d{1,5}$/.test(trimmed) && parseInt(trimmed) > 0 && parseInt(trimmed) <= 65535) {
    return { type: 'port', category: 'network' };
  }

  // Check HTTP method
  if (/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)$/i.test(trimmed)) {
    return { type: 'http_method', category: 'application' };
  }

  // Check status code
  if (/^[1-5]\d{2}$/.test(trimmed)) {
    return { type: 'status_code', category: 'application' };
  }

  // Check severity
  if (/^(debug|info|notice|warn|warning|error|critical|fatal|alert)$/i.test(trimmed)) {
    return { type: 'severity', category: 'level' };
  }

  // Check protocol
  if (/^(tcp|udp|icmp|http|https|ftp|ssh|smtp|dns)$/i.test(trimmed)) {
    return { type: 'protocol', category: 'network' };
  }

  // Check user-like
  if (/^[\w.-]+@[\w.-]+$/.test(trimmed)) {
    return { type: 'email', category: 'identity' };
  }

  if (/^[a-zA-Z0-9_-]+$/.test(trimmed) && trimmed.length < 50) {
    return { type: 'string', category: 'text' };
  }

  return { type: 'unknown', category: 'other' };
}

function getFieldTypeCategory(fieldType: string): string {
  const categories: Record<string, string> = {
    timestamp: 'temporal',
    ipAddress: 'network',
    port: 'network',
    user: 'identity',
    pid: 'process',
    severity: 'level',
    hostname: 'system',
    service: 'process',
    action: 'event',
    status: 'application',
    protocol: 'network',
    method: 'application',
    path: 'application',
    filePath: 'system',
    error: 'error',
  };
  return categories[fieldType] || 'other';
}

// Extract structured data from line
function extractStructuredData(line: string, fields: FieldAnalysis[]) {
  const data: Record<string, any> = {};

  fields.forEach(field => {
    data[field.name] = field.value;
  });

  return data;
}

// Determine severity from fields and message
function determineSeverity(fields: FieldAnalysis[], message: string): ParsedLogEntry['severity'] {
  // Check explicit severity field
  const severityField = fields.find(f => f.label === 'severity');
  if (severityField) {
    const severity = parseSeverity(String(severityField.value));
    if (severity !== 'unknown') return severity;
  }

  // Infer from message
  const lowerMsg = message.toLowerCase();
  if (/error|fail|failed|fatal|critical|exception|crash|abort|denied/i.test(lowerMsg)) {
    return 'error';
  }
  if (/warn|warning|alert|deprecated|unusual|suspicious/i.test(lowerMsg)) {
    return 'warning';
  }
  if (/debug|trace|verbose/i.test(lowerMsg)) {
    return 'debug';
  }
  if (/info|notice|log|success|completed|started|stopped/i.test(lowerMsg)) {
    return 'info';
  }

  return 'unknown';
}

// Generate tags from fields and message
function generateTags(fields: FieldAnalysis[], message: string): string[] {
  const tags: string[] = ['dynamic', 'auto-detected'];
  const lowerMsg = message.toLowerCase();

  if (fields.some(f => f.category === 'network')) tags.push('network');
  if (fields.some(f => f.category === 'identity')) tags.push('auth');
  if (fields.some(f => f.category === 'process')) tags.push('process');
  if (fields.some(f => f.category === 'system')) tags.push('system');
  if (fields.some(f => f.category === 'application')) tags.push('application');

  if (/error|fail|failed|fatal|critical/i.test(lowerMsg)) tags.push('error');
  if (/warn|warning|alert/i.test(lowerMsg)) tags.push('warning');
  if (/security|attack|threat|malware/i.test(lowerMsg)) tags.push('security');
  if (/login|auth|password|credential/i.test(lowerMsg)) tags.push('authentication');
  if (/connect|disconnect|session/i.test(lowerMsg)) tags.push('connection');

  return tags;
}

// Dynamic parser that adapts to unknown log formats
export const dynamicParser: Parser = {
  name: 'Dynamic Log Detector',
  logType: 'unknown',
  detect: () => true, // Always matches as fallback
  parse: (line: string): ParsedLogEntry => {
    const trimmed = line.trim();
    if (!trimmed) {
      return {
        id: generateId(),
        timestamp: null,
        logType: 'unknown',
        severity: 'unknown',
        source: {},
        message: '',
        rawLine: line,
        fields: {},
        tags: ['empty'],
      };
    }

    // Detect fields dynamically
    const fields = detectFields(trimmed);

    // Extract common fields
    let timestamp: string | null = null;
    let ip: string | undefined;
    let port: number | undefined;
    let hostname: string | undefined;
    let service: string | undefined;
    let pid: number | undefined;
    let user: string | undefined;
    let action: string | undefined;
    let message = trimmed;

    // Extract from detected fields
    fields.forEach(field => {
      if (field.label === 'timestamp' || field.category === 'temporal') {
        timestamp = parseTimestamp(String(field.value));
      } else if (field.label === 'ipAddress' || field.label === 'src_ip' || field.label === 'dst_ip') {
        if (!ip) ip = extractIP(String(field.value));
      } else if (field.label === 'port' || field.label === 'src_port' || field.label === 'dst_port') {
        if (!port) port = extractPort(String(field.value));
      } else if (field.label === 'hostname' || field.label === 'host') {
        hostname = String(field.value);
      } else if (field.label === 'service' || field.label === 'process') {
        service = String(field.value);
      } else if (field.label === 'pid') {
        pid = parseInt(String(field.value));
      } else if (field.label === 'user' || field.label === 'username' || field.label === 'login') {
        if (!user) user = String(field.value);
      } else if (field.label === 'action' || field.label === 'event') {
        action = String(field.value);
      }
    });

    // Try to extract message (rest of line after structured fields)
    const msgField = fields.find(f => f.label === 'message' || f.label === 'error' || f.label === 'msg');
    if (msgField) {
      message = String(msgField.value);
    }

    // Determine severity
    const severity = determineSeverity(fields, message);

    // Generate tags
    const tags = generateTags(fields, message);

    // Build fields object
    const fieldsObj: Record<string, string | number | boolean | null> = {};
    fields.forEach(field => {
      const key = field.name;
      const value = field.value;
      
      // Skip if already captured in standard fields
      if (['timestamp', 'ipAddress', 'port', 'hostname', 'service', 'pid', 'user', 'action'].includes(key)) {
        return;
      }
      
      // Convert numeric values
      if (/^\d+$/.test(String(value))) {
        fieldsObj[key] = parseInt(String(value));
      } else {
        fieldsObj[key] = value;
      }
    });

    // Add detected field types as metadata
    fieldsObj['_detected_fields'] = fields.map(f => `${f.label}:${f.category}`).join(',');

    return {
      id: generateId(),
      timestamp,
      logType: 'unknown',
      severity,
      source: {
        hostname,
        service,
        pid,
        ip,
        port,
      },
      user: user ? { name: user } : undefined,
      action,
      outcome: 'unknown',
      message,
      rawLine: line,
      fields: fieldsObj,
      tags,
    };
  },
};

// Analyze multiple lines to detect log structure and suggest labels
export function analyzeLogStructureAndSuggestLabels(lines: string[]): {
  structure: LogStructure;
  detectedFields: string[];
  suggestedLabels: Array<{ field: string; type: string; confidence: number }>;
  sampleFields: Record<string, any>[];
} {
  const structure = analyzeLogStructure(lines);
  const allFields: Map<string, Set<string>> = new Map();
  const sampleFields: Record<string, any>[] = [];

  // Analyze first 20 lines
  const sampleLines = lines.slice(0, 20);
  sampleLines.forEach(line => {
    const fields = detectFields(line, structure);
    const fieldObj: Record<string, any> = {};
    
    fields.forEach(field => {
      if (!allFields.has(field.name)) {
        allFields.set(field.name, new Set());
      }
      allFields.get(field.name)!.add(String(field.value));
      fieldObj[field.name] = field.value;
    });
    
    sampleFields.push(fieldObj);
  });

  // Generate suggested labels
  const suggestedLabels = Array.from(allFields.entries()).map(([fieldName, values]) => {
    const valuesArray = Array.from(values);
    const type = inferFieldType(valuesArray[0]);
    const confidence = valuesArray.length > 5 ? 0.9 : 0.6;
    
    return {
      field: fieldName,
      type: type?.type || 'unknown',
      confidence,
    };
  });

  return {
    structure,
    detectedFields: Array.from(allFields.keys()),
    suggestedLabels,
    sampleFields,
  };
}

// Auto-detect log type based on field patterns
export function detectLogTypeFromFields(fields: FieldAnalysis[]): LogType {
  const fieldLabels = fields.map(f => f.label);

  if (fieldLabels.some(l => l.includes('method') || l.includes('status') || l.includes('path'))) {
    return 'apache'; // Likely web server
  }
  if (fieldLabels.some(l => l.includes('protocol') && l.includes('src_ip') && l.includes('dst_ip'))) {
    return 'iptables'; // Likely firewall
  }
  if (fieldLabels.some(l => l.includes('user') && l.includes('login'))) {
    return 'ssh_auth'; // Likely auth
  }
  if (fieldLabels.some(l => l.includes('pid') && l.includes('service'))) {
    return 'syslog'; // Likely system
  }

  return 'unknown';
}
