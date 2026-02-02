// Legacy Parser Wrapper - Converts ISEA-style simple parsing to ParsedLogEntry

import { ParsedLogEntry, LogType } from '../types';
import { generateId } from '../utils/helpers';
import { LogParsers } from './log_parsers';
import { TYPE_MAPPING } from './type_mapping';

export function parseWithLegacyParser(logType: string, line: string): ParsedLogEntry | null {
  const parserMethod = `parse${logType.replace(/[^a-zA-Z0-9]/g, '')}`;
  const parsed = (LogParsers as any)[parserMethod]?.(line);
  
  if (!parsed) return null;
  
  const mappedType = TYPE_MAPPING[logType] || 'unknown';
  
  return convertToParsedLogEntry(parsed, mappedType, line);
}

function convertToParsedLogEntry(
  parsed: Record<string, any>,
  logType: LogType,
  rawLine: string
): ParsedLogEntry {
  const result: ParsedLogEntry = {
    id: generateId(),
    timestamp: null,
    logType,
    severity: 'info',
    source: {},
    message: rawLine,
    rawLine,
    fields: {},
    tags: [],
  };

  if (parsed.timestamp) {
    result.timestamp = parsed.timestamp;
  }

  if (parsed.host) {
    result.source.hostname = parsed.host;
  }

  if (parsed.ip || parsed.ip_address) {
    result.source.ip = parsed.ip || parsed.ip_address;
  }

  if (parsed.port || parsed.src_port) {
    result.source.port = parsed.port || parsed.src_port;
  }

  if (parsed.pid) {
    result.source.pid = parsed.pid;
  }

  if (parsed.service) {
    result.source.service = parsed.service;
  }

  if (parsed.user || parsed.username) {
    result.user = { name: parsed.user || parsed.username };
  }

  if (parsed.dst_ip) {
    result.destination = { ip: parsed.dst_ip };
  }

  if (parsed.dst_port) {
    result.destination = result.destination || {};
    result.destination.port = parsed.dst_port;
  }

  if (parsed.status || parsed.outcome) {
    const status = parsed.status?.toString() || parsed.outcome?.toString();
    if (status) {
      const num = parseInt(status);
      if (!isNaN(num) && num >= 400) {
        result.outcome = 'failure';
        result.severity = num >= 500 ? 'critical' : 'warning';
      } else if (num >= 200 && num < 300) {
        result.outcome = 'success';
      }
    }
  }

  result.fields = { ...parsed };
  
  result.tags = generateTags(logType, parsed, rawLine);
  
  result.message = parsed.message || rawLine;
  
  return result;
}

function generateTags(logType: LogType, parsed: Record<string, any>, rawLine: string): string[] {
  const tags: string[] = [];
  
  if (logType === 'ssh_auth') {
    tags.push('auth', 'ssh', 'security');
    if (parsed.auth_method) tags.push(`auth_${parsed.auth_method.toLowerCase()}`);
  } else if (logType.startsWith('mysql')) {
    tags.push('database', 'mysql');
    if (logType === 'mysql_slow') tags.push('slow_query', 'performance');
    if (logType === 'mysql_error') tags.push('error');
  } else if (logType.startsWith('postgres')) {
    tags.push('database', 'postgresql');
    if (logType === 'postgres_error') tags.push('error');
  } else if (logType.startsWith('oracle')) {
    tags.push('database', 'oracle');
    if (logType === 'oracle_audit') tags.push('audit');
    if (logType === 'oracle_alert') tags.push('alert', 'error');
  } else if (logType.startsWith('sqlserver')) {
    tags.push('database', 'sqlserver');
  } else if (logType.startsWith('mongodb')) {
    tags.push('database', 'mongodb');
    if (logType === 'mongodb_audit') tags.push('audit');
  } else if (logType === 'iptables' || logType === 'ufw') {
    tags.push('firewall', 'linux', 'network');
  } else if (logType === 'windows_firewall') {
    tags.push('firewall', 'windows', 'network');
  } else if (logType === 'apache' || logType === 'nginx') {
    tags.push('webserver', 'http', 'access');
  } else if (logType === 'postfix' || logType === 'sendmail') {
    tags.push('mail', 'smtp', 'email');
  } else if (logType === 'syslog' || logType === 'systemd') {
    tags.push('system', 'linux');
  } else if (logType === 'kernel') {
    tags.push('system', 'linux', 'kernel');
  } else if (logType === 'audit') {
    tags.push('system', 'linux', 'audit', 'security');
  }
  
  return tags;
}
