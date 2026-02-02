// Multi-line Parser - Support for multi-line log formats like MySQL slow queries

import { ParsedLogEntry, LogType } from '../types';
import { generateId } from '../utils/helpers';

export const MULTI_LINE_TYPES = ['mysql_slow', 'oracle_alert', 'oracle_audit'];

export function isMultiLineLog(logType: string): boolean {
  return MULTI_LINE_TYPES.includes(logType);
}

export function parseMultiLineBlock(lines: string[], logType: string): ParsedLogEntry | null {
  const block = lines.join('\n');
  
  if (logType === 'mysql_slow') {
    return parseMySqlSlowBlock(block);
  } else if (logType === 'oracle_alert') {
    return parseOracleAlertBlock(block);
  } else if (logType === 'oracle_audit') {
    return parseOracleAuditBlock(block);
  }
  
  return null;
}

function parseMySqlSlowBlock(block: string): ParsedLogEntry | null {
  const timeMatch = block.match(/# Time: (\S+)/);
  const userMatch = block.match(/# User@Host: (\w+)\[\w+\] @ (\S+) \[(.*?)\]/);
  const queryMatch = block.match(/# Query_time: ([\d.]+).*Rows_examined: (\d+)/);
  const sqlMatch = block.match(/\n(SELECT.*);/s);

  if (!timeMatch || !userMatch || !queryMatch || !sqlMatch) return null;

  return {
    id: generateId(),
    timestamp: timeMatch[1],
    logType: 'mysql_slow',
    severity: 'warning',
    source: {
      hostname: userMatch[2],
      ip: userMatch[3],
    },
    message: `Slow query: ${sqlMatch[1]}`,
    rawLine: block,
    fields: {
      user: userMatch[1],
      host: userMatch[2],
      ip: userMatch[3],
      query_time: parseFloat(queryMatch[1]),
      rows_examined: parseInt(queryMatch[2]),
      sql: sqlMatch[1].trim(),
    },
    tags: ['database', 'mysql', 'slow_query', 'performance'],
  };
}

function parseOracleAlertBlock(block: string): ParsedLogEntry | null {
  const alertRe = /^([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\n*ORA-(\d+):\s+(.+)$/s;
  const match = alertRe.exec(block);

  if (!match) return null;

  return {
    id: generateId(),
    timestamp: match[1],
    logType: 'oracle_alert',
    severity: 'error',
    source: { service: 'oracle' },
    message: `ORA-${match[2]}: ${match[3].trim()}`,
    rawLine: block,
    fields: {
      error_code: match[2],
      error_message: match[3].trim(),
    },
    tags: ['database', 'oracle', 'alert', 'error'],
  };
}

function parseOracleAuditBlock(block: string): ParsedLogEntry | null {
  const timeMatch = block.match(/generated at (.*)/);
  const actionMatch = block.match(/ACTION : (.*)/);
  const userMatch = block.match(/USERID : (.*)/);
  const objMatch = block.match(/OBJ\$NAME : (.*)/);

  if (!timeMatch || !actionMatch || !userMatch || !objMatch) return null;

  return {
    id: generateId(),
    timestamp: timeMatch[1],
    logType: 'oracle_audit',
    severity: 'info',
    source: { service: 'oracle' },
    user: { name: userMatch[1].trim() },
    action: actionMatch[1].trim(),
    message: `Oracle audit: ${actionMatch[1].trim()} on ${objMatch[1].trim()}`,
    rawLine: block,
    fields: {
      action: actionMatch[1].trim(),
      user: userMatch[1].trim(),
      object_name: objMatch[1].trim(),
    },
    tags: ['database', 'oracle', 'audit'],
  };
}
