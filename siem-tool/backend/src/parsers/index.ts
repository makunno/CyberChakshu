// Parser Registry - MIGRATED: Uses ISEA-style detection and parsing

import { Parser, ParsedLogEntry, LogType } from '../types';
import { generateId } from '../utils/helpers';

// Import ISEA-style detection and parsing
import { LogDetector } from './log_detector';
import { LogParsers } from './log_parsers';
import { parseWithLegacyParser } from './legacy_parser';
import { TYPE_MAPPING } from './type_mapping';
import { isMultiLineLog, parseMultiLineBlock } from './multiline_parser';
import { WindowsParsers, JsonFTPHandler } from './windows';

// Import all parser groups (keep for backward compatibility)
import { databaseParsers } from './database';
import { webserverParsers } from './webserver';
import { systemParsers } from './system';
import { authParsers } from './auth';
import { firewallParsers } from './firewall';
import { mailParsers } from './mail';
import { dynamicParser } from './dynamic';
import { JsonFTPHandler } from './windows';

// Combine all parsers into a single registry
// NOTE: Order matters! More specific parsers should come BEFORE generic ones.
// Auth parsers (SSH, sudo) are checked before syslog which is a generic format.
export const allParsers: Parser[] = [
  ...authParsers,      // Most specific - check auth patterns first (SSH, PAM, sudo)
  ...firewallParsers,  // Firewall logs (iptables, ufw, etc.)
  ...mailParsers,      // Mail server logs
  ...databaseParsers,  // Database logs
  ...webserverParsers, // Web server logs
  ...systemParsers,    // Generic system logs (syslog, systemd) - checked last
];

// Raw/fallback parser for unrecognized logs - uses dynamic parser
const rawParser: Parser = dynamicParser;

/**
 * Detect log type using ISEA-style LogDetector
 * Returns FreeKhana LogType enum value
 */
export function detectLogType(content: string): LogType {
  const iseaType = LogDetector.detect(content);
  return TYPE_MAPPING[iseaType] || 'unknown';
}

/**
 * Get parser for a specific log type (backward compatibility)
 */
export function getParser(logType: LogType): Parser | null {
  if (logType === 'raw' || logType === 'unknown') {
    return rawParser;
  }
  return allParsers.find(p => p.logType === logType) || null;
}

/**
 * Get ALL parsers for a specific log type (backward compatibility)
 * Some log types (like ssh_auth) have multiple parsers for different patterns
 */
export function getParsersForType(logType: LogType): Parser[] {
  if (logType === 'raw' || logType === 'unknown') {
    return [rawParser];
  }
  return allParsers.filter(p => p.logType === logType);
}

/**
 * Try parsing a line with multiple parsers of same type (backward compatibility)
 */
function tryParsersForLine(line: string, parsers: Parser[]): ParsedLogEntry | null {
  const trimmed = line.trim();
  for (const parser of parsers) {
    if (parser.detect(trimmed)) {
      const result = parser.parse(trimmed);
      if (result) return result;
    }
  }
  return null;
}

/**
 * Auto-detect and parse a single line (backward compatibility)
 */
export function autoParseLineSingle(line: string): ParsedLogEntry {
  const trimmed = line.trim();
  if (!trimmed) {
    return rawParser.parse(line)!;
  }

  for (const parser of allParsers) {
    if (parser.detect(trimmed)) {
      const result = parser.parse(trimmed);
      if (result) return result;
    }
  }

  return rawParser.parse(line)!;
}

/**
 * Parse multiple lines with a specific parser (backward compatibility)
 */
export function parseLines(lines: string[], logType: LogType): ParsedLogEntry[] {
  const parser = getParser(logType);
  if (!parser) {
    return lines.map(line => rawParser.parse(line)!);
  }

  const results: ParsedLogEntry[] = [];
  
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const parsed = parser.parse(trimmed);
    if (parsed) {
      results.push(parsed);
    } else {
      // Fallback to raw if parser fails
      results.push(rawParser.parse(line)!);
    }
  }

  return results;
}

/**
  * Parse using ISEA-style parsers with support for multi-line logs
  * Returns detected FreeKhana LogType and parsed entries with statistics
  */
export function parseWithISEA(content: string): {
  detectedType: LogType;
  entries: ParsedLogEntry[];
  stats: {
    totalLines: number;
    parsedLines: number;
    failedLines: number;
  };
} {
  const detectedType = detectLogType(content);
  
  function buildWindowsEventEntry(parsed: Record<string, any>, rawEvent: string): ParsedLogEntry | null {
    const timestamp = parsed.timestamp || new Date().toISOString();
    const keywords = parsed.keywords || '';
    const isSuccess = keywords.toLowerCase().includes('success');
    const severity = keywords.toLowerCase().includes('failure') || keywords.toLowerCase().includes('error') ? 'error' 
                   : keywords.toLowerCase().includes('warning') ? 'warning' : 'info';
    
    // Extract fields from multi-line content
    let username = parsed.user?.name || '';
    let securityId = '';
    let processId = '';
    let processName = '';
    
    // Extract Security ID
    const securityIdMatch = rawEvent.match(/Security ID:\s+(\S+)/);
    if (securityIdMatch) securityId = securityIdMatch[1];
    
    // Extract Account Name (username)
    const accountNameMatch = rawEvent.match(/Account Name:\s+(\S+)/);
    if (accountNameMatch && !username) username = accountNameMatch[1];
    
    // Extract Process ID
    const processIdMatch = rawEvent.match(/Process ID:\s+(0x[\da-fA-F]+|\d+)/);
    if (processIdMatch) processId = processIdMatch[1];
    
    // Extract Process Name (capture full path including spaces)
    const processNameMatch = rawEvent.match(/Process Name:\s+(.+)/);
    if (processNameMatch) {
      // Get everything after "Process Name:" and clean up
      processName = processNameMatch[1].trim();
      // Remove any trailing tabs, quotes, or whitespace
      processName = processName.replace(/["\t\r\n]+$/, '').replace(/\t+$/, '').trim();
    }
    
    // Extract IP address from description
    let ipAddress = '';
    const ipMatch = rawEvent.match(/Source:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    if (ipMatch) ipAddress = ipMatch[1];
    
    // Extract Logon ID
    let logonId = '';
    const logonIdMatch = rawEvent.match(/Logon ID:\s+(0x[\da-fA-F]+)/);
    if (logonIdMatch) logonId = logonIdMatch[1];
    
    const message = parsed.message || rawEvent;
    
    const entry: ParsedLogEntry = {
      id: generateId(),
      timestamp,
      logType: 'windows_event_viewer' as LogType,
      severity,
      source: {
        hostname: parsed.host,
        service: parsed.service || parsed.source || 'event'
      },
      user: username ? { name: username } : undefined,
      action: parsed.taskCategory || 'event',
      outcome: isSuccess ? 'success' : 'failure',
      message: message,
      rawLine: rawEvent,
      fields: {
        event_id: parsed.event_id || 0,
        channel: parsed.source || '',
        level: parsed.level || 'info',
        task_category: parsed.taskCategory || '',
        keywords: keywords,
        username,
        security_id: securityId,
        ip_address: ipAddress,
        process_id: processId,
        process_name: processName,
        logon_id: logonId
      },
      tags: ['windows', 'eventviewer', severity, (parsed.source || 'event').toLowerCase()]
    };
    
    return entry;
  }
  
  let entries: ParsedLogEntry[] = [];
  let parsedCount = 0;
  let failedCount = 0;

  if (detectedType === 'moodle_lms') {
    try {
      const data = JSON.parse(content);
      if (Array.isArray(data) && data.length > 0) {
        for (const item of data) {
          if (Array.isArray(item) && item.length >= 9) {
            const [timestamp, user1, user2, module, component, event, description, source, ip] = item;
            
            const entry: ParsedLogEntry = {
              id: generateId(),
              timestamp: typeof timestamp === 'string' ? timestamp : null,
              logType: 'moodle_lms',
              severity: 'info',
              source: {
                ip: typeof ip === 'string' ? ip : undefined,
                hostname: typeof source === 'string' ? source : undefined
              },
              user: {
                name: typeof user1 === 'string' && user1 !== '-' ? user1 : undefined
              },
              action: typeof event === 'string' ? event : undefined,
              message: typeof description === 'string' ? description : JSON.stringify(item),
              rawLine: JSON.stringify(item),
              fields: {
                timestamp,
                user: typeof user1 === 'string' ? user1 : undefined,
                relatedUser: typeof user2 === 'string' && user2 !== '-' ? user2 : undefined,
                module: typeof module === 'string' ? module : undefined,
                component: typeof component === 'string' ? component : undefined,
                event: typeof event === 'string' ? event : undefined,
                description: typeof description === 'string' ? description : undefined,
                source: typeof source === 'string' ? source : undefined,
                ip: typeof ip === 'string' ? ip : undefined
              },
              tags: ['moodle', 'lms', 'education']
            };
            
            entries.push(entry);
            parsedCount++;
          }
        }
      }
    } catch (e) {
      console.error('Failed to parse Moodle LMS JSON:', e);
      failedCount = 1;
    }
    
    return {
      detectedType,
      entries,
      stats: {
        totalLines: entries.length,
        parsedLines: parsedCount,
        failedLines: failedCount,
      },
    };
  }

  if (detectedType === 'iis_ftp') {
    const parsedEntries = JsonFTPHandler.parseJsonFTPLogs(content);
    return {
      detectedType,
      entries: parsedEntries,
      stats: {
        totalLines: parsedEntries.length,
        parsedLines: parsedEntries.length,
        failedLines: 0,
      },
    };
  }

  // Handle Windows Event Viewer TXT format
  if (detectedType === 'windows_event_viewer') {
    // Remove BOM character if present
    let cleanContent = content;
    if (cleanContent.startsWith('\uFEFF') || cleanContent.startsWith('﻿')) {
      cleanContent = cleanContent.slice(1);
    }

    const lines = cleanContent.split('\n');
    const parsedEntries: ParsedLogEntry[] = [];
    let currentEvent: string[] = [];
    let headerSkipped = false;
    let totalEventsDetected = 0;

    for (const line of lines) {
      const trimmed = line.trim();

      // Skip header line
      if (!headerSkipped && (trimmed.startsWith('Keywords\t') || trimmed.startsWith('Keywords,'))) {
        headerSkipped = true;
        continue;
      }

      // Check if this is a new event line (starts with keywords pattern)
      const isNewEvent = /^(Audit (?:Success|Failure|Error|Warning)|Success|Failure|Error|Warning)[\t,]?\d{2}-\d{2}-\d{4}/.test(trimmed);

      if (isNewEvent) {
        // Count this as a detected event
        totalEventsDetected++;

        // Parse previous event if exists
        if (currentEvent.length > 0) {
          const fullEvent = currentEvent.join('\n');
          const parsed = WindowsParsers.windowsEventViewerTXT(fullEvent);
          if (parsed) {
            const entry = buildWindowsEventEntry(parsed, fullEvent);
            if (entry) parsedEntries.push(entry);
          }
        }
        // Start new event
        currentEvent = [line];
      } else if (trimmed) {
        // Continue current event (multi-line details)
        currentEvent.push(line);
      }
    }

    // Don't forget the last event
    if (currentEvent.length > 0) {
      totalEventsDetected++;
      const fullEvent = currentEvent.join('\n');
      const parsed = WindowsParsers.windowsEventViewerTXT(fullEvent);
      if (parsed) {
        const entry = buildWindowsEventEntry(parsed, fullEvent);
        if (entry) parsedEntries.push(entry);
      }
    }

    const successfulParses = parsedEntries.length;
    const failedParses = totalEventsDetected - successfulParses;
    const successRate = totalEventsDetected > 0 ? Math.round((successfulParses / totalEventsDetected) * 100) : 0;

    return {
      detectedType,
      entries: parsedEntries,
      stats: {
        totalLines: lines.length,
        totalEvents: totalEventsDetected,
        parsedEvents: successfulParses,
        failedEvents: failedParses,
        successRate: successRate,
      },
    };
  }

  // Handle Windows Application TXT format (Level\tDate\tSource\tEvent ID\tTask\tMessage)
  if (detectedType === 'windows_application' || detectedType === 'Windows Application TXT') {
    // Remove BOM character if present
    let cleanContent = content;
    if (cleanContent.startsWith('\uFEFF') || cleanContent.startsWith('﻿')) {
      cleanContent = content.slice(1);
    }
    
    const lines = cleanContent.split('\n').filter(l => l.trim() && !l.startsWith('Level\t') && !l.startsWith('Level,'));
    const parsedEntries: ParsedLogEntry[] = [];
    let parsedCount = 0;

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      const parsed = WindowsParsers.windowsApplicationTXT(trimmed);
      if (parsed) {
        const timestamp = parsed.timestamp || new Date().toISOString();
        const severity = parsed.level === 'error' || parsed.level === 'critical' ? 'error'
                       : parsed.level === 'warning' ? 'warning' : 'info';

        const entry: ParsedLogEntry = {
          id: generateId(),
          timestamp,
          logType: 'windows_application' as LogType,
          severity,
          source: {
            hostname: parsed.host,
            service: parsed.service || parsed.source || 'application'
          },
          action: parsed.taskCategory || 'event',
          outcome: severity === 'error' ? 'failure' : 'success',
          message: parsed.message || trimmed,
          rawLine: trimmed,
          fields: {
            event_id: parsed.event_id || 0,
            channel: parsed.source || '',
            level: parsed.level || 'info',
            task_category: parsed.taskCategory || '',
            keywords: parsed.keywords || '',
          },
          tags: ['windows', 'application', severity, (parsed.source || 'application').toLowerCase()]
        };

        parsedEntries.push(entry);
        parsedCount++;
      }
    }

    const successRate = lines.length > 0 ? Math.round((parsedCount / lines.length) * 100) : 0;

    return {
      detectedType,
      entries: parsedEntries,
      stats: {
        totalLines: lines.length,
        totalEvents: parsedEntries.length,
        parsedEvents: parsedCount,
        failedEvents: lines.length - parsedCount,
        successRate: successRate,
      },
    };
  }

  const lines = content.split('\n').filter(l => l.trim());
  
  // Check if this is a multi-line log type
  if (isMultiLineLog(detectedType)) {
    // Parse multi-line blocks
    let currentBlock: string[] = [];
    const blockStartPatterns: Record<string, RegExp> = {
      'mysql_slow': /^# Time:/,
      'oracle_alert': /^[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{2}\s+\d{2}:\d{2}\s+\d{4}/,
      'oracle_audit': /^Audit record generated/,
    };
    
    const startPattern = blockStartPatterns[detectedType];
    
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      
      if (startPattern && startPattern.test(trimmed)) {
        // Parse previous block
        if (currentBlock.length > 0) {
          const parsed = parseMultiLineBlock(currentBlock, detectedType);
          if (parsed) {
            entries.push(parsed);
            parsedCount++;
          }
        }
        currentBlock = [trimmed];
      } else {
        currentBlock.push(trimmed);
      }
    }
    
    // Don't forget the last block
    if (currentBlock.length > 0) {
      const parsed = parseMultiLineBlock(currentBlock, detectedType);
      if (parsed) {
        entries.push(parsed);
        parsedCount++;
      }
    }
  } else {
    // Single-line parsing - use ISEA-style LogParsers
    const iseaType = LogDetector.detect(content);
    entries = [];
    
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      
      const parsed = parseWithLegacyParser(iseaType, trimmed);
      if (parsed) {
        entries.push(parsed);
        parsedCount++;
      } else {
        // Fallback to auto-parsing
        const autoParsed = autoParseLineSingle(trimmed);
        entries.push(autoParsed);
        if (autoParsed.logType !== 'raw') {
          parsedCount++;
        } else {
          failedCount++;
        }
      }
    }
  }

  return {
    detectedType,
    entries,
    stats: {
      totalLines: lines.length,
      parsedLines: parsedCount,
      failedLines: failedCount,
    },
  };
}

/**
 * Auto-detect log type and parse all lines (MIGRATED - uses ISEA detection/parsing)
 * Returns detected FreeKhana LogType and parsed entries with statistics
 */
export function autoParse(content: string): {
  detectedType: LogType;
  entries: ParsedLogEntry[];
  stats: {
    totalLines: number;
    parsedLines: number;
    failedLines: number;
  };
} {
  return parseWithISEA(content);
}

// Export individual parser groups for direct access
export { databaseParsers, webserverParsers, systemParsers, authParsers, firewallParsers, mailParsers };

// Export dynamic parser utilities
export { dynamicParser, analyzeLogStructureAndSuggestLabels, detectLogTypeFromFields } from './dynamic';
export type { FieldAnalysis, LogStructure } from './dynamic';
