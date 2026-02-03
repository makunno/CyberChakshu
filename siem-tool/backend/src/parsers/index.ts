// Parser Registry - MIGRATED: Uses ISEA-style detection and parsing

import { Parser, ParsedLogEntry, LogType } from '../types';
import { generateId } from '../utils/helpers';

// Import ISEA-style detection and parsing
import { LogDetector } from './log_detector';
import { LogParsers } from './log_parsers';
import { parseWithLegacyParser } from './legacy_parser';
import { TYPE_MAPPING } from './type_mapping';
import { isMultiLineLog, parseMultiLineBlock } from './multiline_parser';

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
