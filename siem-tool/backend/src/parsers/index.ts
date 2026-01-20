// Parser Registry - Combines all parsers and provides detection/parsing functionality

import { Parser, ParsedLogEntry, LogType } from '../types';
import { generateId } from '../utils/helpers';

// Import all parser groups
import { databaseParsers } from './database';
import { webserverParsers } from './webserver';
import { systemParsers } from './system';
import { authParsers } from './auth';
import { firewallParsers } from './firewall';
import { mailParsers } from './mail';
import { dynamicParser } from './dynamic';

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
 * Detect log type by sampling lines
 * Returns the most likely log type based on pattern matching
 */
export function detectLogType(lines: string[], sampleSize = 50): LogType {
  const scores: Record<string, number> = {};
  
  // Initialize scores
  allParsers.forEach(p => {
    scores[p.logType] = 0;
  });
  scores['raw'] = 0;

  // Sample lines for detection
  const samplesToCheck = lines.slice(0, sampleSize);
  
  for (const line of samplesToCheck) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    let matched = false;
    for (const parser of allParsers) {
      if (parser.detect(trimmed)) {
        scores[parser.logType] = (scores[parser.logType] || 0) + 1;
        matched = true;
        break; // First match wins for this line
      }
    }
    
    if (!matched) {
      scores['raw']++;
    }
  }

  // Find the highest scoring log type
  let bestType: LogType = 'unknown';
  let bestScore = 0;
  
  for (const [logType, score] of Object.entries(scores)) {
    if (score > bestScore) {
      bestScore = score;
      bestType = logType as LogType;
    }
  }

  // If too few matches, return unknown
  if (bestScore < 3) {
    return 'unknown';
  }

  return bestType;
}

/**
 * Get parser for a specific log type
 */
export function getParser(logType: LogType): Parser | null {
  if (logType === 'raw' || logType === 'unknown') {
    return rawParser;
  }
  return allParsers.find(p => p.logType === logType) || null;
}

/**
 * Get ALL parsers for a specific log type
 * Some log types (like ssh_auth) have multiple parsers for different patterns
 */
export function getParsersForType(logType: LogType): Parser[] {
  if (logType === 'raw' || logType === 'unknown') {
    return [rawParser];
  }
  return allParsers.filter(p => p.logType === logType);
}

/**
 * Try parsing a line with multiple parsers of the same type
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
 * Auto-detect and parse a single line
 * Tries all parsers until one matches
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
 * Parse multiple lines with a specific parser
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
 * Auto-detect log type and parse all lines
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
  const lines = content.split('\n').filter(l => l.trim());
  const detectedType = detectLogType(lines);
  
  let entries: ParsedLogEntry[];
  let parsedCount = 0;
  let failedCount = 0;

  if (detectedType === 'unknown' || detectedType === 'raw') {
    // Auto-parse each line individually
    entries = lines.map(line => {
      const result = autoParseLineSingle(line);
      if (result.logType !== 'raw') {
        parsedCount++;
      } else {
        failedCount++;
      }
      return result;
    });
  } else {
    // Get ALL parsers for this log type (some types like ssh_auth have multiple)
    const parsers = getParsersForType(detectedType);
    entries = [];
    
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      // Try all parsers for this log type
      const parsed = tryParsersForLine(trimmed, parsers);
      if (parsed) {
        entries.push(parsed);
        parsedCount++;
      } else {
        // If none of the type-specific parsers worked, try auto-parsing
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

// Export individual parser groups for direct access
export { databaseParsers, webserverParsers, systemParsers, authParsers, firewallParsers, mailParsers };

// Export dynamic parser utilities
export { dynamicParser, analyzeLogStructureAndSuggestLabels, detectLogTypeFromFields } from './dynamic';
export type { FieldAnalysis, LogStructure } from './dynamic';
