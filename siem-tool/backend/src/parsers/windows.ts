// Windows Event Log Parsers
// ISEA-style static parser methods

import { ParsedLogEntry, LogType } from '../types';
import { generateId } from '../utils/helpers';

export class WindowsParsers {

  static windowsEvent(line: string): Record<string, any> | null {
    const match = line.match(
      /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})(?:\s+(INFO|WARNING|ERROR|DEBUG))?(?:\s+(\S+))?(?:\s+(\d+))?(?:\s+(.+))?$/
    );
    if (!match) return null;
    
    const [, timestamp, level, source, eventId, message] = match;
    
    return {
      timestamp: timestamp.trim(),
      host: 'windows',
      service: source?.toLowerCase() || 'application',
      event_id: eventId ? parseInt(eventId) : null,
      level: level || 'INFO',
      message: message?.trim() || '',
      source: 'event_log'
    };
  }

  static windowsSecurity(line: string): Record<string, any> | null {
    const match = line.match(
      /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(INFO|WARNING|ERROR)\s+Security\s+(\d+)(?:\s+User:\s*(\S+))?(?:\s+(.+))?$/
    );
    if (!match) return null;
    
    const [, timestamp, level, eventId, user, message] = match;
    
    return {
      timestamp,
      host: 'windows',
      service: 'security',
      event_id: parseInt(eventId),
      user,
      level,
      message: message?.trim() || '',
      source: 'windows_security'
    };
  }

  static windowsApplication(line: string): Record<string, any> | null {
    const match = line.match(
      /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(INFO|WARNING|ERROR)\s+Application\s+(\d+)(?:\s+Product:\s*(\S+))?(?:\s+EventCode:\s*(\d+))?(?:\s+(.+))?$/
    );
    if (!match) return null;
    
    const [, timestamp, level, eventId, product, eventCode, message] = match;
    
    return {
      timestamp,
      host: 'windows',
      service: 'application',
      event_id: parseInt(eventId),
      product,
      event_code: eventCode ? parseInt(eventCode) : null,
      level,
      message: message?.trim() || '',
      source: 'windows_application'
    };
  }

  static windowsSystem(line: string): Record<string, any> | null {
    const match = line.match(
      /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(INFO|WARNING|ERROR)\s+System\s+(\d+)(?:\s+Source:\s*(\S+))?(?:\s+(.+))?$/
    );
    if (!match) return null;
    
    const [, timestamp, level, eventId, sourceName, message] = match;
    
    return {
      timestamp,
      host: 'windows',
      service: 'system',
      event_id: parseInt(eventId),
      source_name: sourceName,
      level,
      message: message?.trim() || '',
      source: 'windows_system'
    };
  }
}
