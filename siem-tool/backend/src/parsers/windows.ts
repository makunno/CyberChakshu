// Windows Event Log Parsers
// Supports: Application, System, Security, Setup, Forwarded Events

import { ParsedLogEntry, LogType } from '../types';
import { generateId } from '../utils/helpers';

export class WindowsParsers {

  // Windows Application Log
  // Format: 2026-01-14 18:55:07 Application 1234 INFO ProductName: Event description
  static windowsApplication(line: string): Record<string, any> | null {
    const match = line.match(
      /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+Application\s+(\d+)\s+(INFO|WARNING|ERROR|CRITICAL)(?:\s+(\S[^:]*))?(?::\s*(.+))?$/
    );
    if (!match) return null;
    
    const [, timestamp, eventId, level, source, message] = match;
    
    return {
      timestamp: timestamp.trim(),
      host: 'windows',
      service: 'application',
      event_id: parseInt(eventId),
      level: level.toLowerCase(),
      source: source?.trim(),
      message: message?.trim() || '',
      source_type: 'windows_application'
    };
  }

  // Windows System Log
  // Format: 2026-01-14 18:55:07 System 5678 INFO SourceName: Event description
  static windowsSystem(line: string): Record<string, any> | null {
    const match = line.match(
      /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+System\s+(\d+)\s+(INFO|WARNING|ERROR|CRITICAL)(?:\s+(\S[^:]*))?(?::\s*(.+))?$/
    );
    if (!match) return null;
    
    const [, timestamp, eventId, level, sourceName, message] = match;
    
    return {
      timestamp: timestamp.trim(),
      host: 'windows',
      service: 'system',
      event_id: parseInt(eventId),
      level: level.toLowerCase(),
      source_name: sourceName?.trim(),
      message: message?.trim() || '',
      source_type: 'windows_system'
    };
  }

  // Windows Security Log
  // Format: 2026-01-14 18:55:07 Security 4625 INFO An account failed to log on
  static windowsSecurity(line: string): Record<string, any> | null {
    const match = line.match(
      /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+Security\s+(\d+)\s+(INFO|WARNING|ERROR|CRITICAL)(?:\s+(\S[^:]*))?(?::\s*(.+))?$/
    );
    if (!match) return null;
    
    const [, timestamp, eventId, level, task, message] = match;
    
    return {
      timestamp: timestamp.trim(),
      host: 'windows',
      service: 'security',
      event_id: parseInt(eventId),
      level: level.toLowerCase(),
      task: task?.trim(),
      message: message?.trim() || '',
      source_type: 'windows_security'
    };
  }

  // Windows Setup Log
  // Format: 2026-01-14 18:55:07 Setup 1001 INFO Windows Setup started
  static windowsSetup(line: string): Record<string, any> | null {
    const match = line.match(
      /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+Setup\s+(\d+)\s+(INFO|WARNING|ERROR|CRITICAL)(?:\s+(\S[^:]*))?(?::\s*(.+))?$/
    );
    if (!match) return null;
    
    const [, timestamp, eventId, level, component, message] = match;
    
    return {
      timestamp: timestamp.trim(),
      host: 'windows',
      service: 'setup',
      event_id: parseInt(eventId),
      level: level.toLowerCase(),
      component: component?.trim(),
      message: message?.trim() || '',
      source_type: 'windows_setup'
    };
  }

  // Windows Forwarded Events Log
  // Format: 2026-01-14 18:55:07 ForwardedEvents 9999 INFO Event forwarded from another computer
  static windowsForwarded(line: string): Record<string, any> | null {
    const match = line.match(
      /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+ForwardedEvents\s+(\d+)\s+(INFO|WARNING|ERROR|CRITICAL)(?:\s+(\S[^:]*))?(?::\s*(.+))?$/
    );
    if (!match) return null;
    
    const [, timestamp, eventId, level, originator, message] = match;
    
    return {
      timestamp: timestamp.trim(),
      host: 'windows',
      service: 'forwarded_events',
      event_id: parseInt(eventId),
      level: level.toLowerCase(),
      originator: originator?.trim(),
      message: message?.trim() || '',
      source_type: 'windows_forwarded'
    };
  }

  // Generic Windows Event (fallback)
  static windowsEvent(line: string): Record<string, any> | null {
    const match = line.match(
      /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(\d+)\s+(INFO|WARNING|ERROR|CRITICAL)(?:\s+(\S[^:]*))?(?::\s*(.+))?$/
    );
    if (!match) return null;
    
    const [, timestamp, logName, eventId, level, source, message] = match;
    
    // Skip if it matched a more specific format
    if (['Application', 'System', 'Security', 'Setup', 'ForwardedEvents'].includes(logName)) {
      return null;
    }
    
    return {
      timestamp: timestamp.trim(),
      host: 'windows',
      service: logName.toLowerCase(),
      event_id: parseInt(eventId),
      level: level.toLowerCase(),
      source: source?.trim(),
      message: message?.trim() || '',
      source_type: 'windows_event'
    };
  }
}

// JSON FTP Log Passthrough Handler
// Handles pre-parsed JSON array logs from IIS FTP or similar sources
export class JsonFTPHandler {
  
  static isJsonFTPLogs(content: string): boolean {
    const trimmed = content.trim();
    if (!trimmed.startsWith('[') || !trimmed.endsWith(']')) {
      return false;
    }
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed) && parsed.length > 0) {
        const first = parsed[0];
        return (
          'timestamp' in first &&
          'username' in first &&
          'ip_address' in first &&
          'event_type' in first &&
          'status' in first
        );
      }
      return false;
    } catch {
      return false;
    }
  }
  
  static parseJsonFTPLogs(content: string): ParsedLogEntry[] {
    try {
      const logs = JSON.parse(content.trim());
      if (!Array.isArray(logs)) {
        return [];
      }
      
      return logs.map((entry, index) => {
        const timestamp = entry.timestamp || new Date().toISOString();
        const isSuccess = entry.status === 'OK' || entry.status === 'SUCCESS';
        const severity = isSuccess ? 'info' : 'warning';
        
        return {
          id: generateId(),
          timestamp,
          logType: 'iis_ftp' as LogType,
          severity,
          source: {
            ip: entry.ip_address,
            service: 'iis_ftp'
          },
          user: { name: entry.username },
          action: (entry.event_type || 'UNKNOWN').toLowerCase(),
          outcome: isSuccess ? 'success' : 'failure',
          message: JSON.stringify(entry),
          rawLine: JSON.stringify(entry),
          fields: {
            log_source: entry.log_source || 'iis',
            raw_status: entry.status,
            raw_event_type: entry.event_type,
          },
          tags: ['ftp', 'json', 'iis', isSuccess ? 'success' : 'failure']
        };
      });
    } catch (error) {
      console.error('Failed to parse JSON FTP logs:', error);
      return [];
    }
  }
}
