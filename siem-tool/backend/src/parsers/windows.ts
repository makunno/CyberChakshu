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

  // Windows Event Viewer TXT Export Format
  // Format: Audit Success\t04-02-2026 09:45:33\tMicrosoft-Windows-Security-Auditing\t4798\tUser Account Management\t"Description..."
  // Note: Tab-separated with keywords first, date in DD-MM-YYYY format
  static windowsEventViewerTXT(line: string): Record<string, any> | null {
    // Skip header line
    if (line.startsWith('Keywords\t') || line.startsWith('Keywords,')) {
      return null;
    }
    
    // Try tab-separated format
    const parts = line.split('\t');
    
    if (parts.length >= 5) {
      const keywords = parts[0].trim();
      const dateTime = parts[1].trim();
      const source = parts[2].trim();
      const eventId = parts[3].trim();
      const taskCategory = parts[4].trim();
      // Parse description - handle multi-line format
      let descMessage = parts[5] || '';
      // For multi-line events, the description might be followed by additional details
      // The full message should include all tab-separated parts after the 5th field
      if (parts.length > 6) {
        descMessage = parts.slice(5).join('\t').trim();
      }
      // Clean up quotes
      descMessage = descMessage.replace(/^"|"$/g, '').trim();
      
      // Parse date in DD-MM-YYYY HH:MM:SS format
      const dateMatch = dateTime.match(/(\d{2})-(\d{2})-(\d{4})\s+(\d{2}:\d{2}:\d{2})/);
      let timestamp = dateTime;
      if (dateMatch) {
        // Convert DD-MM-YYYY to YYYY-MM-DD
        timestamp = `${dateMatch[3]}-${dateMatch[1]}-${dateMatch[2]}T${dateMatch[4]}`;
      }
      
      // Determine level from keywords
      let level = 'info';
      if (keywords.includes('Failure') || keywords.includes('Error')) {
        level = 'error';
      } else if (keywords.includes('Warning')) {
        level = 'warning';
      } else if (keywords.includes('Success')) {
        level = 'info';
      }
      
      // Determine service from source
      let service = 'event';
      if (source.includes('Security')) {
        service = 'security';
      } else if (source.includes('System')) {
        service = 'system';
      } else if (source.includes('Application')) {
        service = 'application';
      }
      
        // Extract username from description (handle multi-line format)
        let username = '';
        // First try single-line format
        let userMatch = descMessage.match(/Account Name:\s+(\S+)/);
        if (userMatch) {
          username = userMatch[1];
        }
        // For multi-line format, try to find Account Name in the full message
        if (!username && line.includes('Account Name:')) {
          const fullMatch = line.match(/Account Name:\s+(\S+)/);
          if (fullMatch) {
            username = fullMatch[1];
          }
        }
        
        // Extract IP address from description
        let ipAddress = '';
        const ipMatch = descMessage.match(/Source:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
        if (ipMatch) {
          ipAddress = ipMatch[1];
        }
        
        // For multi-line format, try to find IP in full line
        if (!ipAddress && line.includes('Source:')) {
          const fullIpMatch = line.match(/Source:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
          if (fullIpMatch) {
            ipAddress = fullIpMatch[1];
          }
        }
      
      return {
        timestamp,
        host: 'windows',
        service,
        event_id: parseInt(eventId),
        level,
        source,
        taskCategory,
        message: descMessage,
        keywords,
        source_type: 'windows_event_viewer',
        user: username ? { name: username } : undefined,
        fields: {
          username,
          ip_address: ipAddress,
          taskCategory,
          keywords,
          event_id: parseInt(eventId)
        }
      };
    }
    
    // Try comma-separated format as fallback
    const commaParts = line.split(',');
    if (commaParts.length >= 5) {
      const keywords = commaParts[0].trim();
      const dateTime = commaParts[1].trim();
      const source = commaParts[2].trim();
      const eventId = commaParts[3].trim();
      const taskCategory = commaParts[4].trim();
      let descMessage = commaParts.slice(5).join(',').replace(/^"|"$/g, '').trim();
      
      const dateMatch = dateTime.match(/(\d{2})-(\d{2})-(\d{4})\s+(\d{2}:\d{2}:\d{2})/);
      let timestamp = dateTime;
      if (dateMatch) {
        timestamp = `${dateMatch[3]}-${dateMatch[1]}-${dateMatch[2]}T${dateMatch[4]}`;
      }
      
      let level = 'info';
      if (keywords.includes('Failure') || keywords.includes('Error')) {
        level = 'error';
      } else if (keywords.includes('Warning')) {
        level = 'warning';
      } else if (keywords.includes('Success')) {
        level = 'info';
      }
      
      let service = 'event';
      if (source.includes('Security')) {
        service = 'security';
      } else if (source.includes('System')) {
        service = 'system';
      } else if (source.includes('Application')) {
        service = 'application';
      }
      
      let username = '';
      const userMatch = descMessage.match(/Account Name:\s+(\S+)/);
      if (userMatch) {
        username = userMatch[1];
      }
      
      return {
        timestamp,
        host: 'windows',
        service,
        event_id: parseInt(eventId),
        level,
        source,
        taskCategory,
        message: descMessage,
        keywords,
        source_type: 'windows_event_viewer',
        user: username ? { name: username } : undefined,
        fields: {
          username,
          taskCategory,
          keywords,
          event_id: parseInt(eventId)
        }
      };
    }
    
    return null;
  }

  // Windows Application Log TXT Export Format
  // Format: Level\tDate and Time\tSource\tEvent ID\tTask Category\tMessage
  // Example: Information\t04-02-2026 11:51:42\tSecurityCenter\t15\tNone\tUpdated Windows Defender status successfully...
  static windowsApplicationTXT(line: string): Record<string, any> | null {
    // Skip header line
    if (line.startsWith('Level\t') || line.startsWith('Level,')) {
      return null;
    }

    // Try tab-separated format first
    if (line.includes('\t')) {
      const parts = line.split('\t');
      if (parts.length >= 5) {
        const level = parts[0].trim();
        const dateTime = parts[1].trim();
        const source = parts[2].trim();
        const eventId = parts[3].trim();
        const taskCategory = parts[4].trim();
        let message = parts.slice(5).join('\t').trim();
        message = message.replace(/^"|"$/g, '').trim();

        const dateMatch = dateTime.match(/(\d{2})-(\d{2})-(\d{4})\s+(\d{2}:\d{2}:\d{2})/);
        let timestamp = dateTime;
        if (dateMatch) {
          timestamp = `${dateMatch[3]}-${dateMatch[1]}-${dateMatch[2]}T${dateMatch[4]}`;
        }

        let severity = 'info';
        if (level.toLowerCase() === 'error' || level.toLowerCase() === 'critical') {
          severity = 'error';
        } else if (level.toLowerCase() === 'warning') {
          severity = 'warning';
        }

        let service = 'application';
        const lowerSource = source.toLowerCase();
        if (lowerSource.includes('security')) {
          service = 'security';
        } else if (lowerSource.includes('system')) {
          service = 'system';
        }

        return {
          timestamp,
          host: 'windows',
          service,
          event_id: parseInt(eventId),
          level: level.toLowerCase(),
          source,
          taskCategory,
          message,
          keywords: level,
          source_type: 'windows_application_txt',
          fields: {
            event_id: parseInt(eventId),
            level: level,
            task_category: taskCategory,
            keywords: level,
          }
        };
      }
    }

    // Try comma-separated format (CSV)
    const levelMatch = line.match(/^(Information|Warning|Error|Critical),/);
    if (levelMatch) {
      const parts = line.split(',');
      if (parts.length >= 5) {
        const level = parts[0].trim();
        const dateTime = parts[1].trim();
        const source = parts[2].trim();
        const eventId = parts[3].trim();
        const taskCategory = parts[4].trim();
        // For CSV, message is everything after taskCategory (comma-separated values may include commas in quoted message)
        let message = parts.slice(5).join(',');
        // Clean up quotes at start/end
        message = message.replace(/^"/, '').replace(/"$/, '').trim();

        const dateMatch = dateTime.match(/(\d{2})-(\d{2})-(\d{4})\s+(\d{2}:\d{2}:\d{2})/);
        let timestamp = dateTime;
        if (dateMatch) {
          timestamp = `${dateMatch[3]}-${dateMatch[1]}-${dateMatch[2]}T${dateMatch[4]}`;
        }

        let severity = 'info';
        if (level.toLowerCase() === 'error' || level.toLowerCase() === 'critical') {
          severity = 'error';
        } else if (level.toLowerCase() === 'warning') {
          severity = 'warning';
        }

        let service = 'application';
        const lowerSource = source.toLowerCase();
        if (lowerSource.includes('security')) {
          service = 'security';
        } else if (lowerSource.includes('system')) {
          service = 'system';
        }

        return {
          timestamp,
          host: 'windows',
          service,
          event_id: parseInt(eventId),
          level: level.toLowerCase(),
          source,
          taskCategory,
          message,
          keywords: level,
          source_type: 'windows_application_csv',
          fields: {
            event_id: parseInt(eventId),
            level: level,
            task_category: taskCategory,
            keywords: level,
          }
        };
      }
    }

    return null;
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
