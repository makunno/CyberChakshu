// Network Service Log Parsers - DHCP, DNS, Proxy
// ISEA-style static parser methods

import { ParsedLogEntry, LogType } from '../types';
import { generateId } from '../utils/helpers';

export class NetworkParsers {

  static dhcp(line: string): Record<string, any> | null {
    const match = line.match(
      /^[A-Z][a-z]{2}\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(?:dhcpd|dhclient)(?:\[\d+\])?:\s+(DHCP(?:REQUEST|ACK|OFFER|Discover|Inform))?\s*(?:for\s+(\d+\.\d+\.\d+\.\d+))?(?:\s+from\s+([0-9A-Fa-f:]+))?(?:\s+\((.+)\))?(.+)?$/
    );
    if (!match) return null;
    
    const [, day, time, requestType, ip, mac, hostname, message] = match;
    const year = new Date().getFullYear();
    const timestamp = `${year}-${day.padStart(2, '0')} ${time}`;
    
    return {
      timestamp,
      host: 'dhcp',
      service: 'dhcp',
      ip,
      mac,
      hostname,
      action: requestType?.toLowerCase() || 'unknown',
      message: message?.trim() || ''
    };
  }

  static dns(line: string): Record<string, any> | null {
    const match = line.match(
      /^(?:(\d{2}-[A-Z][a-z]{2}-\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)|([A-Z][a-z]{2}\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})))\s+(?:queries:|named(?:\[\d+\])?:\s+)?(?:info:\s+)?(?:client\s+(\d+\.\d+\.\d+\.\d+)#(\d+))?\s*(?:\((.+)\))?\s*(?:query:\s+)?(?:(\S+)\s+)?(?:IN\s+(\w+))?(?:\s*\+.*)?(.+)?$/
    );
    if (!match) return null;
    
    let timestamp: string;
    if (match[1]) {
      timestamp = match[1];
    } else {
      const month = match[2];
      const day = (match[3] || '').padStart(2, '0');
      const time = match[4];
      timestamp = `${day}-${month}-${new Date().getFullYear()} ${time}`;
    }
    
    const clientIp = match[5];
    const clientPort = match[6];
    const queryName = match[8];
    const recordType = match[9];
    const message = match[10];
    
    return {
      timestamp,
      host: 'dns',
      service: 'dns',
      client_ip: clientIp,
      client_port: clientPort ? parseInt(clientPort) : null,
      query_name: queryName,
      record_type: recordType,
      message: message?.trim() || ''
    };
  }

  static proxy(line: string): Record<string, any> | null {
    // Try Squid format first
    let match = line.match(
      /(\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\/(\d+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.+))?$/
    );
    if (match) {
      const [, timestamp, clientIp, result, status, method, url, hierarchy, extra] = match;
      return {
        timestamp: NetworkParsers.squidToIso(timestamp),
        host: 'proxy',
        service: 'squid',
        client_ip: clientIp,
        result,
        status: parseInt(status),
        method,
        url,
        hierarchy,
        message: line
      };
    }
    
    // Try common format
    match = line.match(
      /^(\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(\d{2}\/[A-Z][a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)(?:\s+"([^"]+)"\s+"([^"]+)")?$/
    );
    if (match) {
      const [, clientIp, timestamp, method, url, protocol, status, bytesSent, referrer, userAgent] = match;
      return {
        timestamp: NetworkParsers.commonToIso(timestamp),
        host: 'proxy',
        service: 'http_proxy',
        client_ip: clientIp,
        method,
        url,
        protocol,
        status: parseInt(status),
        bytes: parseInt(bytesSent),
        referrer,
        user_agent: userAgent,
        message: line
      };
    }
    
    return null;
  }

  private static squidToIso(timestamp: string): string {
    try {
      const dt = new Date(timestamp.replace('/', '-').replace(' ', 'T'));
      return dt.toISOString();
    } catch {
      return timestamp;
    }
  }

  private static commonToIso(timestamp: string): string {
    try {
      const dt = new Date(timestamp);
      return dt.toISOString();
    } catch {
      return timestamp;
    }
  }
}
