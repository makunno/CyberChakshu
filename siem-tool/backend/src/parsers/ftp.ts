// FTP Server Log Parsers - VSFTPD, PROFTPD, FileZilla, xferlog
// ISEA-style static parser methods

import { ParsedLogEntry, LogType } from '../types';
import { generateId } from '../utils/helpers';

export class FTPParsers {
  
  static vsftpd(line: string): Record<string, any> | null {
    const match = line.match(
      /^[A-Z][a-z]{2}\s+([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})\s+\[pid\s+(\d+)\](?:\s+\[(.+)\])?\s+(.+)$/
    );
    if (!match) return null;
    
    const [, month, day, time, year, pid, user, message] = match;
    const timestamp = `${year}-${FTPParsers.monthToNum(month)}-${day.padStart(2, '0')} ${time}`;
    
    const result: Record<string, any> = {
      timestamp,
      host: 'localhost',
      service: 'vsftpd',
      pid: parseInt(pid),
      user,
      message
    };
    
    if (message.includes('OK UPLOAD') || message.includes('OK DOWNLOAD')) {
      const fileMatch = message.match(/"(.+)"/);
      const sizeMatch = message.match(/(\d+)\s+bytes/);
      if (fileMatch) result['filename'] = fileMatch[1];
      if (sizeMatch) result['bytes'] = parseInt(sizeMatch[1]);
      result['action'] = message.includes('UPLOAD') ? 'upload' : 'download';
    } else if (message.includes('OK LOGIN')) {
      const clientMatch = message.match(/Client:\s*"(.+)"/);
      if (clientMatch) result['client_ip'] = clientMatch[1];
      result['action'] = 'login';
    } else if (message.includes('FAIL LOGIN') || message.includes('Login incorrect')) {
      const clientMatch = message.match(/Client:\s*"(.+)"/);
      if (clientMatch) result['client_ip'] = clientMatch[1];
      result['action'] = 'login_failed';
      result['outcome'] = 'failure';
    }
    
    return result;
  }

  static proftpd(line: string): Record<string, any> | null {
    const match = line.match(
      /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+\[(\d+)\]:\s+(.+?)\s+\((.+?)\):\s+(.+)$/
    );
    if (!match) return null;
    
    const [, month, day, time, daemon, pid, user, host, message] = match;
    const timestamp = `${new Date().getFullYear()}-${FTPParsers.monthToNum(month)}-${day.padStart(2, '0')} ${time}`;
    
    return {
      timestamp,
      host: daemon,
      service: 'proftpd',
      pid: parseInt(pid),
      user,
      client_ip: host,
      message
    };
  }

  static filezilla(line: string): Record<string, any> | null {
    const match = line.match(
      /^\((\d+)\)(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{1,2}:\d{2}:\d{2})(?:\s+(?:AM|PM))?\s*-\s+(.+?)\s+\(([\d\.]+)\)\s*(?:>\s+)?(\d{3})/
    );
    if (!match) return null;
    
    const [, seqNum, month, day, year, time, user, ip, code] = match;
    const timestamp = `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')} ${time}`;
    
    const result: Record<string, any> = {
      timestamp,
      host: 'filezilla',
      service: 'filezilla',
      user: user !== 'not logged in' ? user : null,
      client_ip: ip,
      message: '',
      fields: {
        seq_num: parseInt(seqNum),
        response_code: code
      }
    };
    
    if (code.startsWith('2')) {
      result['outcome'] = 'success';
    } else if (code.startsWith('4') || code.startsWith('5')) {
      result['outcome'] = 'failure';
    }
    
    return result;
  }

  static xferlog(line: string): Record<string, any> | null {
    const match = line.match(
      /^(\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})\s+(\d+)\s+(\S+)\s+(\d+)\s+([a-z])\s+(\d+)\s+([a-z])\s+([a-z_])\s+(\S+)\s+(\S+)\s+(\d+)\s+(\*?)\s+([a-z])$/
    );
    if (!match) return null;
    
    const [, wday, month, day, time, year, transferId, user, fileSize, bytesReceived, code, completionFlag, filename, direction, serviceName, restartOffset, completionStatus] = match;
    const timestamp = `${year}-${FTPParsers.monthToNum(month)}-${day.padStart(2, '0')} ${time}`;
    
    return {
      timestamp,
      host: 'ftp',
      service: 'xferlog',
      user,
      filename,
      bytes: parseInt(fileSize),
      direction: direction === 'o' ? 'upload' : direction === 'i' ? 'download' : null,
      access_mode: code,
      completion_status: completionStatus === 'c' ? 'complete' : 'incomplete',
      fields: {
        transfer_id: parseInt(transferId),
        bytes_received: parseInt(bytesReceived),
        code,
        service: serviceName,
        restart_offset: parseInt(restartOffset),
        completion_flag: completionFlag
      }
    };
  }

  private static monthToNum(month: string): string {
    const months: Record<string, string> = {
      'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
      'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
      'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
    };
    return months[month] || '01';
  }

  private static convertTo24Hour(timeAmpm: string): string {
    try {
      const dt = new Date(timeAmpm);
      return dt.toTimeString().slice(0, 8);
    } catch {
      return timeAmpm.split(' ')[0];
    }
  }
}
