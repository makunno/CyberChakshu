// LogParsers - ISEA-style static parser methods returning simple structures

import { ParsedLogEntry, LogType } from '../types';
import { generateId } from '../utils/helpers';

export class LogParsers {

  static apache(line: string): Record<string, any> | null {
    const match = line.match(/(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)/);
    if (!match) return null;
    
    const [, ip, timestamp, request, status, bytes] = match;
    return { ip, timestamp, request, status: parseInt(status), bytes: parseInt(bytes) };
  }

  static nginx(line: string): Record<string, any> | null {
    const match = line.match(/(\S+) - (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+)/);
    if (!match) return null;
    
    const [, ip, user, timestamp, request, status, bytes] = match;
    return { ip, user: user === '-' ? null : user, timestamp, request, status: parseInt(status), bytes: parseInt(bytes) };
  }

  static sshdFailed(line: string): Record<string, any> | null {
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[(\d+)\]:\s+Failed\s+(\w+)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(\d+)/
    );
    if (!match) return null;

    const [, timestamp, host, pid, method, user, ip, port] = match;
    return {
      timestamp,
      host,
      pid: parseInt(pid),
      auth_method: method,
      user,
      ip,
      port: parseInt(port)
    };
  }

  static sshdAccepted(line: string): Record<string, any> | null {
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[(\d+)\]:\s+Accepted\s+(\w+)\s+for\s+(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(\d+)/
    );
    if (!match) return null;

    const [, timestamp, host, pid, method, user, ip, port] = match;
    return {
      timestamp,
      host,
      pid: parseInt(pid),
      auth_method: method,
      user,
      ip,
      port: parseInt(port)
    };
  }

  static postfix(line: string): Record<string, any> | null {
    const match = line.match(
      /^[A-Z][a-z]{2}\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+postfix\/(smtpd|smtp|cleanup|qmgr)\[(\d+)\]:\s+(.+)$/
    );
    if (!match) return null;
    
    const [, date, time, host, service, pid, message] = match;
    return { 
      timestamp: `${date} ${time}`, 
      host, 
      service: `postfix/${service}`, 
      pid: parseInt(pid), 
      message 
    };
  }

  static iptables(line: string): Record<string, any> | null {
    const match = line.match(
      /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:\s+IPTABLES-(DROP|ACCEPT):\s+IN=(\S*)\s+OUT=(\S*)\s+.*SRC=(\d+\.\d+\.\d+\.\d+)\s+DST=(\d+\.\d+\.\d+\.\d+).*PROTO=(TCP|UDP|ICMP).*$/
    );
    if (!match) return null;
    
    const [, timestamp, host, action, inIface, outIface, srcIp, dstIp, proto] = match;
    return { 
      timestamp, 
      host, 
      action: action.toLowerCase(), 
      in_iface: inIface || '-', 
      out_iface: outIface || '-', 
      src_ip: srcIp, 
      dst_ip: dstIp, 
      protocol: proto 
    };
  }

  static mysqlError(line: string): Record<string, any> | null {
    const match = line.match(/(\S+Z)\s+(\d+)\s+\[ERROR\]\s+\[MY-(\d+)\]\s+\[Server\]\s+(.*)/);
    if (!match) return null;
    
    const [, timestamp, threadId, errorCode, errorMessage] = match;
    return { 
      timestamp, 
      thread_id: parseInt(threadId), 
      error_level: 'ERROR', 
      error_code: errorCode, 
      component: 'Server', 
      error_message: errorMessage 
    };
  }

  static mysqlQuery(line: string): Record<string, any> | null {
    const match = line.match(/(\S+Z)\s+(\d+)\s+Query\s+(.*);/);
    if (!match) return null;
    
    const [, timestamp, threadId, sqlStatement] = match;
    return { timestamp, thread_id: parseInt(threadId), sql_statement: sqlStatement };
  }

  static mysqlSlow(block: string): Record<string, any> | null {
    const timeMatch = block.match(/# Time: (\S+)/);
    const userMatch = block.match(/# User@Host: (\w+)\[\w+\] @ (\S+) \[(.*?)\]/);
    const queryMatch = block.match(/# Query_time: ([\d.]+).*Rows_examined: (\d+)/);
    const sqlMatch = block.match(/\n(SELECT.*);/);

    if (!timeMatch || !userMatch || !queryMatch || !sqlMatch) return null;

    return {
      timestamp: timeMatch[1],
      user: userMatch[1],
      host: userMatch[2],
      ip: userMatch[3],
      query_time: parseFloat(queryMatch[1]),
      rows_examined: parseInt(queryMatch[2]),
      sql_statement: sqlMatch[1].trim()
    };
  }

  static postgresError(line: string): Record<string, any> | null {
    const match = line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\w+)\s+\[(\d+)\]\s+(?:\S+@\S+\s+)?(ERROR|FATAL):\s+([0-9A-Z]{5}):\s+(.*)$/);
    if (!match) return null;
    
    const [, timestamp, timezone, pid, level, code, message] = match;
    return { timestamp, timezone, pid: parseInt(pid), level, code, message };
  }

  static postgresAuth(line: string): Record<string, any> | null {
    const match = line.match(/(\S+)\s+(\S+)\s+\[(\d+)\].*user=(\w+)\s+database=(\w+)/);
    if (!match) return null;
    
    const [, timestamp, timezone, pid, user, database] = match;
    return { timestamp, timezone, pid: parseInt(pid), user, database };
  }

  static postgresStatement(line: string): Record<string, any> | null {
    const match = line.match(/(\S+)\s+(\S+)\s+\[(\d+)\]\s+STATEMENT:\s+(.*);/);
    if (!match) return null;
    
    const [, timestamp, timezone, pid, sqlStatement] = match;
    return { timestamp, timezone, pid: parseInt(pid), sql_statement: sqlStatement };
  }

  static filezilla(line: string): Record<string, any> | null {
    const match = line.match(
      /\(\d+\)(\d{1,2}\/\d{1,2}\/\d{4})\s+(\d{2}:\d{2}:\d{2})\s+-\s+(\S+)\s+\(([\d\.]+)\)>\s+(\d+)\s+(.*)/
    );
    if (!match) return null;
    
    const [, date, time, user, ip, code, message] = match;
    return { timestamp: `${date} ${time}`, username: user, ip_address: ip, code: parseInt(code), message };
  }

  static iisFtp(line: string): Record<string, any> | null {
    if (line.startsWith('#')) return null;
    
    const match = line.match(
      /(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+([\d\.]+)\s+([\w\-]+)\s+[\d\.]+\s+\d+\s+(\w+)\s+([\S]*)\s+(\d+)/
    );
    if (!match) return null;
    
    const [, date, time, ip, user, command, file, code] = match;
    return { timestamp: `${date} ${time}`, ip_address: ip, username: user, command, file, code: parseInt(code) };
  }

  static xferlog(line: string): Record<string, any> | null {
    const match = line.match(
      /(\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})\s+\d+\s+([\d\.]+)\s+\d+\s+(\S+)\s+[ab]\s+[_]\s+([io])\s+[ra]\s+(\S+)\s+\w+\s+[01]\s+\*\s+([ci])/
    );
    if (!match) return null;
    
    const [, day, month, date, time, year, ip, file, direction, user, status] = match;
    return { 
      timestamp: `${day} ${month} ${date} ${time} ${year}`, 
      ip_address: ip, 
      file, 
      direction, 
      username: user, 
      status 
    };
  }

  static syslog(line: string): Record<string, any> | null {
    const match = line.match(/(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w\-\/]+)\[(\d+)\]:\s+(.*)/);
    if (!match) return null;

    const [, timestamp, host, service, pid, message] = match;
    return { timestamp, host, service, pid: parseInt(pid), message };
  }

  static systemd(line: string): Record<string, any> | null {
    const match = line.match(/(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+systemd\[(\d+)\]:\s+(.*)/);
    if (!match) return null;

    const [, timestamp, host, pid, message] = match;
    return { timestamp, host, service: 'systemd', pid: parseInt(pid), message };
  }

  static kernel(line: string): Record<string, any> | null {
    const match = line.match(/(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:\s+(.*)/);
    if (!match) return null;

    const [, timestamp, host, message] = match;
    return { timestamp, host, service: 'kernel', pid: null, message };
  }

  static audit(line: string): Record<string, any> | null {
    const match = line.match(/type=(\w+)\s+msg=audit\((\d+)\.\d+:(\d+)\):\s*(.*)/);
    if (!match) return null;

    const [, eventType, epoch, eventId, rest] = match;
    return {
      timestamp: new Date(parseInt(epoch) * 1000).toISOString(),
      event_type: eventType,
      epoch: parseInt(epoch),
      event_id: parseInt(eventId),
      message: rest
    };
  }

  static fastapiJson(line: string): Record<string, any> | null {
    try {
      const obj = JSON.parse(line);
      if (obj.framework === "FastAPI" && obj.method && obj.path) {
        return {
          timestamp: obj.time,
          framework: obj.framework,
          method: obj.method,
          path: obj.path,
          status: obj.status,
          latency_ms: obj.latency_ms,
          ip: obj.ip
        };
      }
      return null;
    } catch {
      return null;
    }
  }

  static phpFpm(line: string): Record<string, any> | null {
    const match = line.match(/\[(\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2})\]\s+(NOTICE|WARNING|ERROR):\s+(.*)/);
    if (!match) return null;

    const [, timestamp, level, message] = match;
    return { timestamp, level, message };
  }

  static haproxy(line: string): Record<string, any> | null {
    const match = line.match(/^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+haproxy\[\d+\]:\s+(GET|POST|PUT|DELETE)\s+(\S+)\s+(\d{3})$/);
    if (!match) return null;

    const [, method, path, status] = match;
    return { timestamp: null, method, path, status: parseInt(status) };
  }

  static springBoot(line: string): Record<string, any> | null {
    const match = line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+(INFO|WARN|ERROR|DEBUG)\s+(\S+)\s+-\s+(GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s+(\d{3})$/);
    if (!match) return null;

    const [, timestamp, level, logger, method, path, status] = match;
    return { timestamp, level, logger, method, path, status: parseInt(status) };
  }

  static aspnetCore(line: string): Record<string, any> | null {
    const match = line.match(/^(info|warn|error|debug):\s+Microsoft\.AspNetCore.*\[\d+\]\s+(GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s+responded\s+(\d{3})$/i);
    if (!match) return null;

    const [, level, method, path, status] = match;
    return { level: level.toLowerCase(), method, path, status: parseInt(status) };
  }

  static courier(line: string): Record<string, any> | null {
    const match = line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+courier(?:imap|pop3):\s+(LOGIN|LOGOUT),\s+user=(\S+)(?:.*port=(\d+))?/);
    if (!match) return null;

    const [, timestamp, host, action, user, port] = match;
    return { timestamp, host, service: 'courier', action, user, port: port ? parseInt(port) : null };
  }

  static amavis(line: string): Record<string, any> | null {
    const match = line.match(/^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+amavis\[\d+\]:\s+(.*)/);
    if (!match) return null;

    const [, host, message] = match;
    return { timestamp: null, host, service: 'amavis', message };
  }

  static spamassassin(line: string): Record<string, any> | null {
    const match = line.match(/^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+spamd\[\d+\]:\s+(.*)/);
    if (!match) return null;

    const [, host, message] = match;
    return { timestamp: null, host, service: 'spamd', message };
  }

  static mailscanner(line: string): Record<string, any> | null {
    const match = line.match(/^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+MailScanner\[\d+\]:\s+(.*)/);
    if (!match) return null;

    const [, host, message] = match;
    return { timestamp: null, host, service: 'MailScanner', message };
  }

  static macosPf(line: string): Record<string, any> | null {
    const match = line.match(/^(\d{2}:\d{2}:\d{2}\.\d+)\s+rule\s+(\d+\/\d+)\((?:match)\):\s+(block|pass)\s+(in|out)\s+on\s+(\S+):\s+(\d{1,3}(?:\.\d{1,3}){3}\.\d+)\s+>\s+(\d{1,3}(?:\.\d{1,3}){3}\.\d+)/);
    if (!match) return null;

    const [, timestamp, rule, action, direction, iface, src, dst] = match;
    return { timestamp, rule, action, direction, iface, src, dst };
  }

  static macosAppFw(line: string): Record<string, any> | null {
    const match = line.match(/^Firewall:\s+(Blocked|Allowed)\s+(incoming|outgoing)\s+connection from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+to\s+app\s+(\S+)/);
    if (!match) return null;

    const [, action, direction, ip, app] = match;
    return { timestamp: null, action: action.toLowerCase(), direction, ip, app };
  }

  static linuxPackage(line: string): Record<string, any> | null {
    const match = line.match(/(\d{4}-\d{2}-\d{2})\s+(.*)/);
    if (!match) return null;

    const [, date, message] = match;
    return { timestamp: date, message };
  }

  static oracleAlert(line: string): Record<string, any> | null {
    const match = line.match(/^[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}/);
    if (!match) return null;

    return { timestamp: null, message: line };
  }

  static oracleListener(line: string): Record<string, any> | null {
    const match = line.match(/(.*?)\s+\*.*SERVICE_NAME=(\w+).*PROTOCOL=(\w+).*HOST=(\d+\.\d+\.\d+\.\d+).*PORT=(\d+).*\*\s+(\d+)/);
    if (!match) return null;

    const [, message, serviceName, protocol, host, port, pid] = match;
    return { timestamp: null, service_name: serviceName, protocol, host, port: parseInt(port), pid: parseInt(pid), message };
  }

  static oracleAudit(line: string): Record<string, any> | null {
    if (!line.startsWith("Audit record generated")) return null;
    return { timestamp: null, message: line };
  }

  static raw(line: string): Record<string, any> {
    return { timestamp: null, host: null, service: null, pid: null, message: line };
  }
}
