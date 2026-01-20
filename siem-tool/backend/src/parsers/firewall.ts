// Firewall Log Parsers - iptables, UFW, Windows Firewall, Enterprise firewalls, Cloud firewalls
// Based on ~/ISEA/Tanubhav/Prototype3.py and Prototype4.py

import { Parser, ParsedLogEntry } from '../types';
import { generateId, parseTimestamp } from '../utils/helpers';

// ========== iptables Parser ==========

export const iptablesParser: Parser = {
  name: 'iptables Log',
  logType: 'iptables',
  detect: (line: string) => /kernel:.*IPTABLES-(DROP|ACCEPT):.*SRC=.*DST=.*PROTO=/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:.*IPTABLES-(DROP|ACCEPT):\s+IN=(\S*)\s+OUT=(\S*)\s+.*SRC=(\d+\.\d+\.\d+\.\d+)\s+DST=(\d+\.\d+\.\d+\.\d+).*PROTO=(\w+)/
    );
    if (!match) return null;

    const [, timestamp, host, action, inIface, outIface, srcIp, dstIp, proto] = match;
    
    // Extract ports if TCP/UDP
    const srcPortMatch = line.match(/SPT=(\d+)/);
    const dstPortMatch = line.match(/DPT=(\d+)/);

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'iptables',
      severity: action === 'DROP' ? 'warning' : 'info',
      source: { hostname: host, service: 'iptables', ip: srcIp, port: srcPortMatch ? parseInt(srcPortMatch[1]) : undefined },
      destination: { ip: dstIp, port: dstPortMatch ? parseInt(dstPortMatch[1]) : undefined },
      action: action.toLowerCase(),
      outcome: action === 'ACCEPT' ? 'success' : 'failure',
      message: `${action} ${proto} ${srcIp} -> ${dstIp}`,
      rawLine: line,
      fields: {
        host,
        action,
        in_iface: inIface || null,
        out_iface: outIface || null,
        src_ip: srcIp,
        dst_ip: dstIp,
        protocol: proto,
        src_port: srcPortMatch ? parseInt(srcPortMatch[1]) : null,
        dst_port: dstPortMatch ? parseInt(dstPortMatch[1]) : null,
      },
      tags: ['firewall', 'iptables', 'linux', 'network'],
    };
  },
};

// ========== UFW Parser ==========

export const ufwParser: Parser = {
  name: 'UFW Log',
  logType: 'ufw',
  detect: (line: string) => /\[UFW\s+(ALLOW|BLOCK)\]/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+.*\[UFW\s+(ALLOW|BLOCK)\]\s+IN=(\S*)\s+OUT=(\S*)\s+.*SRC=(\d+\.\d+\.\d+\.\d+)\s+DST=(\d+\.\d+\.\d+\.\d+)/
    );
    if (!match) return null;

    const [, timestamp, host, action, inIface, outIface, srcIp, dstIp] = match;
    
    const protoMatch = line.match(/PROTO=(\w+)/);
    const srcPortMatch = line.match(/SPT=(\d+)/);
    const dstPortMatch = line.match(/DPT=(\d+)/);

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'ufw',
      severity: action === 'BLOCK' ? 'warning' : 'info',
      source: { hostname: host, service: 'ufw', ip: srcIp, port: srcPortMatch ? parseInt(srcPortMatch[1]) : undefined },
      destination: { ip: dstIp, port: dstPortMatch ? parseInt(dstPortMatch[1]) : undefined },
      action: action.toLowerCase(),
      outcome: action === 'ALLOW' ? 'success' : 'failure',
      message: `${action} ${protoMatch?.[1] || ''} ${srcIp} -> ${dstIp}`,
      rawLine: line,
      fields: {
        host,
        action,
        in_iface: inIface || null,
        out_iface: outIface || null,
        src_ip: srcIp,
        dst_ip: dstIp,
        protocol: protoMatch?.[1] || null,
        src_port: srcPortMatch ? parseInt(srcPortMatch[1]) : null,
        dst_port: dstPortMatch ? parseInt(dstPortMatch[1]) : null,
      },
      tags: ['firewall', 'ufw', 'linux', 'network'],
    };
  },
};

// ========== nftables Parser ==========

export const nftablesParser: Parser = {
  name: 'nftables Log',
  logType: 'nftables',
  detect: (line: string) => /kernel:.*nftables:.*rule\s+(accept|drop|reject)/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:.*nftables:\s+rule\s+(accept|drop|reject)\s+.*(tcp|udp|icmp)/i
    );
    if (!match) return null;

    const [, timestamp, host, action, protocol] = match;

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'nftables',
      severity: action === 'drop' || action === 'reject' ? 'warning' : 'info',
      source: { hostname: host, service: 'nftables' },
      action: action.toLowerCase(),
      outcome: action === 'accept' ? 'success' : 'failure',
      message: `nftables ${action} ${protocol}`,
      rawLine: line,
      fields: {
        host,
        action,
        protocol,
      },
      tags: ['firewall', 'nftables', 'linux', 'network'],
    };
  },
};

// ========== firewalld Parser ==========

export const firewalldParser: Parser = {
  name: 'firewalld Log',
  logType: 'firewalld',
  detect: (line: string) => /firewalld:\s+(INFO|WARNING|ERROR):/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+firewalld:\s+(INFO|WARNING|ERROR):\s+(.*)/
    );
    if (!match) return null;

    const [, timestamp, host, level, message] = match;

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'firewalld',
      severity: level === 'ERROR' ? 'error' : level === 'WARNING' ? 'warning' : 'info',
      source: { hostname: host, service: 'firewalld' },
      message,
      rawLine: line,
      fields: {
        host,
        level,
      },
      tags: ['firewall', 'firewalld', 'linux'],
    };
  },
};

// ========== Windows Firewall Parser ==========

export const windowsFirewallParser: Parser = {
  name: 'Windows Firewall Log',
  logType: 'windows_firewall',
  detect: (line: string) => /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(ALLOW|DROP|BLOCK)\s+(TCP|UDP|ICMP)/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(ALLOW|DROP|BLOCK)\s+(TCP|UDP|ICMP)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)/
    );
    if (!match) return null;

    const [, date, time, action, protocol, srcIp, dstIp, srcPort, dstPort] = match;

    return {
      id: generateId(),
      timestamp: parseTimestamp(`${date} ${time}`),
      logType: 'windows_firewall',
      severity: action === 'DROP' || action === 'BLOCK' ? 'warning' : 'info',
      source: { service: 'windows_firewall', ip: srcIp, port: parseInt(srcPort) },
      destination: { ip: dstIp, port: parseInt(dstPort) },
      action: action.toLowerCase(),
      outcome: action === 'ALLOW' ? 'success' : 'failure',
      message: `${action} ${protocol} ${srcIp}:${srcPort} -> ${dstIp}:${dstPort}`,
      rawLine: line,
      fields: {
        date,
        time,
        action,
        protocol,
        src_ip: srcIp,
        dst_ip: dstIp,
        src_port: parseInt(srcPort),
        dst_port: parseInt(dstPort),
      },
      tags: ['firewall', 'windows', 'network'],
    };
  },
};

// ========== Palo Alto Firewall Parser ==========

export const paloAltoParser: Parser = {
  name: 'Palo Alto Firewall Log',
  logType: 'palo_alto',
  detect: (line: string) => /^\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s+(allow|deny|drop)\s+(tcp|udp|icmp)/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\d{4}\/\d{2}\/\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(allow|deny|drop)\s+(tcp|udp|icmp)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+rule=(\S+)/
    );
    if (!match) return null;

    const [, date, time, action, protocol, srcIp, dstIp, rule] = match;

    return {
      id: generateId(),
      timestamp: parseTimestamp(`${date.replace(/\//g, '-')} ${time}`),
      logType: 'palo_alto',
      severity: action === 'deny' || action === 'drop' ? 'warning' : 'info',
      source: { service: 'palo_alto', ip: srcIp },
      destination: { ip: dstIp },
      action,
      outcome: action === 'allow' ? 'success' : 'failure',
      message: `${action} ${protocol} ${srcIp} -> ${dstIp} (rule: ${rule})`,
      rawLine: line,
      fields: {
        date,
        time,
        action,
        protocol,
        src_ip: srcIp,
        dst_ip: dstIp,
        rule,
      },
      tags: ['firewall', 'palo_alto', 'enterprise', 'network'],
    };
  },
};

// ========== FortiGate Firewall Parser ==========

export const fortigateParser: Parser = {
  name: 'FortiGate Firewall Log',
  logType: 'fortigate',
  detect: (line: string) => /^date=\d{4}-\d{2}-\d{2}\s+time=\d{2}:\d{2}:\d{2}\s+.*action=(allow|deny)/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const dateMatch = line.match(/date=(\d{4}-\d{2}-\d{2})/);
    const timeMatch = line.match(/time=(\d{2}:\d{2}:\d{2})/);
    const actionMatch = line.match(/action=(allow|deny)/);
    const srcIpMatch = line.match(/srcip=(\d+\.\d+\.\d+\.\d+)/);
    const dstIpMatch = line.match(/dstip=(\d+\.\d+\.\d+\.\d+)/);
    const srcPortMatch = line.match(/srcport=(\d+)/);
    const dstPortMatch = line.match(/dstport=(\d+)/);
    const protoMatch = line.match(/proto=(\d+)/);

    if (!dateMatch || !actionMatch) return null;

    const action = actionMatch[1];

    return {
      id: generateId(),
      timestamp: parseTimestamp(`${dateMatch[1]} ${timeMatch?.[1] || '00:00:00'}`),
      logType: 'fortigate',
      severity: action === 'deny' ? 'warning' : 'info',
      source: { 
        service: 'fortigate', 
        ip: srcIpMatch?.[1], 
        port: srcPortMatch ? parseInt(srcPortMatch[1]) : undefined 
      },
      destination: { 
        ip: dstIpMatch?.[1], 
        port: dstPortMatch ? parseInt(dstPortMatch[1]) : undefined 
      },
      action,
      outcome: action === 'allow' ? 'success' : 'failure',
      message: `${action} ${srcIpMatch?.[1]} -> ${dstIpMatch?.[1]}`,
      rawLine: line,
      fields: {
        date: dateMatch[1],
        time: timeMatch?.[1] || null,
        action,
        src_ip: srcIpMatch?.[1] || null,
        dst_ip: dstIpMatch?.[1] || null,
        src_port: srcPortMatch ? parseInt(srcPortMatch[1]) : null,
        dst_port: dstPortMatch ? parseInt(dstPortMatch[1]) : null,
        protocol: protoMatch?.[1] || null,
      },
      tags: ['firewall', 'fortigate', 'enterprise', 'network'],
    };
  },
};

// ========== Cisco ASA Parser ==========

export const ciscoAsaParser: Parser = {
  name: 'Cisco ASA Firewall Log',
  logType: 'cisco_asa',
  detect: (line: string) => /%ASA-\d-\d+:/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+%ASA-(\d)-(\d+):\s+access-list\s+(\S+)\s+(denied|permitted)\s+(tcp|udp|icmp)\s+\S+\/(\d+\.\d+\.\d+\.\d+)(?:\((\d+)\))?\s+.*?(\d+\.\d+\.\d+\.\d+)(?:\((\d+)\))?/
    );
    if (!match) return null;

    const [, timestamp, host, severity, msgId, acl, action, protocol, srcIp, srcPort, dstIp, dstPort] = match;

    return {
      id: generateId(),
      timestamp: parseTimestamp(timestamp),
      logType: 'cisco_asa',
      severity: action === 'denied' ? 'warning' : 'info',
      source: { 
        hostname: host, 
        service: 'cisco_asa', 
        ip: srcIp, 
        port: srcPort ? parseInt(srcPort) : undefined 
      },
      destination: { 
        ip: dstIp, 
        port: dstPort ? parseInt(dstPort) : undefined 
      },
      action: action === 'permitted' ? 'allow' : 'deny',
      outcome: action === 'permitted' ? 'success' : 'failure',
      message: `${action} ${protocol} ${srcIp} -> ${dstIp}`,
      rawLine: line,
      fields: {
        host,
        asa_severity: parseInt(severity),
        message_id: parseInt(msgId),
        acl,
        action,
        protocol,
        src_ip: srcIp,
        dst_ip: dstIp,
        src_port: srcPort ? parseInt(srcPort) : null,
        dst_port: dstPort ? parseInt(dstPort) : null,
      },
      tags: ['firewall', 'cisco_asa', 'enterprise', 'network'],
    };
  },
};

// ========== Check Point Firewall Parser ==========

export const checkpointParser: Parser = {
  name: 'Check Point Firewall Log',
  logType: 'checkpoint',
  detect: (line: string) => /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(accept|drop|reject)\s+(TCP|UDP|ICMP)\s+src=/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(accept|drop|reject)\s+(TCP|UDP|ICMP)\s+src=(\d+\.\d+\.\d+\.\d+)\s+dst=(\d+\.\d+\.\d+\.\d+)\s+rule=(\S+)/
    );
    if (!match) return null;

    const [, date, time, action, protocol, srcIp, dstIp, rule] = match;

    return {
      id: generateId(),
      timestamp: parseTimestamp(`${date} ${time}`),
      logType: 'checkpoint',
      severity: action === 'drop' || action === 'reject' ? 'warning' : 'info',
      source: { service: 'checkpoint', ip: srcIp },
      destination: { ip: dstIp },
      action,
      outcome: action === 'accept' ? 'success' : 'failure',
      message: `${action} ${protocol} ${srcIp} -> ${dstIp} (rule: ${rule})`,
      rawLine: line,
      fields: {
        date,
        time,
        action,
        protocol,
        src_ip: srcIp,
        dst_ip: dstIp,
        rule,
      },
      tags: ['firewall', 'checkpoint', 'enterprise', 'network'],
    };
  },
};

// ========== AWS VPC Flow Logs Parser ==========

export const awsVpcFlowParser: Parser = {
  name: 'AWS VPC Flow Logs',
  logType: 'aws_vpc_flow',
  detect: (line: string) => /^\d+\s+\d+\s+eni-\S+\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(ACCEPT|REJECT)/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\d+)\s+(\d+)\s+(eni-\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(ACCEPT|REJECT)\s+(\S+)/
    );
    if (!match) return null;

    const [, version, accountId, interfaceId, srcIp, dstIp, srcPort, dstPort, protocol, packets, bytes, startTime, endTime, action, status] = match;

    // Convert epoch to ISO timestamp
    const timestamp = new Date(parseInt(startTime) * 1000).toISOString();

    return {
      id: generateId(),
      timestamp,
      logType: 'aws_vpc_flow',
      severity: action === 'REJECT' ? 'warning' : 'info',
      source: { service: 'aws_vpc', ip: srcIp, port: parseInt(srcPort) },
      destination: { ip: dstIp, port: parseInt(dstPort) },
      action: action.toLowerCase(),
      outcome: action === 'ACCEPT' ? 'success' : 'failure',
      message: `${action} ${srcIp}:${srcPort} -> ${dstIp}:${dstPort}`,
      rawLine: line,
      fields: {
        version: parseInt(version),
        account_id: accountId,
        interface_id: interfaceId,
        src_ip: srcIp,
        dst_ip: dstIp,
        src_port: parseInt(srcPort),
        dst_port: parseInt(dstPort),
        protocol: parseInt(protocol),
        packets: parseInt(packets),
        bytes: parseInt(bytes),
        start_time: parseInt(startTime),
        end_time: parseInt(endTime),
        action,
        status,
      },
      tags: ['firewall', 'aws', 'vpc', 'cloud', 'network'],
    };
  },
};

// ========== Azure NSG Flow Logs Parser ==========

export const azureNsgParser: Parser = {
  name: 'Azure NSG Flow Logs',
  logType: 'azure_nsg',
  detect: (line: string) => {
    try {
      const j = JSON.parse(line);
      return j.time && j.properties && j.properties.flows;
    } catch {
      return false;
    }
  },
  parse: (line: string): ParsedLogEntry | null => {
    try {
      const j = JSON.parse(line);
      
      return {
        id: generateId(),
        timestamp: j.time,
        logType: 'azure_nsg',
        severity: 'info',
        source: { service: 'azure_nsg' },
        message: 'Azure NSG Flow Log',
        rawLine: line,
        fields: { ...j },
        tags: ['firewall', 'azure', 'nsg', 'cloud', 'network'],
      };
    } catch {
      return null;
    }
  },
};

// ========== GCP VPC Firewall Parser ==========

export const gcpVpcParser: Parser = {
  name: 'GCP VPC Firewall Log',
  logType: 'gcp_vpc',
  detect: (line: string) => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\s+(allow|deny)\s+(tcp|udp|icmp)/.test(line),
  parse: (line: string): ParsedLogEntry | null => {
    const match = line.match(
      /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+(allow|deny)\s+(tcp|udp|icmp)\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\d+\.\d+\.\d+\.\d+):(\d+)/
    );
    if (!match) return null;

    const [, timestamp, action, protocol, srcIp, srcPort, dstIp, dstPort] = match;

    return {
      id: generateId(),
      timestamp,
      logType: 'gcp_vpc',
      severity: action === 'deny' ? 'warning' : 'info',
      source: { service: 'gcp_vpc', ip: srcIp, port: parseInt(srcPort) },
      destination: { ip: dstIp, port: parseInt(dstPort) },
      action,
      outcome: action === 'allow' ? 'success' : 'failure',
      message: `${action} ${protocol} ${srcIp}:${srcPort} -> ${dstIp}:${dstPort}`,
      rawLine: line,
      fields: {
        timestamp,
        action,
        protocol,
        src_ip: srcIp,
        dst_ip: dstIp,
        src_port: parseInt(srcPort),
        dst_port: parseInt(dstPort),
      },
      tags: ['firewall', 'gcp', 'cloud', 'network'],
    };
  },
};

// Export all firewall parsers
export const firewallParsers: Parser[] = [
  iptablesParser,
  ufwParser,
  nftablesParser,
  firewalldParser,
  windowsFirewallParser,
  paloAltoParser,
  fortigateParser,
  ciscoAsaParser,
  checkpointParser,
  awsVpcFlowParser,
  azureNsgParser,
  gcpVpcParser,
];
