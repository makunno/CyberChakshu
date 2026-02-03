// Log Types supported by the SIEM
export type LogType =
  // Database logs
  | 'mysql_error' | 'mysql_query' | 'mysql_slow'
  | 'postgres_error' | 'postgres_auth' | 'postgres_statement'
  | 'oracle_alert' | 'oracle_listener' | 'oracle_audit'
  | 'sqlserver_error' | 'sqlserver_audit' | 'sqlserver_transaction'
  | 'mongodb_server' | 'mongodb_audit'
  // Web server logs
  | 'apache' | 'nginx' | 'iis'
  | 'django' | 'flask' | 'laravel' | 'rails'
  | 'express' | 'fastapi' | 'gunicorn' | 'uvicorn'
  // System logs (Linux)
  | 'syslog' | 'systemd' | 'kernel' | 'audit' | 'package'
  // SSH/Auth logs
  | 'ssh_auth' | 'pam'
  // Firewall logs
  | 'iptables' | 'ufw' | 'nftables' | 'firewalld'
  | 'windows_firewall' | 'palo_alto' | 'fortigate' | 'cisco_asa' | 'checkpoint'
  | 'aws_vpc_flow' | 'azure_nsg' | 'gcp_vpc'
  // Mail server logs
  | 'postfix' | 'sendmail' | 'exim' | 'dovecot' | 'exchange'
  // Network logs
  | 'dns' | 'dhcp' | 'proxy'
  // FTP logs
  | 'vsftpd' | 'proftpd' | 'iis_ftp'
  // Windows logs
  | 'windows_security' | 'windows_system' | 'windows_application' | 'windows_setup' | 'windows_forwarded'
  | 'windows_event'
  // Daemon logs
  | 'cron' | 'daemon'
  // Unknown
  | 'raw' | 'unknown';

// Parsed log entry with normalized fields
export interface ParsedLogEntry {
  id: string;
  timestamp: string | null;
  logType: LogType;
  severity: 'debug' | 'info' | 'warning' | 'error' | 'critical' | 'unknown';
  source: {
    ip?: string;
    port?: number;
    hostname?: string;
    service?: string;
    pid?: number;
  };
  destination?: {
    ip?: string;
    port?: number;
    hostname?: string;
  };
  user?: {
    name?: string;
    domain?: string;
  };
  action?: string;
  outcome?: 'success' | 'failure' | 'unknown';
  message: string;
  rawLine: string;
  fields: Record<string, string | number | boolean | null>;
  tags: string[];
  attackType?: string;
  attackConfidence?: number;
  mitreTactics?: string[];
  mitreTechniques?: string[];
}

// Detection alert
export interface Alert {
  id: string;
  type: 'bruteforce' | 'password_spray' | 'privilege_escalation' | 'suspicious_activity' | 'anomaly';
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: 'low' | 'medium' | 'high';
  title: string;
  description: string;
  timestamp: string;
  sourceIps: string[];
  targetUsers: string[];
  relatedEvents: string[];
  metadata: Record<string, unknown>;
}

// Parser interface
export interface Parser {
  name: string;
  logType: LogType;
  detect: (line: string) => boolean;
  parse: (line: string) => ParsedLogEntry | null;
}

// API Response types
export interface ParseResponse {
  success: boolean;
  detectedType: LogType;
  totalLines: number;
  parsedLines: number;
  failedLines: number;
  entries: ParsedLogEntry[];
  alerts: Alert[];
  stats: {
    byType: Record<string, number>;
    bySeverity: Record<string, number>;
    byOutcome: Record<string, number>;
    topSources: Array<{ ip: string; count: number }>;
    topUsers: Array<{ user: string; count: number }>;
    timeline: Array<{ time: string; count: number }>;
  };
  mlAttacks?: Array<{
    entry: ParsedLogEntry;
    attack: {
      attackType: string;
      confidence: number;
      mitreTactics: string[];
      mitreTechniques: string[];
    };
  }>;
  mlPredictions?: Array<{
    attackType: string;
    confidence: number;
    probability: number;
    explanation: string[];
    isFalsePositive: boolean;
    falsePositiveReason?: string;
  }>;
  multiLogAnomalies?: Array<{
    logType: string;
    anomalyScore: number;
    isAnomaly: boolean;
    confidence: number;
    detectedAttackTypes: string[];
    featureScores: Record<string, number>;
    explanation: string[];
  }>;
  attackSummary?: {
    totalAttacks: number;
    attackTypes: string[];
    uniqueSources: number;
    riskScore: number;
    multiLogRiskScore?: number;
  };
}
