// Type Mapping - Maps ISEA-style type names to FreeKhana LogType enum

import { LogType } from '../types';

export const TYPE_MAPPING: Record<string, LogType> = {
  // Web Server
  'Apache': 'apache',
  'NGINX': 'nginx',
  'IIS': 'iis',
  'Django': 'django',
  'Flask': 'flask',
  'Laravel': 'laravel',
  'Ruby on Rails': 'rails',
  'Node.js': 'express',
  'Express.js': 'express',
  'Gunicorn': 'gunicorn',
  'Uvicorn': 'uvicorn',
  'PHP-FPM': 'apache',
  'Caddy': 'apache',
  'HAProxy': 'apache',
  'Spring Boot': 'apache',
  'ASP.NET Core': 'iis',
  'Apache Error': 'apache',

  // SSH/Auth
  'Linux SSHD Failed': 'ssh_auth',
  'Linux SSHD Accepted': 'ssh_auth',

  // Mail
  'Postfix': 'postfix',
  'Sendmail': 'sendmail',
  'Exim': 'exim',
  'Dovecot': 'dovecot',
  'Courier': 'dovecot',
  'Microsoft Exchange': 'exchange',
  'SMTP Server': 'postfix',
  'Amavis': 'postfix',
  'SpamAssassin': 'postfix',
  'MailScanner': 'postfix',

  // Firewall
  'Windows Firewall': 'windows_firewall',
  'iptables': 'iptables',
  'UFW': 'ufw',
  'nftables': 'nftables',
  'firewalld': 'firewalld',
  'macOS PF': 'iptables',
  'macOS App Firewall': 'windows_firewall',
  'Palo Alto Firewall': 'palo_alto',
  'FortiGate': 'fortigate',
  'Cisco ASA': 'cisco_asa',
  'Check Point Firewall': 'checkpoint',
  'AWS VPC Flow Logs': 'aws_vpc_flow',
  'Azure NSG Flow Logs': 'azure_nsg',
  'GCP VPC Firewall': 'gcp_vpc',
  'Disk Traffic': 'iptables',

  // Database
  'MySQL Error': 'mysql_error',
  'MySQL Query': 'mysql_query',
  'MySQL Slow Query': 'mysql_slow',
  'PostgreSQL Error': 'postgres_error',
  'PostgreSQL Auth': 'postgres_auth',
  'PostgreSQL Statement': 'postgres_statement',
  'Oracle Alert': 'oracle_alert',
  'Oracle Listener': 'oracle_listener',
  'Oracle Audit': 'oracle_audit',
  'SQL Server Error': 'sqlserver_error',
  'SQL Server Audit': 'sqlserver_audit',
  'SQL Server Transaction': 'sqlserver_transaction',
  'MongoDB Server': 'mongodb_server',
  'MongoDB Audit': 'mongodb_audit',

  // System
  'Linux Syslog': 'syslog',
  'Linux Systemd': 'systemd',
  'Linux Kernel': 'kernel',
  'Linux Audit': 'audit',
  'Linux Package': 'package',
  'Windows Text': 'windows_system',
  'Windows Application': 'windows_application',
  'Windows System': 'windows_system',
  'Windows Security': 'windows_security',
  'Windows Setup': 'windows_setup',
  'Windows Forwarded Events': 'windows_forwarded',

  // FTP
  'JSON FTP Logs': 'iis_ftp',
  'FileZilla FTP': 'vsftpd',
  'IIS FTP': 'proftpd',
  'xferlog': 'vsftpd',

  // Application
  'Application Logs JSON': 'raw',
  'Moodle LMS': 'moodle_lms',

  // Unknown/Raw
  'Custom / Raw': 'raw',
};

export const REVERSE_TYPE_MAPPING: Record<LogType, string> = Object.fromEntries(
  Object.entries(TYPE_MAPPING).map(([k, v]) => [v, k])
) as Record<LogType, string>;
