// Per-entry attack detection for individual log entries
// This complements the aggregate attack classification in classifier.ts

import { ParsedLogEntry } from '../types';
import { AttackType } from './types';

/**
 * Attack detection result for a single log entry
 */
export interface EntryAttackDetection {
  attackType: AttackType;
  confidence: number;
  mitreTactics: string[];
  mitreTechniques: string[];
  matchedPatterns: string[];
}

// Log type categories for attack detection
export type LogTypeCategory = 
  | 'webserver'
  | 'authentication'
  | 'firewall'
  | 'database'
  | 'mail'
  | 'syslog'
  | 'cloud'
  | 'security'
  | 'generic';

/**
 * Map detected log type to category
 */
export function getLogTypeCategory(logType: string): LogTypeCategory {
  const lowerType = logType.toLowerCase();
  
  // Web servers
  if (/apache|nginx|iis|express|django|flask|fastapi|laravel|rails|gunicorn|uvicorn|node|caddy|haproxy|spring|asp\.net/.test(lowerType)) {
    return 'webserver';
  }
  
  // Authentication
  if (/ssh|auth|login|sshd|windows.*security/.test(lowerType)) {
    return 'authentication';
  }
  
  // Firewall
  if (/firewall|iptables|ufw|nftables|palo|fortigate|cisco|checkpoint|aws.*vpc|azure.*nsg|gcp.*vpc/.test(lowerType)) {
    return 'firewall';
  }
  
  // Database
  if (/mysql|postgres|oracle|sql.*server|mongodb/.test(lowerType)) {
    return 'database';
  }
  
  // Mail
  if (/postfix|sendmail|exim|dovecot|courier|exchange|smtp|mail/.test(lowerType)) {
    return 'mail';
  }
  
  // Cloud
  if (/cloudtrail|guardduty|azure.*activity|gcp.*audit|kubernetes|docker/.test(lowerType)) {
    return 'cloud';
  }
  
  // Security tools
  if (/suricata|zeek|ossec|fail2ban/.test(lowerType)) {
    return 'security';
  }
  
  // Syslog/Daemon
  if (/syslog|systemd|kernel|audit/.test(lowerType)) {
    return 'syslog';
  }
  
  return 'generic';
}

/**
 * Per-entry attack patterns - organized by log type category
 * Each category only checks patterns relevant to that log type
 */
const LOG_TYPE_ATTACK_PATTERNS: Record<LogTypeCategory, Partial<Record<AttackType, { patterns: RegExp[]; weight: number }>>> = {
  // Web servers: Check for web application attacks
  webserver: {
    sql_injection: {
      patterns: [
        /('|"|%27|%22)\s*(OR|AND)\s*('|"|%27|%22)\s*\d*\s*=\s*('|"|%27|%22)\s*\d*/i,
        /(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b)/i,
        /;\s*(DROP|DELETE|INSERT|UPDATE|EXEC|EXECUTE)\s+/i,
        /(\bWAITFOR\b|\bDELAY\b|\bSLEEP\b|\bBENCHMARK\b)/i,
        /(INFORMATION_SCHEMA|sys\.(tables|columns|objects)|pg_catalog)/i,
      ],
      weight: 0.9,
    },
    xss_attack: {
      patterns: [
        /<script[^>]*>.*?<\/script>/i,
        /javascript:/i,
        /on\w+\s*=\s*['"]*[^'">\s]+/i,
        /<iframe[^>]*src\s*=\s*['"]*javascript:/i,
        /<svg[^>]*onload\s*=/i,
        /(document\.(cookie|location|write)|window\.location)/i,
        /eval\s*\(|setTimeout\s*\(|setInterval\s*\(/i,
      ],
      weight: 0.85,
    },
    command_injection: {
      patterns: [
        /[;|`]\s*(cat|ls|pwd|whoami|id|uname|wget|curl|nc|bash|sh|python|perl)\s/i,
        /\$\([^)]*\)|`[^`]*`|\$\{[^}]*\}/,
        /(chmod|chown|rm\s+-rf|mkdir|rmdir)\s+/i,
        /(\/bin\/sh|\/bin\/bash|\/bin\/python|cmd\.exe|powershell)/i,
      ],
      weight: 0.9,
    },
    path_traversal: {
      patterns: [
        /\.\.(\/|\\|%2f|%5c|%252f|%255c)/i,
        /(%2e%2e|%252e%252e)/i,
        /(\/etc\/passwd|\/etc\/shadow|\/etc\/hosts|\/proc\/self)/i,
        /(c:\\windows|c:\\boot\.ini|c:\\system32|c:\\inetpub)/i,
      ],
      weight: 0.8,
    },
    ssrf_attack: {
      patterns: [
        /(169\.254\.169\.254|metadata\.google\.internal|169-254-169-254)/i,
        /\?.*(url|uri|path|dest|redirect|next)\s*=\s*https?:/i,
        /(file:\/\/|gopher:\/\/|dict:\/\/|ftp:\/\/|ldap:\/\/)/i,
        /(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::\]|0x7f\.)/i,
      ],
      weight: 0.85,
    },
    xxe_attack: {
      patterns: [
        /<!ENTITY\s+[^>]+\s+SYSTEM\s+["'][^"']+["']/i,
        /<!DOCTYPE\s+[^>]+\s+\[\s*<!ENTITY/i,
        /(file:\/\/|expect:\/\/|php:\/\/filter|http:\/\/)/i,
      ],
      weight: 0.85,
    },
    file_inclusion: {
      patterns: [
        /\?(page|file|path|include)\s*=\s*https?:/i,
        /(include\s*\(|require\s*\(|require_once\s*\()/i,
      ],
      weight: 0.8,
    },
    log4shell: {
      patterns: [
        /\$\{jndi:(ldap|ldaps|rmi|dns|iiop):\/\//i,
        /\$\{\$\{[^}]*:-[^}]*\}/,
        /\$\{\s*lower\s*:\s*j\s*\}\s*\{\s*lower\s*:\s*n/i,
      ],
      weight: 0.98,
    },
    deserialization: {
      patterns: [
        /(rO0|ysoserial|gadgetchain)/i,
        /(\xac\xed\x00\x05|H4sIAAAAAAAA)/,
      ],
      weight: 0.9,
    },
    prototype_pollution: {
      patterns: [
        /(__proto__|constructor\s*\[\s*"prototype"\s*\])/i,
      ],
      weight: 0.8,
    },
    webshell: {
      patterns: [
        /(c99|r57|b374k|wso|weevely|alfa|p0wny|mini.*shell)/i,
        /\.(php|asp|aspx|jsp)\?cmd=|\?exec=|\?shell=/i,
        /eval\s*\(\s*\$_(GET|POST)|system\s*\(\s*\$|passthru\s*\(\s*\$/i,
      ],
      weight: 0.85,
    },
    bruteforce: {
      patterns: [
        /(401|403)\s+.*\/login|Failed\s+password|Authentication\s+failure/i,
      ],
      weight: 0.6,
    },
    reconnaissance: {
      patterns: [
        /(\/\.env|\/config\.json|\/\.git\/|\/\.htaccess|\/phpinfo)/i,
        /(nikto|sqlmap|nmap|masscan|zgrab|nuclei|dirbuster|gobuster)/i,
      ],
      weight: 0.7,
    },
  },

  // Authentication logs: Focus on credential attacks
  authentication: {
    bruteforce: {
      patterns: [
        /Failed\s+password|Authentication\s+failure|Invalid\s+user|Failed\s+login/i,
      ],
      weight: 0.75,
    },
    password_spray: {
      patterns: [
        /(Authentication\s+failure|Invalid\s+user|Unknown\s+user)/i,
      ],
      weight: 0.65,
    },
    credential_stuffing: {
      patterns: [
        /(Account\s+locked|Too\s+many\s+attempts|Rate\s+limit)/i,
      ],
      weight: 0.7,
    },
    privilege_escalation: {
      patterns: [
        /(sudo|su\s+-|sudo\s+-i|sudo\s+su|sudo\s+.*ALL)/i,
        /(SetUser|Privilege\s+escalation|Admin\s+access)/i,
        /(useradd|usermod|passwd\s+root)/i,
      ],
      weight: 0.8,
    },
    lateral_movement: {
      patterns: [
        /(psexec|wmiexec|smbexec|pass\s+the\s+hash)/i,
        /(ssh.*from.*to|scp\s+.*\s+\S+@\S+:\s*)/i,
      ],
      weight: 0.75,
    },
    account_takeover: {
      patterns: [
        /(impossible\s+travel|unusual\s+location|new\s+device)/i,
        /(suspicious\s+login|account.*compromised)/i,
      ],
      weight: 0.75,
    },
    kerberoasting: {
      patterns: [
        /(4768.*0x12|4769.*0x17)/i,
        /(krbtgt|ticket_granting|AS-REQ|TGS-REQ)/i,
      ],
      weight: 0.8,
    },
    pass_the_hash: {
      patterns: [
        /(NTLM.*hash|pass.the.hash|mimikatz|rubeus)/i,
      ],
      weight: 0.8,
    },
  },

  // Firewall logs: Focus on network attacks
  firewall: {
    port_scan: {
      patterns: [
        /(Connection\s+(refused|timed\s+out)|No\s+route\s+to\s+host)/i,
        /(SYN\s+scan|PORT\s+scan|nmap|masscan)/i,
        /multiple\s+ports?\s+scanned/i,
      ],
      weight: 0.75,
    },
    ddos: {
      patterns: [
        /(Connection\s+reset\s+by\s+peer|Too\s+many\s+connections)/i,
        /(flood|rate\s+limit\s+exceeded|syn\s+flood)/i,
      ],
      weight: 0.8,
    },
    reconnaissance: {
      patterns: [
        /(scan|probe|enumerate|discover)/i,
      ],
      weight: 0.65,
    },
    c2_communication: {
      patterns: [
        /(beacon|heartbeat|check-in|command.*control)/i,
        /dns\s+tunnel|dga|domain\s+generation/i,
      ],
      weight: 0.7,
    },
    data_exfiltration: {
      patterns: [
        /(large\s+data\s+transfer|bulk\s+upload|unusual\s+outbound)/i,
        /(scp|rsync|ftp\s+put)\s+.*\*/i,
      ],
      weight: 0.7,
    },
    lateral_movement: {
      patterns: [
        /(internal\s+to\s+internal|east-west\s+traffic)/i,
        /(RDP|SSH|SMB|WINRM)\s+.*internal/i,
      ],
      weight: 0.7,
    },
  },

  // Database logs: Focus on data-related attacks
  database: {
    sql_injection: {
      patterns: [
        /(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b)/i,
        /;\s*(DROP|DELETE|INSERT|UPDATE|EXEC|EXECUTE)\s+/i,
        /(INFORMATION_SCHEMA|sys\.(tables|columns|objects)|pg_catalog)/i,
        /(\bWAITFOR\b|\bDELAY\b|\bBENCHMARK\b|\bSLEEP\b)/i,
      ],
      weight: 0.95,
    },
    data_exfiltration: {
      patterns: [
        /(SELECT\s+.*\s+INTO\s+OUTFILE|COPY\s+.*\s+TO\s+)/i,
        /(bulk\s+select|bcp\s+.*\s+out)/i,
        /(large\s+result\s+set|million\s+rows)/i,
      ],
      weight: 0.8,
    },
    privilege_escalation: {
      patterns: [
        /(GRANT\s+ALL|ALTER\s+USER.*WITH\s+ADMIN)/i,
        /(CREATE\s+USER|ADD\s+MEMBER\s+TO\s+ROLE)/i,
      ],
      weight: 0.75,
    },
    insider_threat: {
      patterns: [
        /(unauthorized.*access|sensitive.*table|customer.*data)/i,
      ],
      weight: 0.7,
    },
  },

  // Mail logs: Focus on email-based attacks
  mail: {
    bruteforce: {
      patterns: [
        /(authentication\s+failed|login\s+failed|535|530)/i,
      ],
      weight: 0.7,
    },
    data_exfiltration: {
      patterns: [
        /(large\s+attachment|bulk\s+email|mass\s+mailing)/i,
      ],
      weight: 0.65,
    },
    c2_communication: {
      patterns: [
        /(suspicious\s+attachment|executable.*email|macro)/i,
      ],
      weight: 0.75,
    },
    reconnaissance: {
      patterns: [
        /(user\s+enumeration|verify\s+email|rcpt\s+to.*multiple)/i,
      ],
      weight: 0.6,
    },
  },

  // Syslog/Daemon logs: Focus on system-level attacks
  syslog: {
    privilege_escalation: {
      patterns: [
        /(sudo|su\s+-|sudo\s+-i|sudo\s+su)/i,
        /(chmod\s+.*\+s|setuid|setgid)/i,
        /(kernel.*privilege|capability\s+escalation)/i,
      ],
      weight: 0.8,
    },
    malware_activity: {
      patterns: [
        /(virus|trojan|malware|ransomware|backdoor)/i,
        /(suspicious\s+process|unusual\s+execution)/i,
      ],
      weight: 0.85,
    },
    cryptomining: {
      patterns: [
        /(xmrig|minerd|cryptonight|stratum\+tcp)/i,
        /(high\s*cpu\s*usage|mining\s*pool)/i,
      ],
      weight: 0.9,
    },
    ransomware: {
      patterns: [
        /(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete)/i,
        /(bcdedit.*recoveryenabled.*no)/i,
        /(\.(encrypted|locked|crypto|crypt|enc)\b)/i,
      ],
      weight: 0.95,
    },
    living_off_the_land: {
      patterns: [
        /(powershell.*-enc|certutil.*-urlcache|bitsadmin.*\/transfer)/i,
        /(mshta.*vbscript|regsvr32.*\/s.*\/u|wmic.*process.*call)/i,
      ],
      weight: 0.75,
    },
    command_injection: {
      patterns: [
        /[;|`]\s*(wget|curl|nc|bash|python)\s/i,
        /\$\([^)]*\)|`[^`]*`/,
      ],
      weight: 0.8,
    },
  },

  // Cloud logs: Focus on cloud-specific attacks
  cloud: {
    privilege_escalation: {
      patterns: [
        /(AssumeRole|CreateAccessKey|AttachUserPolicy)/i,
        /(elevate|escalate|admin.*policy)/i,
      ],
      weight: 0.8,
    },
    data_exfiltration: {
      patterns: [
        /(GetObject.*large|Download\s+data|ExportSnapshot)/i,
        /(unusual\s+data\s+access|bulk\s+download)/i,
      ],
      weight: 0.75,
    },
    account_takeover: {
      patterns: [
        /(ConsoleLogin.*suspicious|unusual\s+API\s+calls)/i,
        /(impossible\s+travel|unrecognized\s+principal)/i,
      ],
      weight: 0.8,
    },
    lateral_movement: {
      patterns: [
        /(cross-account|role.*chaining|AssumeRole.*external)/i,
      ],
      weight: 0.75,
    },
    reconnaissance: {
      patterns: [
        /(ListBuckets|DescribeInstances|ListUsers.*rapid)/i,
      ],
      weight: 0.7,
    },
    supply_chain: {
      patterns: [
        /(PutBucketPolicy|ModifyLambda|UpdateFunctionCode)/i,
      ],
      weight: 0.8,
    },
  },

  // Security tool logs: Focus on detected threats
  security: {
    malware_activity: {
      patterns: [
        /(malware.*detected|virus.*found|trojan)/i,
      ],
      weight: 0.9,
    },
    c2_communication: {
      patterns: [
        /(c2.*detected|command.*control|beacon)/i,
      ],
      weight: 0.85,
    },
    port_scan: {
      patterns: [
        /(port\s+scan.*detected|scan\s+alert|reconnaissance)/i,
      ],
      weight: 0.8,
    },
    bruteforce: {
      patterns: [
        /(brute\s+force.*detected|login\s+attack)/i,
      ],
      weight: 0.8,
    },
    sql_injection: {
      patterns: [
        /(sql\s+injection.*detected|sqli)/i,
      ],
      weight: 0.85,
    },
    xss_attack: {
      patterns: [
        /(xss.*detected|cross.*site.*scripting)/i,
      ],
      weight: 0.85,
    },
  },

  // Generic: Minimal patterns for unknown log types
  generic: {
    bruteforce: {
      patterns: [
        /(Failed\s+password|Authentication\s+failure)/i,
      ],
      weight: 0.5,
    },
    malware_activity: {
      patterns: [
        /(virus|trojan|malware)/i,
      ],
      weight: 0.7,
    },
  },
};

/**
 * MITRE ATT&CK mapping for attack types
 */
const MITRE_MAPPING: Record<AttackType, { tactics: string[]; techniques: string[] }> = {
  sql_injection: { tactics: ['TA0006'], techniques: ['T1190'] },
  xss_attack: { tactics: ['TA0006'], techniques: ['T1189'] },
  command_injection: { tactics: ['TA0002'], techniques: ['T1059'] },
  path_traversal: { tactics: ['TA0006'], techniques: ['T1083'] },
  ssrf_attack: { tactics: ['TA0001'], techniques: ['T1190'] },
  ldap_injection: { tactics: ['TA0006'], techniques: ['T1213'] },
  xxe_attack: { tactics: ['TA0001'], techniques: ['T1059'] },
  log4shell: { tactics: ['TA0001'], techniques: ['T1190', 'T1059'] },
  deserialization: { tactics: ['TA0001'], techniques: ['T1059'] },
  bruteforce: { tactics: ['TA0006'], techniques: ['T1110'] },
  password_spray: { tactics: ['TA0006'], techniques: ['T1110.003'] },
  credential_stuffing: { tactics: ['TA0006'], techniques: ['T1110.004'] },
  port_scan: { tactics: ['TA0043'], techniques: ['T1595.001'] },
  ddos: { tactics: ['TA0040'], techniques: ['T1498'] },
  reconnaissance: { tactics: ['TA0043'], techniques: ['T1595'] },
  privilege_escalation: { tactics: ['TA0004'], techniques: ['T1078'] },
  lateral_movement: { tactics: ['TA0008'], techniques: ['T1021'] },
  data_exfiltration: { tactics: ['TA0010'], techniques: ['T1041'] },
  malware_activity: { tactics: ['TA0002'], techniques: ['T1204'] },
  c2_communication: { tactics: ['TA0011'], techniques: ['T1071'] },
  insider_threat: { tactics: ['TA0004'], techniques: ['T1078'] },
  account_takeover: { tactics: ['TA0006'], techniques: ['T1098'] },
  mfa_bypass: { tactics: ['TA0006'], techniques: ['T1556'] },
  mfa_fatigue: { tactics: ['TA0006'], techniques: ['T1621'] },
  session_hijacking: { tactics: ['TA0006'], techniques: ['T1539'] },
  kerberoasting: { tactics: ['TA0006'], techniques: ['T1558.003'] },
  pass_the_hash: { tactics: ['TA0008'], techniques: ['T1550.002'] },
  golden_ticket: { tactics: ['TA0006'], techniques: ['T1558.001'] },
  dns_tunneling: { tactics: ['TA0010'], techniques: ['T1071.004'] },
  cryptomining: { tactics: ['TA0004'], techniques: ['T1496'] },
  ransomware: { tactics: ['TA0040'], techniques: ['T1486'] },
  supply_chain: { tactics: ['TA0001'], techniques: ['T1195'] },
  file_inclusion: { tactics: ['TA0001'], techniques: ['T1190'] },
  prototype_pollution: { tactics: ['TA0001'], techniques: ['T1059'] },
  apt_activity: { tactics: ['TA0043'], techniques: ['T1583'] },
  zero_day_exploit: { tactics: ['TA0001'], techniques: ['T1190'] },
  webshell: { tactics: ['TA0003'], techniques: ['T1505.003'] },
  living_off_the_land: { tactics: ['TA0005'], techniques: ['T1218'] },
  unknown: { tactics: [], techniques: [] },
  anomaly: { tactics: [], techniques: [] },
};

/**
 * Detect attack patterns in a single log entry based on log type
 * Returns attack detection result or null if no attack detected
 */
export function detectEntryAttack(
  entry: ParsedLogEntry,
  logType?: string
): EntryAttackDetection | null {
  const searchText = entry.message + ' ' + (entry.rawLine || '');
  
  // Determine log type category
  const category = logType ? getLogTypeCategory(logType) : 
                   entry.logType ? getLogTypeCategory(entry.logType) : 
                   'generic';
  
  // Get patterns for this log type category
  const categoryPatterns = LOG_TYPE_ATTACK_PATTERNS[category] || LOG_TYPE_ATTACK_PATTERNS.generic;
  
  const detections: Array<{ type: AttackType; confidence: number; patterns: string[] }> = [];

  // Check each attack type applicable to this log type
  for (const [attackType, config] of Object.entries(categoryPatterns)) {
    if (!config || config.patterns.length === 0) continue;

    let matchCount = 0;
    const matchedPatterns: string[] = [];

    for (const pattern of config.patterns) {
      if (pattern.test(searchText)) {
        matchCount++;
        matchedPatterns.push(pattern.source);
      }
    }

    if (matchCount > 0) {
      // Calculate confidence based on matches and weight
      const confidence = Math.min(
        config.weight + (matchCount * 0.1),
        0.95 // Cap at 95%
      );

      detections.push({
        type: attackType as AttackType,
        confidence,
        patterns: matchedPatterns,
      });
    }
  }

  // Return the highest confidence detection
  if (detections.length === 0) return null;

  detections.sort((a, b) => b.confidence - a.confidence);
  const best = detections[0];
  const mitre = MITRE_MAPPING[best.type];

  return {
    attackType: best.type,
    confidence: best.confidence,
    mitreTactics: mitre.tactics,
    mitreTechniques: mitre.techniques,
    matchedPatterns: best.patterns,
  };
}

/**
 * Detect attacks in multiple entries with log type awareness
 * Returns array of entries with attack information
 */
export function detectAttacksInEntries(
  entries: ParsedLogEntry[],
  logType?: string
): Array<{
  entry: ParsedLogEntry;
  attack: EntryAttackDetection;
}> {
  const results: Array<{ entry: ParsedLogEntry; attack: EntryAttackDetection }> = [];

  for (const entry of entries) {
    const attack = detectEntryAttack(entry, logType || entry.logType);
    if (attack && attack.confidence >= 0.3) { // Only include if confidence >= 30%
      results.push({ entry, attack });
    }
  }

  return results;
}

/**
 * Add attack detection fields to an entry (mutates the entry)
 */
export function enrichEntryWithAttackDetection(
  entry: ParsedLogEntry,
  logType?: string
): ParsedLogEntry {
  const detection = detectEntryAttack(entry, logType);
  
  if (detection && detection.confidence >= 0.3) {
    entry.attackType = detection.attackType;
    entry.attackConfidence = detection.confidence;
    entry.mitreTactics = detection.mitreTactics;
    entry.mitreTechniques = detection.mitreTechniques;
  }

  return entry;
}

/**
 * Enrich all entries with attack detection
 */
export function enrichEntriesWithAttacks(
  entries: ParsedLogEntry[],
  logType?: string
): ParsedLogEntry[] {
  return entries.map(e => enrichEntryWithAttackDetection(e, logType));
}

/**
 * Get available attack types for a log type category
 */
export function getAttackTypesForLogType(logType: string): AttackType[] {
  const category = getLogTypeCategory(logType);
  const patterns = LOG_TYPE_ATTACK_PATTERNS[category] || LOG_TYPE_ATTACK_PATTERNS.generic;
  return Object.keys(patterns) as AttackType[];
}

/**
 * Check if an attack type is applicable to a log type
 */
export function isAttackTypeApplicable(attackType: AttackType, logType: string): boolean {
  const category = getLogTypeCategory(logType);
  const patterns = LOG_TYPE_ATTACK_PATTERNS[category] || LOG_TYPE_ATTACK_PATTERNS.generic;
  return attackType in patterns;
}
