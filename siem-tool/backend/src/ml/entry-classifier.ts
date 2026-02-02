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

/**
 * Per-entry attack patterns - checks individual log messages
 * These patterns detect attacks in single log entries (not aggregate behavior)
 */
const ENTRY_ATTACK_PATTERNS: Record<AttackType, { patterns: RegExp[]; weight: number }> = {
  // Web Application Attacks
  sql_injection: {
    patterns: [
      /('|"|%27|%22)\s*(OR|AND)\s*('|"|%27|%22)\s*\d*\s*=\s*('|"|%27|%22)\s*\d*/i,  // ' OR '1'='1
      /(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b)/i,  // UNION SELECT
      /;\s*(DROP|DELETE|INSERT|UPDATE|EXEC|EXECUTE)\s+/i,  // ; DROP TABLE
      /(\bWAITFOR\b|\bDELAY\b|\bSLEEP\b|\bBENCHMARK\b)/i,  // Time-based
      /(INFORMATION_SCHEMA|sys\.(tables|columns|objects)|pg_catalog)/i,  // Schema enumeration
    ],
    weight: 0.9,
  },
  
  xss_attack: {
    patterns: [
      /<script[^>]*>.*?<\/script>/i,  // <script> tags
      /javascript:/i,  // javascript: protocol
      /on\w+\s*=\s*['"]*[^'">\s]+/i,  // onerror=, onload=, etc.
      /<iframe[^>]*src\s*=\s*['"]*javascript:/i,  // <iframe with javascript
      /<svg[^>]*onload\s*=/i,  // SVG onload
      /(document\.(cookie|location|write)|window\.location)/i,  // DOM manipulation
      /eval\s*\(|setTimeout\s*\(|setInterval\s*\(/i,  // Code execution
    ],
    weight: 0.85,
  },
  
  command_injection: {
    patterns: [
      /[;|`]\s*(cat|ls|pwd|whoami|id|uname|wget|curl|nc|bash|sh|python|perl)\s/i,  // Command exec
      /\$\([^)]*\)|`[^`]*`|\$\{[^}]*\}/,  // Command substitution
      /(chmod|chown|rm\s+-rf|mkdir|rmdir)\s+/i,  // File operations
      /(\/bin\/sh|\/bin\/bash|\/bin\/python|cmd\.exe|powershell)/i,  // Shell references
      /(ping\s+-c|\bping\b.*\|)/i,  // Ping with pipe
    ],
    weight: 0.9,
  },
  
  path_traversal: {
    patterns: [
      /\.\.(\/|\\|%2f|%5c|%252f|%255c)/i,  // ../ or ..\ variants
      /(%2e%2e|%252e%252e)/i,  // URL encoded ..
      /(\/etc\/passwd|\/etc\/shadow|\/etc\/hosts|\/proc\/self)/i,  // Unix files
      /(c:\\windows|c:\\boot\.ini|c:\\system32|c:\\inetpub)/i,  // Windows files
      /\.\.[\/\\].*\.(txt|log|ini|conf|config|xml|json)/i,  // Config files
    ],
    weight: 0.8,
  },
  
  ssrf_attack: {
    patterns: [
      /(169\.254\.169\.254|metadata\.google\.internal|169-254-169-254)/i,  // Cloud metadata
      /\?.*(url|uri|path|dest|redirect|next)\s*=\s*https?:/i,  // URL parameters
      /(file:\/\/|gopher:\/\/|dict:\/\/|ftp:\/\/|ldap:\/\/)/i,  // Dangerous protocols
      /(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::\]|0x7f\.)/i,  // Loopback addresses
    ],
    weight: 0.85,
  },
  
  // Injection Attacks
  ldap_injection: {
    patterns: [
      /\*\s*\)\s*\(\s*\*|\)\s*\(\s*cn\s*=\*/i,  // LDAP wildcards
      /(\|\(|&\()/i,  // LDAP operators
    ],
    weight: 0.8,
  },
  
  xxe_attack: {
    patterns: [
      /<!ENTITY\s+[^>]+\s+SYSTEM\s+["'][^"']+["']/i,  // External entity
      /<!DOCTYPE\s+[^>]+\s+\[\s*<!ENTITY/i,  // DOCTYPE with entity
      /(file:\/\/|expect:\/\/|php:\/\/filter|http:\/\/)/i,  // Dangerous protocols
    ],
    weight: 0.85,
  },
  
  // Malware & Exploits
  log4shell: {
    patterns: [
      /\$\{jndi:(ldap|ldaps|rmi|dns|iiop):\/\//i,  // JNDI lookup
      /\$\{\$\{[^}]*:-[^}]*\}/,  // Nested JNDI
      /\$\{\s*lower\s*:\s*j\s*\}\s*\{\s*lower\s*:\s*n/i,  // Obfuscated jndi
    ],
    weight: 0.98,
  },
  
  deserialization: {
    patterns: [
      /(rO0|ysoserial|gadgetchain)/i,  // Java serialization
      /(\xac\xed\x00\x05|H4sIAAAAAAAA)/,  // Serialized objects
    ],
 weight: 0.9,
  },
  
  // Authentication Attacks
  bruteforce: {
    patterns: [
      /Failed\s+password|Authentication\s+failure|Invalid\s+user/i,  // Auth failure
    ],
    weight: 0.6, // Needs aggregate analysis for high confidence
  },
  
  password_spray: {
    patterns: [
      /(Authentication\s+failure|Invalid\s+user|Unknown\s+user)/i,
    ],
    weight: 0.6, // Needs aggregate analysis
  },
  
  credential_stuffing: {
    patterns: [
      /(Account\s+locked|Too\s+many\s+attempts|Rate\s+limit)/i,
    ],
    weight: 0.6,
  },
  
  // Infrastructure Attacks
  port_scan: {
    patterns: [
      /(Connection\s+(refused|timed\s+out)|No\s+route\s+to\s+host)/i,
      /(SYN\s+scan|PORT\s+scan|nmap)/i,
    ],
    weight: 0.7,
  },
  
  ddos: {
    patterns: [
      /(Connection\s+reset\s+by\s+peer|Too\s+many\s+connections)/i,
      /(flood|rate\s+limit\s+exceeded)/i,
    ],
    weight: 0.75,
  },
  
  reconnaissance: {
    patterns: [
      /(scan|probe|enumerate|discover)/i,
      /(\/\.env|\/config\.json|\/\.git\/|\/\.htaccess)/i,
    ],
    weight: 0.65,
  },
  
  // Advanced Threats
  privilege_escalation: {
    patterns: [
      /(sudo|su\s+-|sudo\s+-i|sudo\s+su)/i,
      /(SetUser|Privilege\s+escalation|Admin\s+access)/i,
    ],
    weight: 0.75,
  },
  
  lateral_movement: {
    patterns: [
      /(psexec|wmiexec|smbexec|pass\s+the\s+hash)/i,
      /(Remote\s+desktop|RDP\s+connection|SSH\s+tunnel)/i,
    ],
    weight: 0.75,
  },
  
  data_exfiltration: {
    patterns: [
      /( Large\s+data\s+transfer|Bulk\s+download|unusual\s+outbound)/i,
      /(scp\s+.*\*|rsync\s+.*\*|ftp\s+put)/i,
    ],
    weight: 0.7,
  },
  
  malware_activity: {
    patterns: [
      /(virus|trojan|malware|ransomware|backdoor)/i,
      /(suspicious\s+process|unusual\s+execution)/i,
    ],
    weight: 0.8,
  },
  
  c2_communication: {
    patterns: [
      /(beacon|heartbeat|check-in|command.*control)/i,
      /(dns\s+tunnel|dga|domain\s+generation)/i,
    ],
    weight: 0.75,
  },
  
  insider_threat: {
    patterns: [
      /(unauthorized\s+access|data\s*breach|sensitive.*access)/i,
    ],
    weight: 0.7,
  },
  
  account_takeover: {
    patterns: [
      /(impossible\s+travel|unusual\s+location|new\s+device)/i,
      /(suspicious\s+login|account\s*compromised)/i,
    ],
    weight: 0.75,
  },
  
  // Not applicable for single-entry detection
  mfa_bypass: {
    patterns: [],
    weight: 0,
  },
  
  mfa_fatigue: {
    patterns: [],
    weight: 0,
  },
  
  session_hijacking: {
    patterns: [],
    weight: 0,
  },
  
  kerberoasting: {
    patterns: [],
    weight: 0,
  },
  
  pass_the_hash: {
    patterns: [],
    weight: 0,
  },
  
  golden_ticket: {
    patterns: [],
    weight: 0,
  },
  
  dns_tunneling: {
    patterns: [
      /(long\s*dns\s*query|dns\s*exfiltration)/i,
      /[a-z0-9]{50,}\./i,  // Long subdomain
    ],
    weight: 0.7,
  },
  
  cryptomining: {
    patterns: [
      /(xmrig|minerd|cryptonight|stratum\+tcp)/i,
      /(high\s*cpu\s*usage|mining\s*pool)/i,
    ],
    weight: 0.85,
  },
  
  ransomware: {
    patterns: [
      /(ransomware|encryption|\.locked|\.encrypted)/i,
      /(pay\s*bitcoin|decrypt\s*files)/i,
    ],
    weight: 0.9,
  },
  
  supply_chain: {
    patterns: [
      /(npm\s*install|pip\s*install| compromised\s*package)/i,
    ],
    weight: 0.75,
  },
  
  file_inclusion: {
    patterns: [
      /\?(page|file|path|include)\s*=\s*https?:/i,
      /(include\s*\(|require\s*\(|require_once\s*\()/i,
    ],
    weight: 0.8,
  },
  
  prototype_pollution: {
    patterns: [
      /(__proto__|constructor\s*\[\s*"prototype"\s*\])/i,
    ],
    weight: 0.8,
  },
  
  // Advanced Threats - single entry detection not applicable
  apt_activity: {
    patterns: [],
    weight: 0,
  },
  
  zero_day_exploit: {
    patterns: [],
    weight: 0,
  },
  
  webshell: {
    patterns: [],
    weight: 0,
  },
  
  living_off_the_land: {
    patterns: [],
    weight: 0,
  },

  // Default
  unknown: {
    patterns: [],
    weight: 0,
  },
  
  anomaly: {
    patterns: [],
    weight: 0,
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
 * Detect attack patterns in a single log entry
 * Returns attack detection result or null if no attack detected
 */
export function detectEntryAttack(entry: ParsedLogEntry): EntryAttackDetection | null {
  const searchText = entry.message + ' ' + (entry.rawLine || '');
  const detections: Array<{ type: AttackType; confidence: number; patterns: string[] }> = [];

  // Check each attack type
  for (const [attackType, config] of Object.entries(ENTRY_ATTACK_PATTERNS)) {
    if (config.patterns.length === 0) continue;

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
 * Detect attacks in multiple entries
 * Returns array of entries with attack information
 */
export function detectAttacksInEntries(entries: ParsedLogEntry[]): Array<{
  entry: ParsedLogEntry;
  attack: EntryAttackDetection;
}> {
  const results: Array<{ entry: ParsedLogEntry; attack: EntryAttackDetection }> = [];

  for (const entry of entries) {
    const attack = detectEntryAttack(entry);
    if (attack && attack.confidence >= 0.3) { // Only include if confidence >= 30%
      results.push({ entry, attack });
    }
  }

  return results;
}

/**
 * Add attack detection fields to an entry (mutates the entry)
 */
export function enrichEntryWithAttackDetection(entry: ParsedLogEntry): ParsedLogEntry {
  const detection = detectEntryAttack(entry);
  
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
export function enrichEntriesWithAttacks(entries: ParsedLogEntry[]): ParsedLogEntry[] {
  return entries.map(enrichEntryWithAttackDetection);
}
