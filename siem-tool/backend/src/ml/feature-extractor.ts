// Feature Extraction for ML-based Anomaly Detection

import { ParsedLogEntry } from '../types';
import { FeatureVector, BaselineProfile } from './types';

/**
 * Extract ML features from a set of log entries
 */
export function extractFeatures(entries: ParsedLogEntry[], baseline?: BaselineProfile): FeatureVector {
  if (entries.length === 0) {
    return getEmptyFeatures();
  }

  // Sort by timestamp (filter out invalid timestamps)
  const sorted = [...entries]
    .filter(e => {
      if (!e.timestamp) return false;
      const time = new Date(e.timestamp).getTime();
      return !isNaN(time) && time > 0;
    })
    .sort((a, b) => new Date(a.timestamp!).getTime() - new Date(b.timestamp!).getTime());

  // If no valid timestamps, return features based on other data
  if (sorted.length === 0) {
    // Still extract non-time features
    const sourceIps = entries.map(e => e.source.ip).filter((ip): ip is string => !!ip);
    const targetUsers = entries.map(e => e.user?.name).filter((u): u is string => !!u);
    const failures = entries.filter(e => e.outcome === 'failure');
    
    return {
      ...getEmptyFeatures(),
      eventCount: entries.length,
      uniqueSourceIps: new Set(sourceIps).size,
      uniqueTargetUsers: new Set(targetUsers).size,
      failureRate: entries.length > 0 ? failures.length / entries.length : 0,
    };
  }

  // Time-based features
  const timestamps = sorted.map(e => new Date(e.timestamp!).getTime());
  const timeSpreadMs = timestamps.length > 1 
    ? timestamps[timestamps.length - 1] - timestamps[0] 
    : 0;
  const timeSpreadMinutes = timeSpreadMs / 60000;
  
  const eventsPerMinute = timeSpreadMinutes > 0 
    ? entries.length / timeSpreadMinutes 
    : entries.length;

  // Calculate burstiness (coefficient of variation in inter-event times)
  const interEventTimes: number[] = [];
  for (let i = 1; i < timestamps.length; i++) {
    interEventTimes.push(timestamps[i] - timestamps[i - 1]);
  }
  const burstiness = calculateCV(interEventTimes);

  // Off-hours activity (outside 9am-6pm local time)
  const offHoursCount = sorted.filter(e => {
    const hour = new Date(e.timestamp!).getUTCHours();
    return hour < 9 || hour >= 18;
  }).length;
  const offHoursActivity = entries.length > 0 ? offHoursCount / entries.length : 0;

  // Source-based features
  const sourceIps = entries
    .map(e => e.source.ip)
    .filter((ip): ip is string => !!ip);
  const uniqueSourceIps = new Set(sourceIps).size;
  const sourceIpEntropy = calculateEntropy(sourceIps);

  // New source ratio (if baseline available)
  let newSourceRatio = 0;
  if (baseline && baseline.commonSourceIps.size > 0) {
    const newIps = sourceIps.filter(ip => !baseline.commonSourceIps.has(ip));
    newSourceRatio = newIps.length / Math.max(sourceIps.length, 1);
  }

  // Target-based features
  const targetUsers = entries
    .map(e => e.user?.name)
    .filter((u): u is string => !!u);
  const uniqueTargetUsers = new Set(targetUsers).size;
  const targetUserEntropy = calculateEntropy(targetUsers);

  const targetHosts = entries
    .map(e => e.destination?.hostname || e.source.hostname)
    .filter((h): h is string => !!h);
  const uniqueTargetHosts = new Set(targetHosts).size;

  // Privileged user ratio
  const privilegedUsers = ['root', 'admin', 'administrator', 'system', 'sa', 'postgres', 'mysql'];
  const privilegedCount = targetUsers.filter(u => 
    privilegedUsers.includes(u.toLowerCase())
  ).length;
  const privilegedUserRatio = targetUsers.length > 0 
    ? privilegedCount / targetUsers.length 
    : 0;

  // Authentication features
  const authEvents = entries.filter(e => 
    e.tags.includes('auth') || 
    e.logType.includes('auth') || 
    e.action === 'login'
  );
  const failures = authEvents.filter(e => e.outcome === 'failure');
  const successes = authEvents.filter(e => e.outcome === 'success');
  const failureRate = authEvents.length > 0 
    ? failures.length / authEvents.length 
    : 0;

  // Success after failure detection
  const successAfterFailure = detectSuccessAfterFailure(sorted);

  // Invalid user ratio
  const invalidUserEvents = entries.filter(e => 
    e.fields.failure_reason === 'invalid_user' ||
    e.fields.is_invalid_user === true ||
    e.message.toLowerCase().includes('invalid user')
  );
  const invalidUserRatio = authEvents.length > 0 
    ? invalidUserEvents.length / authEvents.length 
    : 0;

  // MFA failure rate (look for MFA-related events)
  const mfaEvents = entries.filter(e => 
    e.message.toLowerCase().includes('mfa') ||
    e.message.toLowerCase().includes('2fa') ||
    e.message.toLowerCase().includes('totp') ||
    e.message.toLowerCase().includes('second factor') ||
    e.tags.includes('mfa')
  );
  const mfaFailures = mfaEvents.filter(e => e.outcome === 'failure');
  const mfaFailureRate = mfaEvents.length > 0 
    ? mfaFailures.length / mfaEvents.length 
    : 0;

  // Network features
  const ports = entries
    .map(e => e.source.port || e.destination?.port)
    .filter((p): p is number => !!p);
  const uniquePorts = new Set(ports).size;

  const commonPorts = [22, 80, 443, 3306, 5432, 1433, 21, 25, 53, 8080, 8443];
  const commonPortCount = ports.filter(p => commonPorts.includes(p)).length;
  const commonPortRatio = ports.length > 0 
    ? commonPortCount / ports.length 
    : 0;

  // Internal traffic ratio (RFC 1918 addresses)
  const internalIps = sourceIps.filter(ip => isInternalIp(ip));
  const internalTrafficRatio = sourceIps.length > 0 
    ? internalIps.length / sourceIps.length 
    : 0;

  // Payload/Request features
  const requestSizes = entries
    .map(e => e.fields.size || e.fields.bytes || e.fields.length)
    .filter((s): s is number => typeof s === 'number');
  const avgRequestSize = requestSizes.length > 0 
    ? requestSizes.reduce((a, b) => a + b, 0) / requestSizes.length 
    : 0;

  // Error code ratio (4xx, 5xx for web, non-zero for others)
  const errorEvents = entries.filter(e => {
    const status = e.fields.status || e.fields.status_code;
    if (typeof status === 'number') {
      return status >= 400;
    }
    return e.severity === 'error' || e.severity === 'critical';
  });
  const errorCodeRatio = entries.length > 0 
    ? errorEvents.length / entries.length 
    : 0;

  // Suspicious pattern count
  const suspiciousPatternCount = countSuspiciousPatterns(entries);

  // Behavioral features
  let deviationFromBaseline = 0;
  if (baseline) {
    deviationFromBaseline = calculateBaselineDeviation(entries, baseline);
  }

  // Session duration (if we can identify sessions)
  const sessionDuration = timeSpreadMinutes;

  // Action velocity
  const actionVelocity = eventsPerMinute;

  return {
    eventCount: entries.length,
    eventsPerMinute,
    timeSpreadMinutes,
    burstiness,
    offHoursActivity,
    uniqueSourceIps,
    sourceIpEntropy,
    geoSpread: 0, // Would need GeoIP lookup
    newSourceRatio,
    uniqueTargetUsers,
    uniqueTargetHosts,
    targetUserEntropy,
    privilegedUserRatio,
    failureRate,
    successAfterFailure,
    mfaFailureRate,
    invalidUserRatio,
    uniquePorts,
    commonPortRatio,
    internalTrafficRatio,
    avgRequestSize,
    errorCodeRatio,
    suspiciousPatternCount,
    deviationFromBaseline,
    sessionDuration,
    actionVelocity,
  };
}

/**
 * Calculate Shannon entropy for a list of values
 */
function calculateEntropy(values: string[]): number {
  if (values.length === 0) return 0;
  
  const counts = new Map<string, number>();
  for (const v of values) {
    counts.set(v, (counts.get(v) || 0) + 1);
  }
  
  let entropy = 0;
  const total = values.length;
  for (const count of counts.values()) {
    const p = count / total;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }
  
  return entropy;
}

/**
 * Calculate coefficient of variation
 */
function calculateCV(values: number[]): number {
  if (values.length < 2) return 0;
  
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  if (mean === 0) return 0;
  
  const variance = values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / values.length;
  const stdDev = Math.sqrt(variance);
  
  return stdDev / mean;
}

/**
 * Check if IP is internal (RFC 1918)
 */
function isInternalIp(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;
  
  // 10.0.0.0/8
  if (parts[0] === 10) return true;
  
  // 172.16.0.0/12
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  
  // 192.168.0.0/16
  if (parts[0] === 192 && parts[1] === 168) return true;
  
  // 127.0.0.0/8 (localhost)
  if (parts[0] === 127) return true;
  
  return false;
}

/**
 * Detect success after multiple failures pattern
 */
function detectSuccessAfterFailure(sortedEntries: ParsedLogEntry[]): number {
  let count = 0;
  
  // Group by user
  const byUser = new Map<string, ParsedLogEntry[]>();
  for (const entry of sortedEntries) {
    if (!entry.user?.name) continue;
    if (!byUser.has(entry.user.name)) {
      byUser.set(entry.user.name, []);
    }
    byUser.get(entry.user.name)!.push(entry);
  }
  
  // Check each user for success-after-failure pattern
  for (const events of byUser.values()) {
    let failureStreak = 0;
    for (const event of events) {
      if (event.outcome === 'failure') {
        failureStreak++;
      } else if (event.outcome === 'success' && failureStreak >= 3) {
        count++;
        failureStreak = 0;
      } else {
        failureStreak = 0;
      }
    }
  }
  
  return count;
}

/**
 * Advanced attack pattern definitions based on real-world attacks
 */
const ATTACK_PATTERNS = {
  // SQL Injection patterns
  sql_injection: [
    /('|"|;|--|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b)/i,
    /(\bEXEC\b|\bEXECUTE\b|\bxp_|\bsp_)/i,
    /(\bWAITFOR\b|\bDELAY\b|\bBENCHMARK\b|\bSLEEP\b)/i,
    /(INFORMATION_SCHEMA|sys\.(tables|columns|objects))/i,
  ],
  
  // XSS patterns
  xss: [
    /(<script|javascript:|on\w+\s*=|<iframe|<img[^>]+onerror)/i,
    /(<svg[^>]*onload|<body[^>]*onload|<input[^>]*onfocus)/i,
    /(document\.cookie|document\.location|window\.location)/i,
    /(eval\s*\(|setTimeout\s*\(|setInterval\s*\()/i,
  ],
  
  // Path traversal
  path_traversal: [
    /(\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e%252f)/i,
    /(\.\.[\/\\]){2,}/i,
    /(\/etc\/passwd|\/etc\/shadow|\/etc\/hosts)/i,
    /(c:\\windows|c:\\boot\.ini|c:\\system32)/i,
  ],
  
  // Command injection
  command_injection: [
    /(\||;|`|\$\(|&&|\|\|)/,
    /(\bping\b|\bwget\b|\bcurl\b|\bnc\b|\bnetcat\b)/i,
    /(\bchmod\b|\bchown\b|\brm\s+-rf|\bmkdir\b)/i,
    /(\/bin\/sh|\/bin\/bash|cmd\.exe|powershell)/i,
  ],
  
  // Log4Shell (CVE-2021-44228) patterns
  log4shell: [
    /\$\{jndi:(ldap|ldaps|rmi|dns|iiop|corba|nds|http):\/\//i,
    /\$\{(\$\{)?[^}]*(lower|upper|env|sys|java|base64):/i,
    /\$\{jndi:.*\$\{/i,  // Nested expressions
    /\$\{\s*j\s*n\s*d\s*i\s*:/i,  // Obfuscated
  ],
  
  // SSRF (Server-Side Request Forgery) patterns
  ssrf: [
    /(169\.254\.169\.254|metadata\.google\.internal)/i,  // Cloud metadata
    /(127\.0\.0\.1|localhost|0\.0\.0\.0|::1)/i,  // Loopback
    /(10\.\d{1,3}\.\d{1,3}\.\d{1,3})/,  // Internal 10.x.x.x
    /(192\.168\.\d{1,3}\.\d{1,3})/,  // Internal 192.168.x.x
    /(172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})/,  // Internal 172.16-31.x.x
    /(file:\/\/|gopher:\/\/|dict:\/\/|ftp:\/\/)/i,  // Dangerous protocols
    /(\?url=|\?uri=|\?path=|\?dest=|\?redirect=|\?next=)/i,  // URL params
  ],
  
  // XXE (XML External Entity) patterns
  xxe: [
    /(<!DOCTYPE[^>]*\[)/i,
    /(<!ENTITY[^>]*SYSTEM)/i,
    /(<!ENTITY[^>]*PUBLIC)/i,
    /(&[a-z]+;|&#\d+;|&#x[a-f0-9]+;)/i,
    /(file:\/\/|expect:\/\/|php:\/\/filter)/i,
  ],
  
  // Deserialization attacks
  deserialization: [
    /(rO0|ysoserial|gadgetchain)/i,
    /(ObjectInputStream|XMLDecoder|Yaml\.load)/i,
    /(pickle\.loads|marshal\.loads|shelve)/i,  // Python
    /(unserialize\s*\(|__wakeup|__destruct)/i,  // PHP
    /(__reduce__|__reduce_ex__|__getstate__)/i,  // Python pickle
  ],
  
  // LDAP injection
  ldap_injection: [
    /(\*|\(|\)|\||\&|\!)/,  // LDAP special chars
    /(\(cn=\*\)|\(uid=\*\)|\(objectclass=\*\))/i,
    /(\\00|\\28|\\29|\\2a|\\5c)/i,  // Encoded LDAP chars
  ],
  
  // Prototype pollution (JavaScript)
  prototype_pollution: [
    /(__proto__|constructor\.prototype|Object\.assign)/i,
    /(\["__proto__"\]|\['__proto__'\])/i,
    /(\.constructor\s*=|\.prototype\s*=)/i,
  ],
  
  // DNS tunneling indicators
  dns_tunneling: [
    /([a-z0-9]{30,}\.[a-z]{2,})/i,  // Long subdomain (high entropy)
    /(TXT|NULL|CNAME)\s+record/i,  // Suspicious record types
    /dns.*query.*[a-f0-9]{32,}/i,  // Hex-encoded data
  ],
  
  // Cryptomining indicators
  cryptomining: [
    /(stratum\+tcp:\/\/|stratum\+ssl:\/\/)/i,
    /(pool\.|mining\.|xmr\.|btc\.|eth\.)/i,
    /(coinhive|cryptoloot|jsecoin|webminer)/i,
    /(monero|bitcoin|ethereum|litecoin)/i,
    /(minergate|nicehash|slushpool|antpool)/i,
    /\b(xmrig|cpuminer|cgminer|bfgminer)\b/i,
  ],
  
  // Ransomware indicators
  ransomware: [
    /\.(encrypted|locked|crypto|crypt|enc)\b/i,
    /(ransom|decrypt|bitcoin|payment.*restore)/i,
    /(vssadmin|wmic.*shadowcopy|bcdedit.*recoveryenabled)/i,
    /(\.ryuk|\.wannacry|\.locky|\.cerber|\.petya|\.revil)/i,
    /your.*files.*have.*been.*encrypted/i,
  ],
  
  // Webshell indicators
  webshell: [
    /(c99|r57|b374k|wso|weevely|p0wny)/i,  // Known webshells
    /(eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE))/i,  // PHP webshell
    /(system\s*\(\s*\$|passthru\s*\(\s*\$|exec\s*\(\s*\$)/i,
    /(\.php\?cmd=|\.asp\?cmd=|\.jsp\?cmd=)/i,
    /(base64_decode\s*\(\s*\$_(GET|POST))/i,
    /(\bproc_open\b|\bpopen\b|\bshell_exec\b)/i,
  ],
  
  // Living off the land (LOLBins/LOLBas) patterns
  lolbins: [
    /(powershell.*-enc|powershell.*-e\s|powershell.*-encodedcommand)/i,
    /(certutil.*-urlcache|certutil.*-decode|certutil.*-encode)/i,
    /(bitsadmin.*\/transfer|bitsadmin.*\/create)/i,
    /(mshta.*vbscript|mshta.*javascript)/i,
    /(regsvr32.*\/s.*\/u|regsvr32.*\/i:http)/i,
    /(rundll32.*javascript|rundll32.*shell32)/i,
    /(cscript.*\/E:jscript|wscript.*\/E:jscript)/i,
    /(msiexec.*\/q.*http|msiexec.*\/i.*http)/i,
    /(InstallUtil|MSBuild.*\/p:)/i,
    /(PsExec|wmic.*process.*call.*create)/i,
    /(schtasks.*\/create|at\s+\\\\)/i,
  ],
  
  // Kerberos attacks
  kerberos: [
    /(4768.*0x12|4769.*0x17)/i,  // Kerberoasting event IDs
    /(ticket_granting|AS-REQ|TGS-REQ)/i,
    /(krbtgt|golden.*ticket|silver.*ticket)/i,
    /(mimikatz|rubeus|kekeo|impacket)/i,
    /(pass.the.hash|pass.the.ticket|overpass)/i,
  ],
  
  // APT indicators
  apt: [
    /(cobaltstrike|beacon|meterpreter|empire)/i,
    /(bloodhound|sharphound|adexplorer)/i,
    /(lazagne|mimikatz|procdump.*lsass)/i,
    /(psexec|wmiexec|smbexec|atexec)/i,
    /(dcsync|dcshawdow|ntdsutil)/i,
  ],
  
  // Known malicious user agents and tools
  malicious_tools: [
    /(nikto|sqlmap|nmap|masscan|zgrab|nuclei|dirbuster|gobuster)/i,
    /(hydra|medusa|john|hashcat|ophcrack)/i,
    /(burpsuite|zaproxy|acunetix|nessus|openvas)/i,
    /(metasploit|cobalt|empire|covenant)/i,
    /(curl\/|wget\/|python-requests)/i,
  ],
  
  // Encoded/obfuscated patterns
  encoded: [
    /(%00|%0d%0a|%27|%22)/i,
    /(fromCharCode|atob|btoa)/i,
    /(\\x[0-9a-f]{2}){4,}/i,
    /(\\u[0-9a-f]{4}){2,}/i,
  ],
};

/**
 * Known malicious IP ranges (partial list - Tor exit nodes, bulletproof hosting, etc.)
 */
const MALICIOUS_IP_PATTERNS = [
  /^185\.220\./,  // Tor exit nodes range
  /^45\.155\./,   // Bulletproof hosting
  /^194\.165\./,  // Known malicious
  /^89\.248\./,   // Scanning infrastructure
  /^141\.98\./,   // Bulletproof hosting
  /^45\.129\./,   // Bulletproof hosting
  /^195\.54\./,   // Known malicious
  /^162\.247\.7[2-4]\./,  // Tor exit nodes
];

/**
 * Known C2 domain patterns
 */
const C2_DOMAIN_PATTERNS = [
  /\.onion$/i,
  /\.bit$/i,
  /pastebin\.com/i,
  /hastebin\.com/i,
  /ghostbin\.com/i,
  /[a-z0-9]{32,}\.(com|net|org|info)/i,  // DGA-like domains
  /([a-z0-9]+-){3,}[a-z0-9]+\./i,  // Hyphenated subdomains
];

/**
 * Count suspicious patterns in log entries
 */
function countSuspiciousPatterns(entries: ParsedLogEntry[]): number {
  let count = 0;
  for (const entry of entries) {
    const textToCheck = `${entry.message} ${entry.rawLine} ${JSON.stringify(entry.fields)}`;
    
    // Check all pattern categories
    for (const patterns of Object.values(ATTACK_PATTERNS)) {
      for (const pattern of patterns) {
        if (pattern.test(textToCheck)) {
          count++;
          break; // Count each entry only once per category
        }
      }
    }
  }
  
  return count;
}

/**
 * Detect specific attack types in log entries
 * Returns detailed detection results for each attack category
 */
export function detectAttackPatterns(entries: ParsedLogEntry[]): Record<string, number> {
  const detections: Record<string, number> = {};
  
  for (const [category, patterns] of Object.entries(ATTACK_PATTERNS)) {
    let count = 0;
    for (const entry of entries) {
      const textToCheck = `${entry.message} ${entry.rawLine} ${JSON.stringify(entry.fields)}`;
      for (const pattern of patterns) {
        if (pattern.test(textToCheck)) {
          count++;
          break;
        }
      }
    }
    if (count > 0) {
      detections[category] = count;
    }
  }
  
  return detections;
}

/**
 * Check if an IP address matches known malicious patterns
 */
export function isMaliciousIp(ip: string): boolean {
  for (const pattern of MALICIOUS_IP_PATTERNS) {
    if (pattern.test(ip)) {
      return true;
    }
  }
  return false;
}

/**
 * Check if a domain matches known C2 patterns
 */
export function isC2Domain(domain: string): boolean {
  for (const pattern of C2_DOMAIN_PATTERNS) {
    if (pattern.test(domain)) {
      return true;
    }
  }
  return false;
}

/**
 * Calculate string entropy (useful for detecting DGA domains, encoded data)
 */
export function calculateStringEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  
  const freq = new Map<string, number>();
  for (const char of str) {
    freq.set(char, (freq.get(char) || 0) + 1);
  }
  
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  
  return entropy;
}

/**
 * Detect DNS tunneling based on subdomain entropy
 */
export function detectDnsTunneling(entries: ParsedLogEntry[]): number {
  let count = 0;
  
  for (const entry of entries) {
    // Look for DNS queries in the log
    const queryField = typeof entry.fields.query === 'string' ? entry.fields.query : null;
    const dnsMatch = entry.message.match(/query:\s*([a-z0-9.-]+)/i) ||
                     entry.message.match(/queried\s+([a-z0-9.-]+)/i) ||
                     queryField?.match(/([a-z0-9.-]+)/i);
    
    if (dnsMatch) {
      const domain = dnsMatch[1];
      const parts = domain.split('.');
      
      // Check for long subdomains (potential data exfiltration)
      for (const part of parts) {
        if (part.length > 25) {
          const entropy = calculateStringEntropy(part);
          if (entropy > 3.5) {  // High entropy indicates encoded data
            count++;
            break;
          }
        }
      }
    }
  }
  
  return count;
}

/**
 * Detect cryptomining activity
 */
export function detectCryptomining(entries: ParsedLogEntry[]): number {
  let count = 0;
  
  for (const entry of entries) {
    const textToCheck = `${entry.message} ${entry.rawLine}`;
    
    // Check for stratum protocol
    if (/stratum\+tcp:\/\/|stratum\+ssl:\/\//i.test(textToCheck)) {
      count += 3;  // High confidence
      continue;
    }
    
    // Check for known mining pools
    if (/pool\.(minergate|supportxmr|nanopool|2miners)/i.test(textToCheck)) {
      count += 2;
      continue;
    }
    
    // Check for mining-related processes
    if (/\b(xmrig|cpuminer|cgminer|bfgminer|minerd)\b/i.test(textToCheck)) {
      count += 2;
      continue;
    }
    
    // Check for high CPU usage patterns with mining keywords
    if (/cpu.*100%.*miner|miner.*cpu.*100%/i.test(textToCheck)) {
      count++;
    }
  }
  
  return count;
}

/**
 * Detect ransomware indicators
 */
export function detectRansomware(entries: ParsedLogEntry[]): number {
  let count = 0;
  
  for (const entry of entries) {
    const textToCheck = `${entry.message} ${entry.rawLine}`;
    
    // Shadow copy deletion (high confidence)
    if (/vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete/i.test(textToCheck)) {
      count += 5;
      continue;
    }
    
    // BCDEdit tampering
    if (/bcdedit.*recoveryenabled.*no|bcdedit.*bootstatuspolicy.*ignoreallfailures/i.test(textToCheck)) {
      count += 4;
      continue;
    }
    
    // Known ransomware extensions
    if (/\.(encrypted|locked|crypto|crypt|enc|locky|cerber|ryuk|revil|wannacry)\b/i.test(textToCheck)) {
      count += 3;
      continue;
    }
    
    // Mass file operations
    if (/mass\s+file\s+(encrypt|rename|delete)|bulk\s+(encrypt|modify)/i.test(textToCheck)) {
      count += 2;
      continue;
    }
    
    // Ransom note detection
    if (/readme.*txt|how.*decrypt|your.*files.*encrypted/i.test(textToCheck)) {
      count += 2;
    }
  }
  
  return count;
}

/**
 * Detect webshell activity
 */
export function detectWebshell(entries: ParsedLogEntry[]): number {
  let count = 0;
  
  for (const entry of entries) {
    const textToCheck = `${entry.message} ${entry.rawLine} ${entry.fields.url || ''} ${entry.fields.request || ''}`;
    
    // Command execution via URL parameters
    if (/\.(php|asp|aspx|jsp)\?cmd=|\?exec=|\?shell=/i.test(textToCheck)) {
      count += 3;
      continue;
    }
    
    // Known webshell filenames
    if (/(c99|r57|b374k|wso|weevely|alfa|p0wny|mini.*shell)/i.test(textToCheck)) {
      count += 3;
      continue;
    }
    
    // Base64 in URL (potential webshell)
    if (/\.(php|asp)\?.*[A-Za-z0-9+\/]{50,}={0,2}/i.test(textToCheck)) {
      count += 2;
      continue;
    }
    
    // POST to unusual script locations
    if (/POST.*(\/tmp\/|\/var\/tmp\/|\/upload.*\/).*\.(php|asp|jsp)/i.test(textToCheck)) {
      count += 2;
      continue;
    }
    
    // System command functions in logs
    if (/eval\s*\(\s*\$_(GET|POST)|system\s*\(\s*\$|passthru\s*\(\s*\$/i.test(textToCheck)) {
      count++;
    }
  }
  
  return count;
}

/**
 * Detect Living off the Land techniques
 */
export function detectLOLBins(entries: ParsedLogEntry[]): number {
  let count = 0;
  
  for (const entry of entries) {
    const textToCheck = `${entry.message} ${entry.rawLine}`;
    
    // PowerShell encoded commands (highest confidence)
    if (/powershell.*(-enc\s|-e\s|-encodedcommand\s)/i.test(textToCheck)) {
      count += 4;
      continue;
    }
    
    // Certutil abuse
    if (/certutil.*(-urlcache|-decode|-encode)/i.test(textToCheck)) {
      count += 3;
      continue;
    }
    
    // BITSAdmin abuse
    if (/bitsadmin.*\/transfer|bitsadmin.*\/create/i.test(textToCheck)) {
      count += 3;
      continue;
    }
    
    // MSHTA abuse
    if (/mshta.*(vbscript|javascript|http)/i.test(textToCheck)) {
      count += 3;
      continue;
    }
    
    // Regsvr32 abuse (Squiblydoo)
    if (/regsvr32.*\/s.*\/u|regsvr32.*\/i:http/i.test(textToCheck)) {
      count += 3;
      continue;
    }
    
    // Rundll32 abuse
    if (/rundll32.*(javascript|shell32|mshtml)/i.test(textToCheck)) {
      count += 2;
      continue;
    }
    
    // MSBuild abuse
    if (/msbuild.*\/p:|msbuild.*\/property:/i.test(textToCheck)) {
      count += 2;
      continue;
    }
    
    // WMI process creation
    if (/wmic.*process.*call.*create/i.test(textToCheck)) {
      count += 2;
      continue;
    }
    
    // PsExec
    if (/psexec.*-[sd]|psexec.*\\\\.*cmd/i.test(textToCheck)) {
      count += 2;
    }
  }
  
  return count;
}

/**
 * Enhanced feature extraction with new attack detection
 */
export function extractAdvancedFeatures(entries: ParsedLogEntry[]): {
  basic: ReturnType<typeof extractFeatures>;
  attackPatterns: Record<string, number>;
  dnsTunneling: number;
  cryptomining: number;
  ransomware: number;
  webshell: number;
  lolbins: number;
  maliciousIps: string[];
  c2Domains: string[];
} {
  const basic = extractFeatures(entries);
  
  // Detect specific attack patterns
  const attackPatterns = detectAttackPatterns(entries);
  
  // Detect advanced threats
  const dnsTunneling = detectDnsTunneling(entries);
  const cryptomining = detectCryptomining(entries);
  const ransomware = detectRansomware(entries);
  const webshell = detectWebshell(entries);
  const lolbins = detectLOLBins(entries);
  
  // Extract malicious IPs and C2 domains
  const maliciousIps: string[] = [];
  const c2Domains: string[] = [];
  
  for (const entry of entries) {
    if (entry.source.ip && isMaliciousIp(entry.source.ip)) {
      maliciousIps.push(entry.source.ip);
    }
    
    // Check for domains in the log
    const hostField = typeof entry.fields.host === 'string' ? entry.fields.host : null;
    const domainMatch = entry.message.match(/https?:\/\/([a-z0-9.-]+)/i) ||
                        hostField?.match(/([a-z0-9.-]+)/i);
    if (domainMatch && isC2Domain(domainMatch[1])) {
      c2Domains.push(domainMatch[1]);
    }
  }
  
  return {
    basic,
    attackPatterns,
    dnsTunneling,
    cryptomining,
    ransomware,
    webshell,
    lolbins,
    maliciousIps: [...new Set(maliciousIps)],
    c2Domains: [...new Set(c2Domains)],
  };
}

/**
 * Calculate deviation from baseline
 */
function calculateBaselineDeviation(entries: ParsedLogEntry[], baseline: BaselineProfile): number {
  if (entries.length === 0 || baseline.avgEventsPerHour === 0) return 0;
  
  // Calculate hourly distribution of current events
  const hourCounts = new Array(24).fill(0);
  for (const entry of entries) {
    if (!entry.timestamp) continue;
    const hour = new Date(entry.timestamp).getUTCHours();
    hourCounts[hour]++;
  }
  
  // Compare to baseline using cosine similarity
  let dotProduct = 0;
  let normA = 0;
  let normB = 0;
  
  for (let i = 0; i < 24; i++) {
    dotProduct += hourCounts[i] * baseline.hourlyDistribution[i];
    normA += hourCounts[i] * hourCounts[i];
    normB += baseline.hourlyDistribution[i] * baseline.hourlyDistribution[i];
  }
  
  if (normA === 0 || normB === 0) return 1; // Maximum deviation
  
  const cosineSimilarity = dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
  return 1 - cosineSimilarity; // Convert similarity to deviation
}

/**
 * Get empty feature vector
 */
function getEmptyFeatures(): FeatureVector {
  return {
    eventCount: 0,
    eventsPerMinute: 0,
    timeSpreadMinutes: 0,
    burstiness: 0,
    offHoursActivity: 0,
    uniqueSourceIps: 0,
    sourceIpEntropy: 0,
    geoSpread: 0,
    newSourceRatio: 0,
    uniqueTargetUsers: 0,
    uniqueTargetHosts: 0,
    targetUserEntropy: 0,
    privilegedUserRatio: 0,
    failureRate: 0,
    successAfterFailure: 0,
    mfaFailureRate: 0,
    invalidUserRatio: 0,
    uniquePorts: 0,
    commonPortRatio: 0,
    internalTrafficRatio: 0,
    avgRequestSize: 0,
    errorCodeRatio: 0,
    suspiciousPatternCount: 0,
    deviationFromBaseline: 0,
    sessionDuration: 0,
    actionVelocity: 0,
  };
}

/**
 * Build a baseline profile from historical entries
 */
export function buildBaseline(entries: ParsedLogEntry[]): BaselineProfile {
  const hourlyDistribution = new Array(24).fill(0);
  const dailyDistribution = new Array(7).fill(0);
  const sourceIps = new Set<string>();
  const users = new Set<string>();
  const ports = new Set<number>();
  
  let totalFailures = 0;
  let totalAuth = 0;
  
  for (const entry of entries) {
    if (entry.timestamp) {
      const date = new Date(entry.timestamp);
      hourlyDistribution[date.getUTCHours()]++;
      dailyDistribution[date.getUTCDay()]++;
    }
    
    if (entry.source.ip) sourceIps.add(entry.source.ip);
    if (entry.user?.name) users.add(entry.user.name);
    if (entry.source.port) ports.add(entry.source.port);
    if (entry.destination?.port) ports.add(entry.destination.port);
    
    if (entry.tags.includes('auth') || entry.action === 'login') {
      totalAuth++;
      if (entry.outcome === 'failure') totalFailures++;
    }
  }
  
  // Normalize hourly distribution
  const totalHourly = hourlyDistribution.reduce((a, b) => a + b, 0);
  const normalizedHourly = hourlyDistribution.map(v => 
    totalHourly > 0 ? v / totalHourly : 0
  );
  
  // Calculate stats
  const avgEventsPerHour = totalHourly / 24;
  const variance = normalizedHourly.reduce((sum, v) => 
    sum + Math.pow(v - avgEventsPerHour, 2), 0
  ) / 24;
  
  return {
    hourlyDistribution: normalizedHourly,
    dailyDistribution,
    avgEventsPerHour,
    stdEventsPerHour: Math.sqrt(variance),
    commonSourceIps: sourceIps,
    commonUsers: users,
    commonPorts: ports,
    avgFailureRate: totalAuth > 0 ? totalFailures / totalAuth : 0,
    avgSessionDuration: 0, // Would need session tracking
  };
}
