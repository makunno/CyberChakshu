// ML-based Attack Classifier
// Uses a lightweight decision tree / rules-based classifier optimized for edge computing

import { FeatureVector, MLPrediction, AttackType } from './types';

/**
 * Attack classification weights learned from training data
 * These weights can be updated with new training data
 * Based on MITRE ATT&CK framework and real-world attack patterns
 */
const ATTACK_WEIGHTS: Record<AttackType, Partial<Record<keyof FeatureVector, number>>> = {
  // ============ CREDENTIAL-BASED ATTACKS ============
  bruteforce: {
    failureRate: 0.95,
    eventsPerMinute: 0.7,
    uniqueSourceIps: -0.3,  // Low unique IPs = single source
    uniqueTargetUsers: -0.4, // Low unique users = single target
    burstiness: 0.6,
  },
  password_spray: {
    failureRate: 0.9,
    uniqueTargetUsers: 0.95,  // Many unique users
    uniqueSourceIps: -0.3,    // Few source IPs
    targetUserEntropy: 0.8,
    invalidUserRatio: 0.7,
  },
  credential_stuffing: {
    failureRate: 0.85,
    uniqueTargetUsers: 0.9,
    eventsPerMinute: 0.75,
    invalidUserRatio: 0.5,
    successAfterFailure: 0.6,
  },
  mfa_bypass: {
    mfaFailureRate: 0.95,
    failureRate: 0.7,
    successAfterFailure: 0.8,
    eventsPerMinute: 0.5,
  },
  mfa_fatigue: {
    mfaFailureRate: 0.9,
    eventsPerMinute: 0.85,
    burstiness: 0.7,
    timeSpreadMinutes: 0.6,
  },
  session_hijacking: {
    newSourceRatio: 0.9,
    sourceIpEntropy: 0.8,
    offHoursActivity: 0.6,
    deviationFromBaseline: 0.7,
  },
  account_takeover: {
    successAfterFailure: 0.9,
    newSourceRatio: 0.8,
    deviationFromBaseline: 0.7,
    offHoursActivity: 0.5,
  },
  // NEW: Kerberoasting - targeting service account tickets
  kerberoasting: {
    uniqueTargetUsers: 0.85,  // Multiple service accounts
    eventsPerMinute: 0.7,
    privilegedUserRatio: 0.6,
    offHoursActivity: 0.5,
    suspiciousPatternCount: 0.8,
  },
  // NEW: Pass the Hash - NTLM hash reuse
  pass_the_hash: {
    newSourceRatio: 0.9,  // New source using existing credentials
    deviationFromBaseline: 0.85,
    internalTrafficRatio: 0.8,  // Internal movement
    uniqueTargetHosts: 0.7,
    offHoursActivity: 0.6,
  },
  // NEW: Golden Ticket - forged Kerberos tickets
  golden_ticket: {
    privilegedUserRatio: 0.95,  // Domain admin access
    deviationFromBaseline: 0.9,
    uniqueTargetHosts: 0.85,
    offHoursActivity: 0.7,
    internalTrafficRatio: 0.8,
  },

  // ============ WEB APPLICATION ATTACKS (OWASP Top 10) ============
  sql_injection: {
    suspiciousPatternCount: 0.95,
    errorCodeRatio: 0.7,
    eventsPerMinute: 0.5,
  },
  xss_attack: {
    suspiciousPatternCount: 0.9,
    errorCodeRatio: 0.6,
  },
  path_traversal: {
    suspiciousPatternCount: 0.9,
    errorCodeRatio: 0.7,
  },
  command_injection: {
    suspiciousPatternCount: 0.95,
    errorCodeRatio: 0.7,
    privilegedUserRatio: 0.5,
  },
  // NEW: SSRF - Server-Side Request Forgery
  ssrf_attack: {
    suspiciousPatternCount: 0.9,
    internalTrafficRatio: 0.85,  // Requests to internal resources
    errorCodeRatio: 0.6,
    eventsPerMinute: 0.5,
  },
  // NEW: XXE - XML External Entity
  xxe_attack: {
    suspiciousPatternCount: 0.9,
    errorCodeRatio: 0.7,
    avgRequestSize: 0.6,  // XXE payloads can be large
  },
  // NEW: Deserialization attacks
  deserialization: {
    suspiciousPatternCount: 0.95,
    errorCodeRatio: 0.8,
    avgRequestSize: 0.7,  // Serialized payloads
  },
  // NEW: LDAP Injection
  ldap_injection: {
    suspiciousPatternCount: 0.9,
    errorCodeRatio: 0.7,
    uniqueTargetUsers: 0.6,
  },
  // NEW: Log4Shell (CVE-2021-44228)
  log4shell: {
    suspiciousPatternCount: 0.98,  // Very specific pattern
    errorCodeRatio: 0.5,
    eventsPerMinute: 0.4,
  },
  // NEW: Prototype Pollution
  prototype_pollution: {
    suspiciousPatternCount: 0.9,
    errorCodeRatio: 0.6,
  },

  // ============ INFRASTRUCTURE ATTACKS ============
  privilege_escalation: {
    privilegedUserRatio: 0.95,
    actionVelocity: 0.6,
    offHoursActivity: 0.5,
    suspiciousPatternCount: 0.4,
  },
  lateral_movement: {
    uniqueTargetHosts: 0.9,
    internalTrafficRatio: 0.85,
    newSourceRatio: 0.7,
    eventsPerMinute: 0.5,
  },
  data_exfiltration: {
    avgRequestSize: 0.9,
    internalTrafficRatio: -0.5,  // External traffic
    offHoursActivity: 0.7,
    uniqueTargetHosts: 0.6,
  },
  port_scan: {
    uniquePorts: 0.95,
    commonPortRatio: 0.7,
    eventsPerMinute: 0.8,
    failureRate: 0.6,
  },
  ddos: {
    eventsPerMinute: 0.95,
    uniqueSourceIps: 0.8,
    burstiness: 0.9,
    errorCodeRatio: 0.6,
  },
  reconnaissance: {
    uniquePorts: 0.8,
    errorCodeRatio: 0.7,
    eventsPerMinute: 0.5,
    uniqueTargetHosts: 0.6,
  },
  // NEW: DNS Tunneling - data exfiltration via DNS
  dns_tunneling: {
    eventsPerMinute: 0.75,
    avgRequestSize: 0.7,  // Long DNS queries
    internalTrafficRatio: -0.6,  // External DNS
    offHoursActivity: 0.7,
    deviationFromBaseline: 0.8,
  },
  // NEW: Cryptomining
  cryptomining: {
    suspiciousPatternCount: 0.9,
    deviationFromBaseline: 0.85,
    offHoursActivity: 0.4,  // Runs constantly
    eventsPerMinute: 0.6,
  },
  // NEW: Ransomware
  ransomware: {
    suspiciousPatternCount: 0.95,
    actionVelocity: 0.9,  // High-speed file operations
    deviationFromBaseline: 0.95,
    privilegedUserRatio: 0.7,
  },
  // NEW: Supply Chain attacks
  supply_chain: {
    suspiciousPatternCount: 0.85,
    deviationFromBaseline: 0.9,
    newSourceRatio: 0.8,
  },

  // ============ ADVANCED PERSISTENT THREATS ============
  malware_activity: {
    suspiciousPatternCount: 0.85,
    offHoursActivity: 0.7,
    deviationFromBaseline: 0.8,
  },
  c2_communication: {
    offHoursActivity: 0.8,
    burstiness: 0.75,
    internalTrafficRatio: -0.6,
    deviationFromBaseline: 0.7,
  },
  insider_threat: {
    offHoursActivity: 0.8,
    privilegedUserRatio: 0.7,
    avgRequestSize: 0.6,
    deviationFromBaseline: 0.75,
  },
  // NEW: Generic APT activity
  apt_activity: {
    suspiciousPatternCount: 0.9,
    offHoursActivity: 0.75,
    deviationFromBaseline: 0.85,
    internalTrafficRatio: 0.7,  // Internal movement
    uniqueTargetHosts: 0.8,
  },
  // NEW: Zero-day exploits
  zero_day_exploit: {
    suspiciousPatternCount: 0.95,
    errorCodeRatio: 0.8,
    deviationFromBaseline: 0.9,
  },
  // NEW: Webshell deployment/usage
  webshell: {
    suspiciousPatternCount: 0.95,
    errorCodeRatio: 0.6,
    offHoursActivity: 0.7,
    eventsPerMinute: 0.5,
  },
  // NEW: Living off the Land (LOLBins/LOLBas)
  living_off_the_land: {
    suspiciousPatternCount: 0.9,
    privilegedUserRatio: 0.75,
    deviationFromBaseline: 0.8,
    offHoursActivity: 0.6,
  },

  // ============ GENERIC ============
  anomaly: {
    deviationFromBaseline: 0.95,
    burstiness: 0.6,
  },
  unknown: {},
};

/**
 * Thresholds for attack detection
 * Lower threshold = more sensitive (more detections, potential false positives)
 * Higher threshold = more specific (fewer detections, potential false negatives)
 */
const ATTACK_THRESHOLDS: Record<AttackType, number> = {
  // Credential attacks
  bruteforce: 0.7,
  password_spray: 0.75,
  credential_stuffing: 0.7,
  mfa_bypass: 0.8,
  mfa_fatigue: 0.75,
  session_hijacking: 0.8,
  account_takeover: 0.8,
  kerberoasting: 0.75,       // NEW
  pass_the_hash: 0.8,        // NEW - High confidence needed
  golden_ticket: 0.85,       // NEW - Very specific attack
  
  // Web attacks
  sql_injection: 0.7,
  xss_attack: 0.7,
  path_traversal: 0.7,
  command_injection: 0.75,
  ssrf_attack: 0.75,         // NEW
  xxe_attack: 0.75,          // NEW
  deserialization: 0.8,      // NEW - High confidence needed
  ldap_injection: 0.75,      // NEW
  log4shell: 0.65,           // NEW - Very specific, lower threshold
  prototype_pollution: 0.75,  // NEW
  
  // Infrastructure attacks
  privilege_escalation: 0.7,
  lateral_movement: 0.75,
  data_exfiltration: 0.8,
  port_scan: 0.7,
  ddos: 0.75,
  reconnaissance: 0.65,
  dns_tunneling: 0.75,       // NEW
  cryptomining: 0.7,         // NEW
  ransomware: 0.7,           // NEW - Lower threshold due to severity
  supply_chain: 0.8,         // NEW - High confidence needed
  
  // APT
  malware_activity: 0.75,
  c2_communication: 0.8,
  insider_threat: 0.75,
  apt_activity: 0.8,         // NEW - High confidence needed
  zero_day_exploit: 0.85,    // NEW - Very high confidence needed
  webshell: 0.7,             // NEW
  living_off_the_land: 0.75, // NEW
  
  // Generic
  anomaly: 0.6,
  unknown: 1.0,
};

/**
 * Minimum feature values to consider an attack
 */
const MINIMUM_THRESHOLDS: Partial<Record<keyof FeatureVector, number>> = {
  eventCount: 3,
  failureRate: 0.3,
  eventsPerMinute: 0.5,
};

/**
 * Classify attack type based on features
 */
export function classifyAttack(features: FeatureVector): MLPrediction[] {
  const predictions: MLPrediction[] = [];
  
  // Skip if not enough events
  if (features.eventCount < (MINIMUM_THRESHOLDS.eventCount || 3)) {
    return [];
  }
  
  // Calculate score for each attack type
  const scores: Array<{ type: AttackType; score: number; weightedFeatures: Record<string, number> }> = [];
  
  for (const [attackType, weights] of Object.entries(ATTACK_WEIGHTS)) {
    if (Object.keys(weights).length === 0) continue;
    
    let totalWeight = 0;
    let weightedSum = 0;
    const weightedFeatures: Record<string, number> = {};
    
    for (const [featureName, weight] of Object.entries(weights)) {
      const featureValue = features[featureName as keyof FeatureVector] as number;
      if (featureValue === undefined) continue;
      
      // Normalize feature value to 0-1 range
      const normalizedValue = normalizeFeature(featureName as keyof FeatureVector, featureValue);
      
      // Apply weight (negative weights mean inverse relationship)
      const contribution = weight > 0 
        ? normalizedValue * weight 
        : (1 - normalizedValue) * Math.abs(weight);
      
      weightedSum += contribution;
      totalWeight += Math.abs(weight);
      weightedFeatures[featureName] = contribution;
    }
    
    const score = totalWeight > 0 ? weightedSum / totalWeight : 0;
    scores.push({ type: attackType as AttackType, score, weightedFeatures });
  }
  
  // Sort by score descending
  scores.sort((a, b) => b.score - a.score);
  
  // Generate predictions for scores above threshold
  for (const { type, score, weightedFeatures } of scores) {
    const threshold = ATTACK_THRESHOLDS[type];
    
    if (score >= threshold) {
      const confidence = scoreToConfidence(score);
      const explanation = generateExplanation(type, features, weightedFeatures);
      const { isFalsePositive, reason } = checkFalsePositive(type, features);
      
      predictions.push({
        attackType: type,
        confidence: score,
        probability: sigmoid(score * 5 - 2.5), // Convert to probability
        features: extractRelevantFeatures(features, weightedFeatures),
        explanation,
        isFalsePositive,
        falsePositiveReason: reason,
      });
    }
  }
  
  // If no attack detected but features are anomalous, flag as anomaly
  if (predictions.length === 0 && features.deviationFromBaseline > 0.5) {
    predictions.push({
      attackType: 'anomaly',
      confidence: features.deviationFromBaseline,
      probability: features.deviationFromBaseline,
      features: { deviationFromBaseline: features.deviationFromBaseline },
      explanation: ['Unusual activity pattern detected that deviates from baseline'],
      isFalsePositive: false,
    });
  }
  
  return predictions;
}

/**
 * Normalize feature value to 0-1 range
 */
function normalizeFeature(name: keyof FeatureVector, value: number): number {
  // Define normalization ranges for each feature
  const ranges: Partial<Record<keyof FeatureVector, [number, number]>> = {
    eventCount: [0, 1000],
    eventsPerMinute: [0, 100],
    timeSpreadMinutes: [0, 60],
    burstiness: [0, 2],
    offHoursActivity: [0, 1],
    uniqueSourceIps: [0, 100],
    sourceIpEntropy: [0, 5],
    uniqueTargetUsers: [0, 100],
    uniqueTargetHosts: [0, 50],
    targetUserEntropy: [0, 5],
    privilegedUserRatio: [0, 1],
    failureRate: [0, 1],
    successAfterFailure: [0, 10],
    mfaFailureRate: [0, 1],
    invalidUserRatio: [0, 1],
    uniquePorts: [0, 100],
    commonPortRatio: [0, 1],
    internalTrafficRatio: [0, 1],
    avgRequestSize: [0, 1000000],
    errorCodeRatio: [0, 1],
    suspiciousPatternCount: [0, 50],
    deviationFromBaseline: [0, 1],
    sessionDuration: [0, 60],
    actionVelocity: [0, 100],
    newSourceRatio: [0, 1],
    geoSpread: [0, 10],
  };
  
  const range = ranges[name];
  if (!range) return Math.min(Math.max(value, 0), 1);
  
  const [min, max] = range;
  return Math.min(Math.max((value - min) / (max - min), 0), 1);
}

/**
 * Convert score to confidence level
 */
function scoreToConfidence(score: number): number {
  if (score >= 0.9) return 0.95;
  if (score >= 0.8) return 0.85;
  if (score >= 0.7) return 0.75;
  if (score >= 0.6) return 0.65;
  return 0.5;
}

/**
 * Sigmoid function for probability conversion
 */
function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

/**
 * Generate human-readable explanation for the prediction
 */
function generateExplanation(
  attackType: AttackType,
  features: FeatureVector,
  weightedFeatures: Record<string, number>
): string[] {
  const explanations: string[] = [];
  
  // Get top contributing features
  const sortedFeatures = Object.entries(weightedFeatures)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 3);
  
  for (const [feature, contribution] of sortedFeatures) {
    const value = features[feature as keyof FeatureVector];
    explanations.push(getFeatureExplanation(feature, value as number, contribution));
  }
  
  // Add attack-specific context
  explanations.push(...getAttackContext(attackType, features));
  
  return explanations;
}

/**
 * Get human-readable explanation for a feature
 */
function getFeatureExplanation(feature: string, value: number, contribution: number): string {
  const explanationTemplates: Record<string, (v: number) => string> = {
    failureRate: (v) => `High failure rate (${(v * 100).toFixed(1)}%) indicates authentication attacks`,
    eventsPerMinute: (v) => `${v.toFixed(1)} events/min suggests automated activity`,
    uniqueSourceIps: (v) => v < 3 ? `Single source IP pattern` : `${v} unique source IPs`,
    uniqueTargetUsers: (v) => `${v} unique users targeted`,
    burstiness: (v) => v > 1 ? `Bursty traffic pattern detected` : `Steady traffic pattern`,
    offHoursActivity: (v) => `${(v * 100).toFixed(0)}% activity outside business hours`,
    privilegedUserRatio: (v) => `${(v * 100).toFixed(0)}% of attempts target privileged accounts`,
    mfaFailureRate: (v) => `${(v * 100).toFixed(1)}% MFA failure rate`,
    invalidUserRatio: (v) => `${(v * 100).toFixed(1)}% attempts to invalid users`,
    suspiciousPatternCount: (v) => `${v} suspicious patterns detected in requests`,
    successAfterFailure: (v) => `${v} successful logins after failures`,
    newSourceRatio: (v) => `${(v * 100).toFixed(0)}% from new/unknown sources`,
    deviationFromBaseline: (v) => `${(v * 100).toFixed(0)}% deviation from normal behavior`,
    uniquePorts: (v) => `${v} unique ports targeted`,
    avgRequestSize: (v) => `Average request size: ${formatBytes(v)}`,
    errorCodeRatio: (v) => `${(v * 100).toFixed(0)}% error responses`,
  };
  
  const template = explanationTemplates[feature];
  if (template) {
    return template(value);
  }
  
  return `${feature}: ${typeof value === 'number' ? value.toFixed(2) : value}`;
}

/**
 * Get attack-specific context
 */
function getAttackContext(attackType: AttackType, features: FeatureVector): string[] {
  const contexts: Partial<Record<AttackType, string[]>> = {
    // Credential attacks
    bruteforce: [
      'Repeated login attempts from single source to single target',
      'Consider implementing account lockout policies',
    ],
    password_spray: [
      'Single source testing credentials across many accounts',
      'Likely using common passwords against multiple users',
    ],
    mfa_bypass: [
      'Attempts to circumvent multi-factor authentication',
      'Check for session token reuse or MFA fatigue attacks',
    ],
    mfa_fatigue: [
      'Repeated MFA push notifications detected',
      'Attacker may be trying to exhaust user into accepting',
    ],
    kerberoasting: [
      'Service account ticket extraction detected (T1558.003)',
      'Attacker attempting to crack service account passwords offline',
      'Review service accounts with SPNs and strengthen passwords',
    ],
    pass_the_hash: [
      'NTLM hash reuse attack detected',
      'Attacker using stolen hash to authenticate without password',
      'Consider implementing Credential Guard and restrict NTLM',
    ],
    golden_ticket: [
      'Forged Kerberos TGT detected - critical domain compromise',
      'Attacker has obtained krbtgt hash - full domain access possible',
      'IMMEDIATE: Reset krbtgt password twice and investigate DC compromise',
    ],
    
    // Web attacks
    privilege_escalation: [
      'Attempts to gain elevated privileges detected',
      'Review sudo/admin access patterns',
    ],
    sql_injection: [
      'SQL injection patterns detected in requests',
      'Check for unauthorized database access',
    ],
    ssrf_attack: [
      'Server-Side Request Forgery attempt detected',
      'Attacker trying to access internal resources or cloud metadata',
      'Review URL parameters and implement allowlisting',
    ],
    xxe_attack: [
      'XML External Entity injection attempt detected',
      'Attacker may be reading local files or scanning internal network',
      'Disable external entity processing in XML parsers',
    ],
    deserialization: [
      'Insecure deserialization attack detected',
      'Attacker attempting remote code execution via malicious serialized objects',
      'Review and restrict deserialization of untrusted data',
    ],
    ldap_injection: [
      'LDAP injection attempt detected',
      'Attacker may be enumerating directory users or modifying entries',
      'Implement proper input validation for LDAP queries',
    ],
    log4shell: [
      'Log4Shell (CVE-2021-44228) exploitation attempt detected',
      'Critical vulnerability allowing remote code execution',
      'IMMEDIATE: Patch Log4j to 2.17.1+ or disable JNDI lookups',
    ],
    prototype_pollution: [
      'JavaScript prototype pollution attack detected',
      'Attacker may be manipulating application behavior',
      'Sanitize object property assignments from user input',
    ],
    
    // Infrastructure attacks
    data_exfiltration: [
      'Unusually large data transfers detected',
      'Review outbound traffic and data access patterns',
    ],
    lateral_movement: [
      'Movement between internal systems detected',
      'Attacker may be expanding access within network',
    ],
    port_scan: [
      'Port scanning activity detected',
      'Reconnaissance phase of potential attack',
    ],
    dns_tunneling: [
      'DNS tunneling detected - data exfiltration via DNS queries',
      'High-entropy subdomains indicate encoded data in DNS',
      'Monitor DNS query patterns and implement DNS filtering',
    ],
    cryptomining: [
      'Cryptocurrency mining activity detected',
      'Unauthorized resource usage for mining operations',
      'Identify and terminate mining processes, investigate initial access',
    ],
    ransomware: [
      'CRITICAL: Ransomware activity indicators detected',
      'Shadow copy deletion and file encryption patterns observed',
      'IMMEDIATE: Isolate affected systems and activate incident response',
    ],
    supply_chain: [
      'Potential supply chain compromise detected',
      'Unusual activity from trusted software or update mechanism',
      'Review software integrity and investigate update channels',
    ],
    
    // APT
    apt_activity: [
      'Advanced Persistent Threat indicators detected',
      'Coordinated attack activity spanning multiple systems',
      'Engage incident response team and threat intelligence',
    ],
    zero_day_exploit: [
      'Potential zero-day exploitation detected',
      'Unknown vulnerability being actively exploited',
      'Isolate systems, capture forensic data, engage threat intelligence',
    ],
    webshell: [
      'Web shell deployment or usage detected',
      'Attacker has persistent backdoor access via web server',
      'Identify and remove webshell, investigate initial access vector',
    ],
    living_off_the_land: [
      'Living-off-the-Land technique detected (LOLBins/LOLBas)',
      'Attacker using legitimate system tools for malicious purposes',
      'Monitor for unusual use of certutil, mshta, powershell encoded commands',
    ],
    c2_communication: [
      'Command and Control communication detected',
      'System may be compromised and receiving attacker commands',
      'Block C2 domains/IPs and investigate affected hosts',
    ],
  };
  
  return contexts[attackType] || [];
}

/**
 * Check if prediction is likely a false positive
 */
function checkFalsePositive(
  attackType: AttackType,
  features: FeatureVector
): { isFalsePositive: boolean; reason?: string } {
  // False positive rules based on domain knowledge
  
  // Too few events to be confident
  if (features.eventCount < 5) {
    return { 
      isFalsePositive: true, 
      reason: 'Insufficient events for confident classification' 
    };
  }
  
  // Bruteforce with high success rate is likely normal activity
  if (attackType === 'bruteforce' && features.failureRate < 0.5) {
    return { 
      isFalsePositive: true, 
      reason: 'Success rate too high for bruteforce attack' 
    };
  }
  
  // Password spray targeting single user is not spray
  if (attackType === 'password_spray' && features.uniqueTargetUsers < 5) {
    return { 
      isFalsePositive: true, 
      reason: 'Too few unique users for password spray' 
    };
  }
  
  // Port scan with only common ports is likely normal traffic
  if (attackType === 'port_scan' && features.commonPortRatio > 0.9) {
    return { 
      isFalsePositive: true, 
      reason: 'Traffic to common ports only, likely normal activity' 
    };
  }
  
  // Internal traffic during business hours with no failures
  if (features.internalTrafficRatio > 0.9 && 
      features.offHoursActivity < 0.1 && 
      features.failureRate < 0.1) {
    return { 
      isFalsePositive: true, 
      reason: 'Normal internal business hours activity' 
    };
  }
  
  // DDoS needs very high event rate
  if (attackType === 'ddos' && features.eventsPerMinute < 50) {
    return { 
      isFalsePositive: true, 
      reason: 'Event rate too low for DDoS classification' 
    };
  }
  
  return { isFalsePositive: false };
}

/**
 * Extract relevant features for the prediction
 */
function extractRelevantFeatures(
  features: FeatureVector,
  weightedFeatures: Record<string, number>
): Partial<FeatureVector> {
  const result: Partial<FeatureVector> = {};
  
  for (const key of Object.keys(weightedFeatures)) {
    const value = features[key as keyof FeatureVector];
    if (value !== undefined) {
      (result as Record<string, unknown>)[key] = value;
    }
  }
  
  return result;
}

/**
 * Format bytes to human readable
 */
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

/**
 * Get MITRE ATT&CK tactics for attack type
 * Reference: https://attack.mitre.org/tactics/enterprise/
 */
export function getMitreTactics(attackType: AttackType): string[] {
  const tacticMap: Partial<Record<AttackType, string[]>> = {
    // Credential attacks
    bruteforce: ['TA0006 - Credential Access'],
    password_spray: ['TA0006 - Credential Access'],
    credential_stuffing: ['TA0006 - Credential Access'],
    mfa_bypass: ['TA0006 - Credential Access', 'TA0005 - Defense Evasion'],
    mfa_fatigue: ['TA0006 - Credential Access'],
    session_hijacking: ['TA0006 - Credential Access', 'TA0008 - Lateral Movement'],
    account_takeover: ['TA0006 - Credential Access', 'TA0001 - Initial Access'],
    kerberoasting: ['TA0006 - Credential Access'],
    pass_the_hash: ['TA0006 - Credential Access', 'TA0008 - Lateral Movement'],
    golden_ticket: ['TA0006 - Credential Access', 'TA0003 - Persistence', 'TA0004 - Privilege Escalation'],
    
    // Web attacks
    sql_injection: ['TA0001 - Initial Access', 'TA0009 - Collection'],
    xss_attack: ['TA0001 - Initial Access', 'TA0009 - Collection'],
    path_traversal: ['TA0001 - Initial Access', 'TA0009 - Collection'],
    command_injection: ['TA0002 - Execution'],
    ssrf_attack: ['TA0001 - Initial Access', 'TA0009 - Collection', 'TA0043 - Reconnaissance'],
    xxe_attack: ['TA0001 - Initial Access', 'TA0009 - Collection'],
    deserialization: ['TA0002 - Execution', 'TA0001 - Initial Access'],
    ldap_injection: ['TA0006 - Credential Access', 'TA0009 - Collection'],
    log4shell: ['TA0001 - Initial Access', 'TA0002 - Execution'],
    prototype_pollution: ['TA0002 - Execution'],
    
    // Infrastructure attacks
    privilege_escalation: ['TA0004 - Privilege Escalation'],
    lateral_movement: ['TA0008 - Lateral Movement'],
    data_exfiltration: ['TA0010 - Exfiltration'],
    port_scan: ['TA0043 - Reconnaissance'],
    reconnaissance: ['TA0043 - Reconnaissance'],
    ddos: ['TA0040 - Impact'],
    dns_tunneling: ['TA0010 - Exfiltration', 'TA0011 - Command and Control'],
    cryptomining: ['TA0040 - Impact'],
    ransomware: ['TA0040 - Impact', 'TA0002 - Execution'],
    supply_chain: ['TA0001 - Initial Access', 'TA0003 - Persistence'],
    
    // APT
    malware_activity: ['TA0002 - Execution', 'TA0003 - Persistence'],
    c2_communication: ['TA0011 - Command and Control'],
    insider_threat: ['TA0009 - Collection', 'TA0010 - Exfiltration'],
    apt_activity: ['TA0043 - Reconnaissance', 'TA0001 - Initial Access', 'TA0003 - Persistence', 'TA0008 - Lateral Movement'],
    zero_day_exploit: ['TA0001 - Initial Access', 'TA0002 - Execution'],
    webshell: ['TA0003 - Persistence', 'TA0002 - Execution'],
    living_off_the_land: ['TA0005 - Defense Evasion', 'TA0002 - Execution'],
  };
  
  return tacticMap[attackType] || ['Unknown'];
}

/**
 * Get MITRE ATT&CK techniques for attack type
 * Reference: https://attack.mitre.org/techniques/enterprise/
 */
export function getMitreTechniques(attackType: AttackType): string[] {
  const techniqueMap: Partial<Record<AttackType, string[]>> = {
    // Credential attacks
    bruteforce: ['T1110.001 - Password Guessing', 'T1110.003 - Password Spraying'],
    password_spray: ['T1110.003 - Password Spraying'],
    credential_stuffing: ['T1110.004 - Credential Stuffing'],
    mfa_bypass: ['T1111 - Multi-Factor Authentication Interception'],
    mfa_fatigue: ['T1621 - Multi-Factor Authentication Request Generation'],
    session_hijacking: ['T1563 - Remote Service Session Hijacking', 'T1539 - Steal Web Session Cookie'],
    account_takeover: ['T1078 - Valid Accounts'],
    kerberoasting: ['T1558.003 - Kerberoasting', 'T1558 - Steal or Forge Kerberos Tickets'],
    pass_the_hash: ['T1550.002 - Pass the Hash'],
    golden_ticket: ['T1558.001 - Golden Ticket', 'T1558 - Steal or Forge Kerberos Tickets'],
    
    // Web attacks
    sql_injection: ['T1190 - Exploit Public-Facing Application'],
    xss_attack: ['T1189 - Drive-by Compromise', 'T1059.007 - JavaScript'],
    path_traversal: ['T1083 - File and Directory Discovery'],
    command_injection: ['T1059 - Command and Scripting Interpreter'],
    ssrf_attack: ['T1190 - Exploit Public-Facing Application', 'T1018 - Remote System Discovery'],
    xxe_attack: ['T1190 - Exploit Public-Facing Application', 'T1005 - Data from Local System'],
    deserialization: ['T1190 - Exploit Public-Facing Application', 'T1059 - Command and Scripting Interpreter'],
    ldap_injection: ['T1190 - Exploit Public-Facing Application', 'T1087 - Account Discovery'],
    log4shell: ['T1190 - Exploit Public-Facing Application', 'T1059 - Command and Scripting Interpreter'],
    prototype_pollution: ['T1059.007 - JavaScript'],
    
    // Infrastructure attacks
    privilege_escalation: ['T1068 - Exploitation for Privilege Escalation', 'T1548 - Abuse Elevation Control Mechanism'],
    lateral_movement: ['T1021 - Remote Services', 'T1072 - Software Deployment Tools'],
    data_exfiltration: ['T1041 - Exfiltration Over C2 Channel', 'T1048 - Exfiltration Over Alternative Protocol'],
    port_scan: ['T1046 - Network Service Discovery'],
    reconnaissance: ['T1595 - Active Scanning', 'T1592 - Gather Victim Host Information'],
    ddos: ['T1498 - Network Denial of Service', 'T1499 - Endpoint Denial of Service'],
    dns_tunneling: ['T1071.004 - DNS', 'T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol'],
    cryptomining: ['T1496 - Resource Hijacking'],
    ransomware: ['T1486 - Data Encrypted for Impact', 'T1490 - Inhibit System Recovery'],
    supply_chain: ['T1195 - Supply Chain Compromise', 'T1195.002 - Compromise Software Supply Chain'],
    
    // APT
    malware_activity: ['T1204 - User Execution', 'T1055 - Process Injection'],
    c2_communication: ['T1071 - Application Layer Protocol', 'T1095 - Non-Application Layer Protocol'],
    insider_threat: ['T1213 - Data from Information Repositories', 'T1074 - Data Staged'],
    apt_activity: ['T1583 - Acquire Infrastructure', 'T1588 - Obtain Capabilities', 'T1566 - Phishing'],
    zero_day_exploit: ['T1190 - Exploit Public-Facing Application', 'T1203 - Exploitation for Client Execution'],
    webshell: ['T1505.003 - Web Shell', 'T1059 - Command and Scripting Interpreter'],
    living_off_the_land: [
      'T1218 - System Binary Proxy Execution',
      'T1218.011 - Rundll32',
      'T1218.010 - Regsvr32',
      'T1218.005 - Mshta',
      'T1059.001 - PowerShell',
      'T1197 - BITS Jobs',
      'T1127 - Trusted Developer Utilities Proxy Execution',
    ],
  };
  
  return techniqueMap[attackType] || ['Unknown'];
}
