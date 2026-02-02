// ML Types for SIEM Anomaly Detection
// Based on MITRE ATT&CK, OWASP Top 10, and known cyberattack patterns

export type AttackType =
  // Credential-based attacks
  | 'bruteforce'
  | 'password_spray'
  | 'credential_stuffing'
  | 'mfa_bypass'
  | 'mfa_fatigue'
  | 'session_hijacking'
  | 'account_takeover'
  | 'kerberoasting'          // NEW: Kerberos ticket attacks (APT29, etc.)
  | 'pass_the_hash'          // NEW: NTLM hash reuse attacks
  | 'golden_ticket'          // NEW: Forged Kerberos tickets (APT groups)
  
  // Web application attacks (OWASP Top 10)
  | 'sql_injection'
  | 'xss_attack'
  | 'path_traversal'
  | 'command_injection'
  | 'ssrf_attack'            // NEW: Server-Side Request Forgery
  | 'xxe_attack'             // NEW: XML External Entity
  | 'deserialization'        // NEW: Insecure deserialization
  | 'ldap_injection'         // NEW: LDAP injection
  | 'log4shell'              // NEW: Log4j CVE-2021-44228
  | 'prototype_pollution'    // NEW: JavaScript prototype pollution
  | 'file_inclusion'         // NEW: File inclusion attacks (LFI/RFI)
  
  // Infrastructure attacks
  | 'privilege_escalation'
  | 'lateral_movement'
  | 'data_exfiltration'
  | 'port_scan'
  | 'ddos'
  | 'reconnaissance'
  | 'dns_tunneling'          // NEW: DNS-based data exfiltration
  | 'cryptomining'           // NEW: Cryptocurrency mining malware
  | 'ransomware'             // NEW: Ransomware activity
  | 'supply_chain'           // NEW: Supply chain attacks (SolarWinds-style)
  
  // Advanced persistent threats
  | 'malware_activity'
  | 'c2_communication'
  | 'insider_threat'
  | 'apt_activity'           // NEW: Generic APT patterns
  | 'zero_day_exploit'       // NEW: Unknown exploit attempts
  | 'webshell'               // NEW: Web shell deployment/usage
  | 'living_off_the_land'    // NEW: LOLBins/LOLBas abuse
  
  // Generic
  | 'anomaly'
  | 'unknown';

export interface FeatureVector {
  // Time-based features
  eventCount: number;
  eventsPerMinute: number;
  timeSpreadMinutes: number;
  burstiness: number;  // Coefficient of variation in event timing
  offHoursActivity: number;  // % of events outside business hours

  // Source-based features
  uniqueSourceIps: number;
  sourceIpEntropy: number;
  geoSpread: number;  // Number of unique countries (if available)
  newSourceRatio: number;  // % of never-seen-before IPs

  // Target-based features
  uniqueTargetUsers: number;
  uniqueTargetHosts: number;
  targetUserEntropy: number;
  privilegedUserRatio: number;  // % targeting admin/root

  // Authentication features
  failureRate: number;
  successAfterFailure: number;
  mfaFailureRate: number;
  invalidUserRatio: number;

  // Network features
  uniquePorts: number;
  commonPortRatio: number;  // % on ports 22, 80, 443, etc.
  internalTrafficRatio: number;

  // Payload/Request features
  avgRequestSize: number;
  errorCodeRatio: number;
  suspiciousPatternCount: number;

  // Behavioral features
  deviationFromBaseline: number;
  sessionDuration: number;
  actionVelocity: number;  // Actions per session
}

export interface MLPrediction {
  attackType: AttackType;
  confidence: number;  // 0-1
  probability: number;  // 0-1
  features: Partial<FeatureVector>;
  explanation: string[];
  isFalsePositive: boolean;
  falsePositiveReason?: string;
}

export interface CorrelatedEvent {
  id: string;
  timestamp: string;
  logSource: string;  // 'auth', 'web', 'database', 'firewall', 'system'
  logType: string;
  severity: string;
  sourceIp?: string;
  targetUser?: string;
  targetHost?: string;
  action?: string;
  outcome?: string;
  message: string;
  relatedEventIds: string[];
  correlationScore: number;  // How strongly related to the attack chain
}

export interface AttackChain {
  id: string;
  startTime: string;
  endTime: string;
  attackType: AttackType;
  stage: 'reconnaissance' | 'initial_access' | 'execution' | 'persistence' | 'privilege_escalation' | 'lateral_movement' | 'exfiltration' | 'complete';
  events: CorrelatedEvent[];
  sourceIps: string[];
  targetUsers: string[];
  targetHosts: string[];
  prediction: MLPrediction;
  mitreTactics: string[];
  mitreTechniques: string[];
  recommendation: string;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  logSource: string;
  eventType: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  sourceIp?: string;
  targetUser?: string;
  relatedAttackChainId?: string;
  isAnomaly: boolean;
  anomalyScore: number;
}

export interface CorrelationResult {
  success: boolean;
  totalEvents: number;
  correlatedEvents: number;
  attackChains: AttackChain[];
  timeline: TimelineEvent[];
  summary: {
    totalAlerts: number;
    criticalAlerts: number;
    falsePositivesFiltered: number;
    attackTypesDetected: AttackType[];
    mostTargetedUsers: Array<{ user: string; count: number }>;
    mostActiveSourceIps: Array<{ ip: string; count: number; threatScore: number }>;
    riskScore: number;  // Overall risk 0-100
  };
  recommendations: string[];
}

// Baseline profile for anomaly detection
export interface BaselineProfile {
  hourlyDistribution: number[];  // 24 values for each hour
  dailyDistribution: number[];   // 7 values for each day
  avgEventsPerHour: number;
  stdEventsPerHour: number;
  commonSourceIps: Set<string>;
  commonUsers: Set<string>;
  commonPorts: Set<number>;
  avgFailureRate: number;
  avgSessionDuration: number;
}
