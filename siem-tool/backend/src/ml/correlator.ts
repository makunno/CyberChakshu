// Log Correlation Engine
// Correlates events across multiple log sources to detect attack chains

import { ParsedLogEntry } from '../types';
import { 
  AttackChain, 
  CorrelatedEvent, 
  TimelineEvent, 
  CorrelationResult,
  AttackType,
  MLPrediction,
} from './types';
import { extractFeatures, buildBaseline } from './feature-extractor';
import { classifyAttack, getMitreTactics, getMitreTechniques } from './classifier';
import { generateId } from '../utils/helpers';

/**
 * Log source categories for correlation
 */
type LogSource = 'auth' | 'web' | 'database' | 'firewall' | 'system' | 'mail' | 'network' | 'other';

/**
 * Categorize log type to source category
 */
function getLogSource(logType: string): LogSource {
  const sourceMap: Record<string, LogSource> = {
    // Auth
    ssh_auth: 'auth',
    pam: 'auth',
    vsftpd: 'auth',
    proftpd: 'auth',
    // Web
    apache: 'web',
    nginx: 'web',
    iis: 'web',
    django: 'web',
    flask: 'web',
    laravel: 'web',
    rails: 'web',
    express: 'web',
    fastapi: 'web',
    gunicorn: 'web',
    uvicorn: 'web',
    // Database
    mysql_error: 'database',
    mysql_query: 'database',
    mysql_slow: 'database',
    postgres_error: 'database',
    postgres_auth: 'database',
    postgres_statement: 'database',
    oracle_alert: 'database',
    oracle_listener: 'database',
    oracle_audit: 'database',
    sqlserver_error: 'database',
    sqlserver_audit: 'database',
    sqlserver_transaction: 'database',
    mongodb_server: 'database',
    mongodb_audit: 'database',
    // Firewall
    iptables: 'firewall',
    ufw: 'firewall',
    nftables: 'firewall',
    firewalld: 'firewall',
    windows_firewall: 'firewall',
    palo_alto: 'firewall',
    fortigate: 'firewall',
    cisco_asa: 'firewall',
    checkpoint: 'firewall',
    aws_vpc_flow: 'firewall',
    azure_nsg: 'firewall',
    gcp_vpc: 'firewall',
    // System
    syslog: 'system',
    systemd: 'system',
    kernel: 'system',
    audit: 'system',
    package: 'system',
    cron: 'system',
    daemon: 'system',
    windows_security: 'system',
    windows_system: 'system',
    windows_application: 'system',
    // Mail
    postfix: 'mail',
    sendmail: 'mail',
    exim: 'mail',
    dovecot: 'mail',
    exchange: 'mail',
    // Network
    dns: 'network',
    dhcp: 'network',
    proxy: 'network',
  };
  
  return sourceMap[logType] || 'other';
}

/**
 * Multi-log correlation engine
 */
export function correlateMultipleLogs(
  logSources: Array<{ name: string; entries: ParsedLogEntry[] }>
): CorrelationResult {
  // Combine all entries with source tracking
  const allEntries: ParsedLogEntry[] = [];
  const sourceNames = new Map<string, string>();
  
  for (const source of logSources) {
    for (const entry of source.entries) {
      allEntries.push(entry);
      sourceNames.set(entry.id, source.name);
    }
  }
  
  // Sort all entries by timestamp (filter out invalid timestamps)
  const sortedEntries = [...allEntries]
    .filter(e => {
      if (!e.timestamp) return false;
      const time = new Date(e.timestamp).getTime();
      return !isNaN(time) && time > 0;
    })
    .sort((a, b) => {
      const ta = new Date(a.timestamp!).getTime();
      const tb = new Date(b.timestamp!).getTime();
      return ta - tb;
    });
  
  if (sortedEntries.length === 0) {
    return createEmptyResult();
  }
  
  // Build baseline from all entries
  const baseline = buildBaseline(sortedEntries);
  
  // Group entries by correlation keys
  const byIp = groupBySourceIp(sortedEntries);
  const byUser = groupByUser(sortedEntries);
  const byTimeWindow = groupByTimeWindow(sortedEntries, 5 * 60 * 1000); // 5-minute windows
  
  // Detect attack chains
  const attackChains: AttackChain[] = [];
  const processedEventIds = new Set<string>();
  
  // 1. Correlate by source IP (most common attack pattern)
  for (const [ip, entries] of byIp) {
    const chain = analyzeIpActivity(ip, entries, baseline, sourceNames);
    if (chain) {
      attackChains.push(chain);
      chain.events.forEach(e => processedEventIds.add(e.id));
    }
  }
  
  // 2. Correlate by target user (account takeover patterns)
  for (const [user, entries] of byUser) {
    // Skip if already covered by IP-based correlation
    const uncoveredEntries = entries.filter(e => !processedEventIds.has(e.id));
    if (uncoveredEntries.length < 5) continue;
    
    const chain = analyzeUserActivity(user, uncoveredEntries, baseline, sourceNames);
    if (chain) {
      attackChains.push(chain);
      chain.events.forEach(e => processedEventIds.add(e.id));
    }
  }
  
  // 3. Correlate by time window (coordinated attacks)
  for (const entries of byTimeWindow.values()) {
    const uncoveredEntries = entries.filter(e => !processedEventIds.has(e.id));
    if (uncoveredEntries.length < 10) continue;
    
    const chain = analyzeTimeWindowActivity(uncoveredEntries, baseline, sourceNames);
    if (chain) {
      attackChains.push(chain);
      chain.events.forEach(e => processedEventIds.add(e.id));
    }
  }
  
  // 4. Cross-source correlation (e.g., web attack followed by DB access)
  const crossSourceChains = detectCrossSourceAttacks(sortedEntries, sourceNames, baseline);
  for (const chain of crossSourceChains) {
    if (!chain.events.some(e => processedEventIds.has(e.id))) {
      attackChains.push(chain);
    }
  }
  
  // Filter out false positives
  const validChains = attackChains.filter(chain => !chain.prediction.isFalsePositive);
  
  // Build unified timeline
  const timeline = buildTimeline(sortedEntries, validChains, sourceNames);
  
  // Generate summary
  const summary = generateSummary(sortedEntries, validChains, attackChains.length - validChains.length);
  
  // Generate recommendations
  const recommendations = generateRecommendations(validChains);
  
  return {
    success: true,
    totalEvents: allEntries.length,
    correlatedEvents: processedEventIds.size,
    attackChains: validChains,
    timeline,
    summary,
    recommendations,
  };
}

/**
 * Group entries by source IP
 */
function groupBySourceIp(entries: ParsedLogEntry[]): Map<string, ParsedLogEntry[]> {
  const groups = new Map<string, ParsedLogEntry[]>();
  
  for (const entry of entries) {
    const ip = entry.source.ip;
    if (!ip) continue;
    
    if (!groups.has(ip)) {
      groups.set(ip, []);
    }
    groups.get(ip)!.push(entry);
  }
  
  return groups;
}

/**
 * Group entries by target user
 */
function groupByUser(entries: ParsedLogEntry[]): Map<string, ParsedLogEntry[]> {
  const groups = new Map<string, ParsedLogEntry[]>();
  
  for (const entry of entries) {
    const user = entry.user?.name;
    if (!user) continue;
    
    if (!groups.has(user)) {
      groups.set(user, []);
    }
    groups.get(user)!.push(entry);
  }
  
  return groups;
}

/**
 * Group entries by time window
 */
function groupByTimeWindow(
  entries: ParsedLogEntry[], 
  windowMs: number
): Map<string, ParsedLogEntry[]> {
  const groups = new Map<string, ParsedLogEntry[]>();
  
  for (const entry of entries) {
    if (!entry.timestamp) continue;
    
    const time = new Date(entry.timestamp).getTime();
    const windowStart = Math.floor(time / windowMs) * windowMs;
    const key = new Date(windowStart).toISOString();
    
    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key)!.push(entry);
  }
  
  return groups;
}

/**
 * Analyze activity from a single IP
 */
function analyzeIpActivity(
  ip: string,
  entries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>,
  sourceNames: Map<string, string>
): AttackChain | null {
  if (entries.length < 5) return null;
  
  // Extract features
  const features = extractFeatures(entries, baseline);
  
  // Classify attack
  const predictions = classifyAttack(features);
  if (predictions.length === 0) return null;
  
  const topPrediction = predictions[0];
  if (topPrediction.isFalsePositive) return null;
  
  // Build attack chain
  const correlatedEvents: CorrelatedEvent[] = entries.map(entry => ({
    id: entry.id,
    timestamp: entry.timestamp!,
    logSource: getLogSource(entry.logType),
    logType: entry.logType,
    severity: entry.severity,
    sourceIp: entry.source.ip,
    targetUser: entry.user?.name,
    targetHost: entry.destination?.hostname || entry.source.hostname,
    action: entry.action,
    outcome: entry.outcome,
    message: entry.message,
    relatedEventIds: [],
    correlationScore: calculateCorrelationScore(entry, topPrediction.attackType),
  }));
  
  // Sort by timestamp
  correlatedEvents.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  
  // Determine attack stage
  const stage = determineAttackStage(correlatedEvents, topPrediction.attackType);
  
  return {
    id: generateId(),
    startTime: correlatedEvents[0].timestamp,
    endTime: correlatedEvents[correlatedEvents.length - 1].timestamp,
    attackType: topPrediction.attackType,
    stage,
    events: correlatedEvents,
    sourceIps: [ip],
    targetUsers: [...new Set(correlatedEvents.map(e => e.targetUser).filter(Boolean))] as string[],
    targetHosts: [...new Set(correlatedEvents.map(e => e.targetHost).filter(Boolean))] as string[],
    prediction: topPrediction,
    mitreTactics: getMitreTactics(topPrediction.attackType),
    mitreTechniques: getMitreTechniques(topPrediction.attackType),
    recommendation: generateChainRecommendation(topPrediction.attackType, correlatedEvents),
  };
}

/**
 * Analyze activity targeting a single user
 */
function analyzeUserActivity(
  user: string,
  entries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>,
  sourceNames: Map<string, string>
): AttackChain | null {
  if (entries.length < 5) return null;
  
  const features = extractFeatures(entries, baseline);
  const predictions = classifyAttack(features);
  
  if (predictions.length === 0) return null;
  
  const topPrediction = predictions[0];
  if (topPrediction.isFalsePositive) return null;
  
  const correlatedEvents: CorrelatedEvent[] = entries.map(entry => ({
    id: entry.id,
    timestamp: entry.timestamp!,
    logSource: getLogSource(entry.logType),
    logType: entry.logType,
    severity: entry.severity,
    sourceIp: entry.source.ip,
    targetUser: entry.user?.name,
    targetHost: entry.destination?.hostname || entry.source.hostname,
    action: entry.action,
    outcome: entry.outcome,
    message: entry.message,
    relatedEventIds: [],
    correlationScore: calculateCorrelationScore(entry, topPrediction.attackType),
  }));
  
  correlatedEvents.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  
  return {
    id: generateId(),
    startTime: correlatedEvents[0].timestamp,
    endTime: correlatedEvents[correlatedEvents.length - 1].timestamp,
    attackType: topPrediction.attackType,
    stage: determineAttackStage(correlatedEvents, topPrediction.attackType),
    events: correlatedEvents,
    sourceIps: [...new Set(correlatedEvents.map(e => e.sourceIp).filter(Boolean))] as string[],
    targetUsers: [user],
    targetHosts: [...new Set(correlatedEvents.map(e => e.targetHost).filter(Boolean))] as string[],
    prediction: topPrediction,
    mitreTactics: getMitreTactics(topPrediction.attackType),
    mitreTechniques: getMitreTechniques(topPrediction.attackType),
    recommendation: generateChainRecommendation(topPrediction.attackType, correlatedEvents),
  };
}

/**
 * Analyze activity in a time window
 */
function analyzeTimeWindowActivity(
  entries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>,
  sourceNames: Map<string, string>
): AttackChain | null {
  if (entries.length < 10) return null;
  
  const features = extractFeatures(entries, baseline);
  const predictions = classifyAttack(features);
  
  if (predictions.length === 0) return null;
  
  const topPrediction = predictions[0];
  if (topPrediction.isFalsePositive) return null;
  
  const correlatedEvents: CorrelatedEvent[] = entries.map(entry => ({
    id: entry.id,
    timestamp: entry.timestamp!,
    logSource: getLogSource(entry.logType),
    logType: entry.logType,
    severity: entry.severity,
    sourceIp: entry.source.ip,
    targetUser: entry.user?.name,
    targetHost: entry.destination?.hostname || entry.source.hostname,
    action: entry.action,
    outcome: entry.outcome,
    message: entry.message,
    relatedEventIds: [],
    correlationScore: calculateCorrelationScore(entry, topPrediction.attackType),
  }));
  
  correlatedEvents.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  
  return {
    id: generateId(),
    startTime: correlatedEvents[0].timestamp,
    endTime: correlatedEvents[correlatedEvents.length - 1].timestamp,
    attackType: topPrediction.attackType,
    stage: determineAttackStage(correlatedEvents, topPrediction.attackType),
    events: correlatedEvents,
    sourceIps: [...new Set(correlatedEvents.map(e => e.sourceIp).filter(Boolean))] as string[],
    targetUsers: [...new Set(correlatedEvents.map(e => e.targetUser).filter(Boolean))] as string[],
    targetHosts: [...new Set(correlatedEvents.map(e => e.targetHost).filter(Boolean))] as string[],
    prediction: topPrediction,
    mitreTactics: getMitreTactics(topPrediction.attackType),
    mitreTechniques: getMitreTechniques(topPrediction.attackType),
    recommendation: generateChainRecommendation(topPrediction.attackType, correlatedEvents),
  };
}

/**
 * Detect cross-source attack patterns
 * Implements advanced attack chain detection for modern threats
 */
function detectCrossSourceAttacks(
  entries: ParsedLogEntry[],
  sourceNames: Map<string, string>,
  baseline: ReturnType<typeof buildBaseline>
): AttackChain[] {
  const chains: AttackChain[] = [];
  
  // Categorize entries by source
  const webEntries = entries.filter(e => getLogSource(e.logType) === 'web');
  const dbEntries = entries.filter(e => getLogSource(e.logType) === 'database');
  const authEntries = entries.filter(e => getLogSource(e.logType) === 'auth');
  const fwEntries = entries.filter(e => getLogSource(e.logType) === 'firewall');
  const sysEntries = entries.filter(e => getLogSource(e.logType) === 'system');
  const networkEntries = entries.filter(e => getLogSource(e.logType) === 'network');
  
  // Pattern 1: Web attack -> Database access (SQL Injection chain)
  const sqlInjectionChain = detectSqlInjectionChain(webEntries, dbEntries, baseline);
  if (sqlInjectionChain) chains.push(sqlInjectionChain);
  
  // Pattern 2: Auth failure -> Firewall blocks -> Success (Account Takeover)
  const accountTakeoverChains = detectAccountTakeoverChain(authEntries, fwEntries, baseline);
  chains.push(...accountTakeoverChains);
  
  // Pattern 3: Ransomware Kill Chain
  const ransomwareChains = detectRansomwareChain(sysEntries, authEntries, networkEntries, baseline);
  chains.push(...ransomwareChains);
  
  // Pattern 4: APT Activity Chain
  const aptChains = detectAPTChain(entries, baseline);
  chains.push(...aptChains);
  
  // Pattern 5: Log4Shell Exploitation Chain
  const log4shellChains = detectLog4ShellChain(webEntries, sysEntries, networkEntries, baseline);
  chains.push(...log4shellChains);
  
  // Pattern 6: DNS Tunneling / C2 Communication
  const c2Chains = detectC2Chain(networkEntries, fwEntries, baseline);
  chains.push(...c2Chains);
  
  // Pattern 7: Webshell Deployment Chain
  const webshellChains = detectWebshellChain(webEntries, sysEntries, baseline);
  chains.push(...webshellChains);
  
  // Pattern 8: Kerberos Attack Chain (Golden/Silver Ticket)
  const kerberosChains = detectKerberosChain(authEntries, sysEntries, baseline);
  chains.push(...kerberosChains);
  
  // Pattern 9: Lateral Movement Chain
  const lateralChains = detectLateralMovementChain(authEntries, sysEntries, fwEntries, baseline);
  chains.push(...lateralChains);
  
  // Pattern 10: Cryptomining Chain
  const miningChains = detectCryptominingChain(sysEntries, networkEntries, baseline);
  chains.push(...miningChains);
  
  return chains;
}

/**
 * Detect SQL Injection attack chain: Web -> Database
 */
function detectSqlInjectionChain(
  webEntries: ParsedLogEntry[],
  dbEntries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>
): AttackChain | null {
  if (webEntries.length === 0 || dbEntries.length === 0) return null;
  
  // Find suspicious web requests (4xx, 5xx, injection patterns)
  const suspiciousWeb = webEntries.filter(e => 
    e.severity === 'warning' || 
    e.severity === 'error' ||
    /sql|union|select|insert|delete|drop|;--|'.*or.*'|1=1/i.test(e.message)
  );
  
  if (suspiciousWeb.length === 0) return null;
  
  // Check for subsequent database activity
  for (const webEvent of suspiciousWeb) {
    const webTime = new Date(webEvent.timestamp!).getTime();
    const relatedDb = dbEntries.filter(db => {
      const dbTime = new Date(db.timestamp!).getTime();
      return dbTime > webTime && dbTime - webTime < 60000; // Within 1 minute
    });
    
    if (relatedDb.length > 0) {
      const allEvents = [...suspiciousWeb, ...relatedDb];
      const features = extractFeatures(allEvents, baseline);
      const predictions = classifyAttack(features);
      
      if (predictions.length > 0 && !predictions[0].isFalsePositive) {
        const correlatedEvents: CorrelatedEvent[] = allEvents.map(entry => ({
          id: entry.id,
          timestamp: entry.timestamp!,
          logSource: getLogSource(entry.logType),
          logType: entry.logType,
          severity: entry.severity,
          sourceIp: entry.source.ip,
          targetUser: entry.user?.name,
          targetHost: entry.destination?.hostname || entry.source.hostname,
          action: entry.action,
          outcome: entry.outcome,
          message: entry.message,
          relatedEventIds: [],
          correlationScore: 0.8,
        }));
        
        return {
          id: generateId(),
          startTime: correlatedEvents[0].timestamp,
          endTime: correlatedEvents[correlatedEvents.length - 1].timestamp,
          attackType: 'sql_injection',
          stage: 'execution',
          events: correlatedEvents,
          sourceIps: [...new Set(allEvents.map(e => e.source.ip).filter(Boolean))] as string[],
          targetUsers: [...new Set(allEvents.map(e => e.user?.name).filter(Boolean))] as string[],
          targetHosts: [],
          prediction: predictions[0],
          mitreTactics: getMitreTactics('sql_injection'),
          mitreTechniques: getMitreTechniques('sql_injection'),
          recommendation: 'SQL injection attack detected spanning web and database logs. Review database queries and patch vulnerable endpoints.',
        };
      }
    }
  }
  
  return null;
}

/**
 * Detect Account Takeover chain: Auth failures -> FW blocks -> Success
 */
function detectAccountTakeoverChain(
  authEntries: ParsedLogEntry[],
  fwEntries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>
): AttackChain[] {
  const chains: AttackChain[] = [];
  
  if (authEntries.length === 0) return chains;
  
  // Group by target user
  const userGroups = new Map<string, ParsedLogEntry[]>();
  for (const entry of authEntries) {
    if (!entry.user?.name) continue;
    if (!userGroups.has(entry.user.name)) {
      userGroups.set(entry.user.name, []);
    }
    userGroups.get(entry.user.name)!.push(entry);
  }
  
  for (const [user, userEvents] of userGroups) {
    const failures = userEvents.filter(e => e.outcome === 'failure');
    const successes = userEvents.filter(e => e.outcome === 'success');
    
    if (failures.length >= 3 && successes.length > 0) {
      const firstFailure = new Date(failures[0].timestamp!).getTime();
      const firstSuccess = new Date(successes[0].timestamp!).getTime();
      
      const blocksInWindow = fwEntries.filter(fw => {
        const fwTime = new Date(fw.timestamp!).getTime();
        return fwTime > firstFailure && fwTime < firstSuccess;
      });
      
      if (blocksInWindow.length > 0 || failures.length >= 5) {
        const allEvents = [...failures, ...blocksInWindow, ...successes];
        
        chains.push({
          id: generateId(),
          startTime: failures[0].timestamp!,
          endTime: successes[0].timestamp!,
          attackType: 'account_takeover',
          stage: 'initial_access',
          events: allEvents.map(e => ({
            id: e.id,
            timestamp: e.timestamp!,
            logSource: getLogSource(e.logType),
            logType: e.logType,
            severity: e.severity,
            sourceIp: e.source.ip,
            targetUser: e.user?.name,
            targetHost: e.destination?.hostname || e.source.hostname,
            action: e.action,
            outcome: e.outcome,
            message: e.message,
            relatedEventIds: [],
            correlationScore: 0.85,
          })),
          sourceIps: [...new Set(allEvents.map(e => e.source.ip).filter(Boolean))] as string[],
          targetUsers: [user],
          targetHosts: [],
          prediction: {
            attackType: 'account_takeover',
            confidence: 0.85,
            probability: 0.85,
            features: {},
            explanation: [
              'Distributed attack pattern detected across auth and firewall logs',
              'Multiple source IPs used after firewall blocks',
              'Successful login after persistent attempts',
            ],
            isFalsePositive: false,
          },
          mitreTactics: getMitreTactics('account_takeover'),
          mitreTechniques: getMitreTechniques('account_takeover'),
          recommendation: `Account "${user}" may be compromised. Force password reset and review recent activity.`,
        });
      }
    }
  }
  
  return chains;
}

/**
 * Detect Ransomware Kill Chain
 * Pattern: Recon -> Initial Access -> Privilege Escalation -> Lateral Movement -> Shadow Copy Delete -> Encryption
 */
function detectRansomwareChain(
  sysEntries: ParsedLogEntry[],
  authEntries: ParsedLogEntry[],
  networkEntries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>
): AttackChain[] {
  const chains: AttackChain[] = [];
  
  // Look for ransomware indicators
  const shadowCopyDelete = sysEntries.filter(e => 
    /vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete/i.test(e.message) ||
    /vssadmin/i.test(e.action || '')
  );
  
  const bcdEditTamper = sysEntries.filter(e =>
    /bcdedit.*recoveryenabled.*no|bcdedit.*bootstatuspolicy/i.test(e.message)
  );
  
  const massFileOps = sysEntries.filter(e =>
    /encrypt|\.locked|\.encrypted|ransom|\.crypt/i.test(e.message)
  );
  
  const suspiciousPrivEsc = authEntries.filter(e =>
    e.outcome === 'success' && 
    /admin|root|system|administrator/i.test(e.user?.name || '')
  );
  
  // If we see ransomware indicators
  if (shadowCopyDelete.length > 0 || bcdEditTamper.length > 0 || massFileOps.length >= 5) {
    const allEvents = [...shadowCopyDelete, ...bcdEditTamper, ...massFileOps, ...suspiciousPrivEsc];
    
    if (allEvents.length >= 3) {
      const sortedEvents = allEvents
        .filter(e => e.timestamp)
        .sort((a, b) => new Date(a.timestamp!).getTime() - new Date(b.timestamp!).getTime());
      
      chains.push({
        id: generateId(),
        startTime: sortedEvents[0]?.timestamp || new Date().toISOString(),
        endTime: sortedEvents[sortedEvents.length - 1]?.timestamp || new Date().toISOString(),
        attackType: 'ransomware',
        stage: 'complete',
        events: sortedEvents.map(e => ({
          id: e.id,
          timestamp: e.timestamp!,
          logSource: getLogSource(e.logType),
          logType: e.logType,
          severity: 'critical',
          sourceIp: e.source.ip,
          targetUser: e.user?.name,
          targetHost: e.destination?.hostname || e.source.hostname,
          action: e.action,
          outcome: e.outcome,
          message: e.message,
          relatedEventIds: [],
          correlationScore: 0.95,
        })),
        sourceIps: [...new Set(allEvents.map(e => e.source.ip).filter(Boolean))] as string[],
        targetUsers: [...new Set(allEvents.map(e => e.user?.name).filter(Boolean))] as string[],
        targetHosts: [...new Set(allEvents.map(e => e.destination?.hostname || e.source.hostname).filter(Boolean))] as string[],
        prediction: {
          attackType: 'ransomware',
          confidence: 0.95,
          probability: 0.95,
          features: {},
          explanation: [
            'CRITICAL: Ransomware kill chain detected',
            'Shadow copy deletion commands observed',
            'Recovery options being disabled',
            'Mass file encryption activity detected',
          ],
          isFalsePositive: false,
        },
        mitreTactics: getMitreTactics('ransomware'),
        mitreTechniques: getMitreTechniques('ransomware'),
        recommendation: 'CRITICAL: Isolate affected systems immediately. Activate incident response. Do not pay ransom. Restore from offline backups after full investigation.',
      });
    }
  }
  
  return chains;
}

/**
 * Detect APT Activity Chain
 * Pattern: Reconnaissance -> Persistence -> Privilege Escalation -> Lateral Movement -> C2 -> Exfiltration
 */
function detectAPTChain(
  entries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>
): AttackChain[] {
  const chains: AttackChain[] = [];
  
  // Look for APT indicators across multiple categories
  const aptIndicators = {
    recon: entries.filter(e => 
      /bloodhound|sharphound|adexplorer|ldapsearch|net\s+user|net\s+group/i.test(e.message)
    ),
    persistence: entries.filter(e =>
      /schtasks|at\s+\\\\|reg\s+add.*run|startup.*folder/i.test(e.message) ||
      /scheduled\s*task|registry.*run|autostart/i.test(e.message)
    ),
    privesc: entries.filter(e =>
      /mimikatz|procdump.*lsass|sekurlsa|lsadump|dpapi/i.test(e.message) ||
      /privilege.*escalat|sudo.*root|runas.*admin/i.test(e.message)
    ),
    lateral: entries.filter(e =>
      /psexec|wmiexec|smbexec|atexec|dcomexec|winrm/i.test(e.message) ||
      /remote.*desktop|ssh.*from.*internal/i.test(e.message)
    ),
    c2: entries.filter(e =>
      /cobaltstrike|beacon|meterpreter|empire|covenant/i.test(e.message) ||
      /suspicious.*dns|high.*entropy.*domain|dga/i.test(e.message)
    ),
    exfil: entries.filter(e =>
      /large.*upload|bulk.*download|data.*transfer|7z|rar|zip.*password/i.test(e.message)
    ),
  };
  
  // Count indicators
  const indicatorCount = Object.values(aptIndicators).reduce((sum, arr) => sum + arr.length, 0);
  const categoriesHit = Object.values(aptIndicators).filter(arr => arr.length > 0).length;
  
  // APT activity if multiple categories detected
  if (categoriesHit >= 3 || indicatorCount >= 10) {
    const allEvents = Object.values(aptIndicators).flat();
    const sortedEvents = allEvents
      .filter(e => e.timestamp)
      .sort((a, b) => new Date(a.timestamp!).getTime() - new Date(b.timestamp!).getTime());
    
    let stage: AttackChain['stage'] = 'reconnaissance';
    if (aptIndicators.exfil.length > 0) stage = 'exfiltration';
    else if (aptIndicators.lateral.length > 0) stage = 'lateral_movement';
    else if (aptIndicators.privesc.length > 0) stage = 'privilege_escalation';
    else if (aptIndicators.persistence.length > 0) stage = 'persistence';
    
    chains.push({
      id: generateId(),
      startTime: sortedEvents[0]?.timestamp || new Date().toISOString(),
      endTime: sortedEvents[sortedEvents.length - 1]?.timestamp || new Date().toISOString(),
      attackType: 'apt_activity',
      stage,
      events: sortedEvents.map(e => ({
        id: e.id,
        timestamp: e.timestamp!,
        logSource: getLogSource(e.logType),
        logType: e.logType,
        severity: 'critical',
        sourceIp: e.source.ip,
        targetUser: e.user?.name,
        targetHost: e.destination?.hostname || e.source.hostname,
        action: e.action,
        outcome: e.outcome,
        message: e.message,
        relatedEventIds: [],
        correlationScore: 0.9,
      })),
      sourceIps: [...new Set(allEvents.map(e => e.source.ip).filter(Boolean))] as string[],
      targetUsers: [...new Set(allEvents.map(e => e.user?.name).filter(Boolean))] as string[],
      targetHosts: [...new Set(allEvents.map(e => e.destination?.hostname || e.source.hostname).filter(Boolean))] as string[],
      prediction: {
        attackType: 'apt_activity',
        confidence: 0.9,
        probability: 0.9,
        features: {},
        explanation: [
          'Advanced Persistent Threat activity detected',
          `${categoriesHit} attack chain stages identified`,
          'Multiple TTPs observed consistent with APT behavior',
        ],
        isFalsePositive: false,
      },
      mitreTactics: getMitreTactics('apt_activity'),
      mitreTechniques: getMitreTechniques('apt_activity'),
      recommendation: 'CRITICAL: Engage incident response team immediately. Preserve forensic evidence. Consider threat intelligence sharing. Assume full network compromise until proven otherwise.',
    });
  }
  
  return chains;
}

/**
 * Detect Log4Shell exploitation chain
 */
function detectLog4ShellChain(
  webEntries: ParsedLogEntry[],
  sysEntries: ParsedLogEntry[],
  networkEntries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>
): AttackChain[] {
  const chains: AttackChain[] = [];
  
  // Look for Log4Shell patterns
  const log4shellAttempts = webEntries.filter(e =>
    /\$\{jndi:(ldap|ldaps|rmi|dns|iiop):\/\//i.test(e.message) ||
    /\$\{.*\$\{.*jndi/i.test(e.message) ||
    /\$\{\s*j\s*n\s*d\s*i/i.test(e.message)
  );
  
  if (log4shellAttempts.length > 0) {
    // Look for follow-up activity
    const firstAttempt = new Date(log4shellAttempts[0].timestamp!).getTime();
    
    const suspiciousOutbound = networkEntries.filter(e => {
      const time = new Date(e.timestamp!).getTime();
      return time > firstAttempt && time - firstAttempt < 300000; // 5 minutes
    }).filter(e =>
      /ldap|rmi|outbound|external/i.test(e.message)
    );
    
    const suspiciousProcesses = sysEntries.filter(e => {
      const time = new Date(e.timestamp!).getTime();
      return time > firstAttempt && time - firstAttempt < 300000;
    }).filter(e =>
      /java|wget|curl|bash|sh|powershell/i.test(e.message)
    );
    
    const allEvents = [...log4shellAttempts, ...suspiciousOutbound, ...suspiciousProcesses];
    const sortedEvents = allEvents
      .filter(e => e.timestamp)
      .sort((a, b) => new Date(a.timestamp!).getTime() - new Date(b.timestamp!).getTime());
    
    chains.push({
      id: generateId(),
      startTime: sortedEvents[0]?.timestamp || new Date().toISOString(),
      endTime: sortedEvents[sortedEvents.length - 1]?.timestamp || new Date().toISOString(),
      attackType: 'log4shell',
      stage: suspiciousProcesses.length > 0 ? 'execution' : 'initial_access',
      events: sortedEvents.map(e => ({
        id: e.id,
        timestamp: e.timestamp!,
        logSource: getLogSource(e.logType),
        logType: e.logType,
        severity: 'critical',
        sourceIp: e.source.ip,
        targetUser: e.user?.name,
        targetHost: e.destination?.hostname || e.source.hostname,
        action: e.action,
        outcome: e.outcome,
        message: e.message,
        relatedEventIds: [],
        correlationScore: 0.95,
      })),
      sourceIps: [...new Set(allEvents.map(e => e.source.ip).filter(Boolean))] as string[],
      targetUsers: [],
      targetHosts: [...new Set(allEvents.map(e => e.destination?.hostname || e.source.hostname).filter(Boolean))] as string[],
      prediction: {
        attackType: 'log4shell',
        confidence: 0.95,
        probability: 0.95,
        features: {},
        explanation: [
          'Log4Shell (CVE-2021-44228) exploitation attempt detected',
          `${log4shellAttempts.length} JNDI injection payloads observed`,
          suspiciousProcesses.length > 0 ? 'Post-exploitation activity detected' : 'Initial exploitation phase',
        ],
        isFalsePositive: false,
      },
      mitreTactics: getMitreTactics('log4shell'),
      mitreTechniques: getMitreTechniques('log4shell'),
      recommendation: 'CRITICAL: Patch Log4j immediately (version 2.17.1+). Isolate affected Java applications. Check for indicators of compromise. Review outbound network connections.',
    });
  }
  
  return chains;
}

/**
 * Detect C2/DNS Tunneling chain
 */
function detectC2Chain(
  networkEntries: ParsedLogEntry[],
  fwEntries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>
): AttackChain[] {
  const chains: AttackChain[] = [];
  
  // Look for DNS tunneling patterns
  const suspiciousDns = networkEntries.filter(e => {
    // High entropy subdomain detection
    const dnsMatch = e.message.match(/query:\s*([a-z0-9.-]+)/i) ||
                     e.message.match(/domain:\s*([a-z0-9.-]+)/i);
    if (dnsMatch) {
      const domain = dnsMatch[1];
      const parts = domain.split('.');
      for (const part of parts) {
        if (part.length > 30) return true; // Very long subdomain
      }
    }
    // TXT/NULL record abuse
    if (/TXT.*query|NULL.*record|type.*16|type.*10/i.test(e.message)) return true;
    return false;
  });
  
  // Look for beaconing patterns (regular intervals)
  const outboundConnections = fwEntries.filter(e =>
    /outbound|egress|allow/i.test(e.action || '') ||
    /destination.*external/i.test(e.message)
  );
  
  if (suspiciousDns.length >= 5 || outboundConnections.length >= 20) {
    const allEvents = [...suspiciousDns, ...outboundConnections.slice(0, 20)];
    const sortedEvents = allEvents
      .filter(e => e.timestamp)
      .sort((a, b) => new Date(a.timestamp!).getTime() - new Date(b.timestamp!).getTime());
    
    if (sortedEvents.length > 0) {
      chains.push({
        id: generateId(),
        startTime: sortedEvents[0].timestamp!,
        endTime: sortedEvents[sortedEvents.length - 1].timestamp!,
        attackType: suspiciousDns.length >= 5 ? 'dns_tunneling' : 'c2_communication',
        stage: 'execution',
        events: sortedEvents.map(e => ({
          id: e.id,
          timestamp: e.timestamp!,
          logSource: getLogSource(e.logType),
          logType: e.logType,
          severity: 'high',
          sourceIp: e.source.ip,
          targetUser: e.user?.name,
          targetHost: e.destination?.hostname || e.source.hostname,
          action: e.action,
          outcome: e.outcome,
          message: e.message,
          relatedEventIds: [],
          correlationScore: 0.8,
        })),
        sourceIps: [...new Set(allEvents.map(e => e.source.ip).filter(Boolean))] as string[],
        targetUsers: [],
        targetHosts: [],
        prediction: {
          attackType: suspiciousDns.length >= 5 ? 'dns_tunneling' : 'c2_communication',
          confidence: 0.8,
          probability: 0.8,
          features: {},
          explanation: [
            suspiciousDns.length >= 5 ? 'DNS tunneling activity detected' : 'Potential C2 beaconing detected',
            'Unusual DNS query patterns or regular outbound connections',
            'May indicate data exfiltration or command channel',
          ],
          isFalsePositive: false,
        },
        mitreTactics: getMitreTactics('dns_tunneling'),
        mitreTechniques: getMitreTechniques('dns_tunneling'),
        recommendation: 'Block suspicious domains at DNS level. Implement DNS filtering. Investigate source hosts for malware. Review DNS query logs for data exfiltration.',
      });
    }
  }
  
  return chains;
}

/**
 * Detect Webshell deployment chain
 */
function detectWebshellChain(
  webEntries: ParsedLogEntry[],
  sysEntries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>
): AttackChain[] {
  const chains: AttackChain[] = [];
  
  // Look for webshell indicators
  const webshellPatterns = webEntries.filter(e =>
    /\.(php|asp|aspx|jsp)\?cmd=|\?exec=|\?shell=/i.test(e.message) ||
    /(c99|r57|b374k|wso|weevely|alfa|p0wny)/i.test(e.message) ||
    /POST.*(\/tmp\/|\/upload.*\/).*\.(php|asp)/i.test(e.message)
  );
  
  const suspiciousFileOps = sysEntries.filter(e =>
    /create.*\.(php|asp|aspx|jsp)|write.*\.(php|asp)/i.test(e.message) ||
    /www|html|htdocs|inetpub/i.test(e.message)
  );
  
  if (webshellPatterns.length > 0 || suspiciousFileOps.length > 0) {
    const allEvents = [...webshellPatterns, ...suspiciousFileOps];
    const sortedEvents = allEvents
      .filter(e => e.timestamp)
      .sort((a, b) => new Date(a.timestamp!).getTime() - new Date(b.timestamp!).getTime());
    
    if (sortedEvents.length > 0) {
      chains.push({
        id: generateId(),
        startTime: sortedEvents[0].timestamp!,
        endTime: sortedEvents[sortedEvents.length - 1].timestamp!,
        attackType: 'webshell',
        stage: 'persistence',
        events: sortedEvents.map(e => ({
          id: e.id,
          timestamp: e.timestamp!,
          logSource: getLogSource(e.logType),
          logType: e.logType,
          severity: 'critical',
          sourceIp: e.source.ip,
          targetUser: e.user?.name,
          targetHost: e.destination?.hostname || e.source.hostname,
          action: e.action,
          outcome: e.outcome,
          message: e.message,
          relatedEventIds: [],
          correlationScore: 0.9,
        })),
        sourceIps: [...new Set(allEvents.map(e => e.source.ip).filter(Boolean))] as string[],
        targetUsers: [],
        targetHosts: [...new Set(allEvents.map(e => e.destination?.hostname || e.source.hostname).filter(Boolean))] as string[],
        prediction: {
          attackType: 'webshell',
          confidence: 0.9,
          probability: 0.9,
          features: {},
          explanation: [
            'Web shell activity detected',
            'Attacker has persistent backdoor access',
            'Command execution via web interface observed',
          ],
          isFalsePositive: false,
        },
        mitreTactics: getMitreTactics('webshell'),
        mitreTechniques: getMitreTechniques('webshell'),
        recommendation: 'Identify and remove webshell files. Review web server access logs. Check file integrity. Investigate initial compromise vector.',
      });
    }
  }
  
  return chains;
}

/**
 * Detect Kerberos attack chain (Kerberoasting, Golden Ticket)
 */
function detectKerberosChain(
  authEntries: ParsedLogEntry[],
  sysEntries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>
): AttackChain[] {
  const chains: AttackChain[] = [];
  
  // Look for Kerberoasting indicators
  const kerberoasting = authEntries.filter(e =>
    /4769.*0x17|4769.*encryption.*0x17/i.test(e.message) ||  // RC4 encryption request
    /TGS.*request.*spn|service.*ticket/i.test(e.message) ||
    /rubeus|invoke-kerberoast|getuserspns/i.test(e.message)
  );
  
  // Look for Golden Ticket indicators
  const goldenTicket = sysEntries.filter(e =>
    /mimikatz.*kerberos|lsadump.*dcsync|krbtgt/i.test(e.message) ||
    /golden.*ticket|forged.*ticket/i.test(e.message)
  );
  
  // Look for Pass-the-Hash indicators
  const pthIndicators = authEntries.filter(e =>
    /4624.*logon.*type.*9|4624.*type.*3.*ntlm/i.test(e.message) ||
    /pass.*the.*hash|overpass.*the.*hash/i.test(e.message) ||
    /sekurlsa.*pth|mimikatz.*pth/i.test(e.message)
  );
  
  if (kerberoasting.length >= 3) {
    const sortedEvents = kerberoasting
      .filter(e => e.timestamp)
      .sort((a, b) => new Date(a.timestamp!).getTime() - new Date(b.timestamp!).getTime());
    
    chains.push({
      id: generateId(),
      startTime: sortedEvents[0]?.timestamp || new Date().toISOString(),
      endTime: sortedEvents[sortedEvents.length - 1]?.timestamp || new Date().toISOString(),
      attackType: 'kerberoasting',
      stage: 'privilege_escalation',
      events: sortedEvents.map(e => ({
        id: e.id,
        timestamp: e.timestamp!,
        logSource: getLogSource(e.logType),
        logType: e.logType,
        severity: 'high',
        sourceIp: e.source.ip,
        targetUser: e.user?.name,
        targetHost: e.destination?.hostname || e.source.hostname,
        action: e.action,
        outcome: e.outcome,
        message: e.message,
        relatedEventIds: [],
        correlationScore: 0.85,
      })),
      sourceIps: [...new Set(kerberoasting.map(e => e.source.ip).filter(Boolean))] as string[],
      targetUsers: [...new Set(kerberoasting.map(e => e.user?.name).filter(Boolean))] as string[],
      targetHosts: [],
      prediction: {
        attackType: 'kerberoasting',
        confidence: 0.85,
        probability: 0.85,
        features: {},
        explanation: [
          'Kerberoasting attack detected',
          'Multiple TGS requests with weak encryption',
          'Attacker collecting service account tickets for offline cracking',
        ],
        isFalsePositive: false,
      },
      mitreTactics: getMitreTactics('kerberoasting'),
      mitreTechniques: getMitreTechniques('kerberoasting'),
      recommendation: 'Review service account passwords. Implement AES encryption for Kerberos. Monitor for mass TGS requests. Use Managed Service Accounts where possible.',
    });
  }
  
  if (goldenTicket.length > 0) {
    const allEvents = [...goldenTicket, ...pthIndicators];
    const sortedEvents = allEvents
      .filter(e => e.timestamp)
      .sort((a, b) => new Date(a.timestamp!).getTime() - new Date(b.timestamp!).getTime());
    
    chains.push({
      id: generateId(),
      startTime: sortedEvents[0]?.timestamp || new Date().toISOString(),
      endTime: sortedEvents[sortedEvents.length - 1]?.timestamp || new Date().toISOString(),
      attackType: 'golden_ticket',
      stage: 'complete',
      events: sortedEvents.map(e => ({
        id: e.id,
        timestamp: e.timestamp!,
        logSource: getLogSource(e.logType),
        logType: e.logType,
        severity: 'critical',
        sourceIp: e.source.ip,
        targetUser: e.user?.name,
        targetHost: e.destination?.hostname || e.source.hostname,
        action: e.action,
        outcome: e.outcome,
        message: e.message,
        relatedEventIds: [],
        correlationScore: 0.95,
      })),
      sourceIps: [...new Set(allEvents.map(e => e.source.ip).filter(Boolean))] as string[],
      targetUsers: [],
      targetHosts: [],
      prediction: {
        attackType: 'golden_ticket',
        confidence: 0.95,
        probability: 0.95,
        features: {},
        explanation: [
          'CRITICAL: Golden Ticket attack detected',
          'Attacker has obtained krbtgt hash',
          'Complete domain compromise is likely',
        ],
        isFalsePositive: false,
      },
      mitreTactics: getMitreTactics('golden_ticket'),
      mitreTechniques: getMitreTechniques('golden_ticket'),
      recommendation: 'CRITICAL: Reset krbtgt password TWICE (wait for replication). Investigate all domain controllers. Assume full domain compromise. Consider full forest recovery.',
    });
  }
  
  return chains;
}

/**
 * Detect Lateral Movement chain
 */
function detectLateralMovementChain(
  authEntries: ParsedLogEntry[],
  sysEntries: ParsedLogEntry[],
  fwEntries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>
): AttackChain[] {
  const chains: AttackChain[] = [];
  
  // Look for lateral movement patterns
  const lateralTools = sysEntries.filter(e =>
    /psexec|wmiexec|smbexec|winrm|remoting|invoke-command/i.test(e.message) ||
    /remote.*execution|process.*create.*remote/i.test(e.message)
  );
  
  const multiHostAuth = new Map<string, Set<string>>();
  for (const entry of authEntries) {
    const ip = entry.source.ip;
    const host = entry.destination?.hostname || entry.source.hostname;
    if (ip && host) {
      if (!multiHostAuth.has(ip)) multiHostAuth.set(ip, new Set());
      multiHostAuth.get(ip)!.add(host);
    }
  }
  
  // Find IPs authenticating to multiple hosts
  const lateralIps = [...multiHostAuth.entries()]
    .filter(([ip, hosts]) => hosts.size >= 3)
    .map(([ip]) => ip);
  
  if (lateralTools.length > 0 || lateralIps.length > 0) {
    const relevantAuth = authEntries.filter(e => lateralIps.includes(e.source.ip!));
    const allEvents = [...lateralTools, ...relevantAuth.slice(0, 50)];
    
    if (allEvents.length > 0) {
      const sortedEvents = allEvents
        .filter(e => e.timestamp)
        .sort((a, b) => new Date(a.timestamp!).getTime() - new Date(b.timestamp!).getTime());
      
      chains.push({
        id: generateId(),
        startTime: sortedEvents[0]?.timestamp || new Date().toISOString(),
        endTime: sortedEvents[sortedEvents.length - 1]?.timestamp || new Date().toISOString(),
        attackType: 'lateral_movement',
        stage: 'lateral_movement',
        events: sortedEvents.map(e => ({
          id: e.id,
          timestamp: e.timestamp!,
          logSource: getLogSource(e.logType),
          logType: e.logType,
          severity: 'high',
          sourceIp: e.source.ip,
          targetUser: e.user?.name,
          targetHost: e.destination?.hostname || e.source.hostname,
          action: e.action,
          outcome: e.outcome,
          message: e.message,
          relatedEventIds: [],
          correlationScore: 0.85,
        })),
        sourceIps: lateralIps,
        targetUsers: [...new Set(allEvents.map(e => e.user?.name).filter(Boolean))] as string[],
        targetHosts: [...new Set([...multiHostAuth.values()].flatMap(s => [...s]))] as string[],
        prediction: {
          attackType: 'lateral_movement',
          confidence: 0.85,
          probability: 0.85,
          features: {},
          explanation: [
            'Lateral movement activity detected',
            `${lateralIps.length} source IPs accessing multiple internal hosts`,
            'Attacker expanding access within the network',
          ],
          isFalsePositive: false,
        },
        mitreTactics: getMitreTactics('lateral_movement'),
        mitreTechniques: getMitreTechniques('lateral_movement'),
        recommendation: 'Implement network segmentation. Restrict admin tool usage. Enable LSA protection. Monitor for unusual authentication patterns.',
      });
    }
  }
  
  return chains;
}

/**
 * Detect Cryptomining chain
 */
function detectCryptominingChain(
  sysEntries: ParsedLogEntry[],
  networkEntries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>
): AttackChain[] {
  const chains: AttackChain[] = [];
  
  // Look for cryptomining indicators
  const miningProcesses = sysEntries.filter(e =>
    /xmrig|cpuminer|cgminer|bfgminer|minerd|ethminer/i.test(e.message) ||
    /stratum\+tcp|stratum\+ssl/i.test(e.message)
  );
  
  const miningConnections = networkEntries.filter(e =>
    /pool\.(minergate|supportxmr|nanopool|2miners|f2pool)/i.test(e.message) ||
    /stratum.*connect|mining.*pool/i.test(e.message)
  );
  
  const highCpu = sysEntries.filter(e =>
    /cpu.*(100%|9[0-9]%)|high.*cpu.*usage/i.test(e.message)
  );
  
  if (miningProcesses.length > 0 || miningConnections.length > 0) {
    const allEvents = [...miningProcesses, ...miningConnections, ...highCpu.slice(0, 10)];
    const sortedEvents = allEvents
      .filter(e => e.timestamp)
      .sort((a, b) => new Date(a.timestamp!).getTime() - new Date(b.timestamp!).getTime());
    
    if (sortedEvents.length > 0) {
      chains.push({
        id: generateId(),
        startTime: sortedEvents[0].timestamp!,
        endTime: sortedEvents[sortedEvents.length - 1].timestamp!,
        attackType: 'cryptomining',
        stage: 'execution',
        events: sortedEvents.map(e => ({
          id: e.id,
          timestamp: e.timestamp!,
          logSource: getLogSource(e.logType),
          logType: e.logType,
          severity: 'medium',
          sourceIp: e.source.ip,
          targetUser: e.user?.name,
          targetHost: e.destination?.hostname || e.source.hostname,
          action: e.action,
          outcome: e.outcome,
          message: e.message,
          relatedEventIds: [],
          correlationScore: 0.85,
        })),
        sourceIps: [...new Set(allEvents.map(e => e.source.ip).filter(Boolean))] as string[],
        targetUsers: [],
        targetHosts: [...new Set(allEvents.map(e => e.destination?.hostname || e.source.hostname).filter(Boolean))] as string[],
        prediction: {
          attackType: 'cryptomining',
          confidence: 0.85,
          probability: 0.85,
          features: {},
          explanation: [
            'Cryptocurrency mining activity detected',
            'Mining process or pool connections identified',
            'Unauthorized resource usage for cryptocurrency mining',
          ],
          isFalsePositive: false,
        },
        mitreTactics: getMitreTactics('cryptomining'),
        mitreTechniques: getMitreTechniques('cryptomining'),
        recommendation: 'Terminate mining processes. Block mining pool domains. Investigate initial access vector. Review system for persistence mechanisms.',
      });
    }
  }
  
  return chains;
}

/**
 * Calculate correlation score for an event
 */
function calculateCorrelationScore(entry: ParsedLogEntry, attackType: AttackType): number {
  let score = 0.5; // Base score
  
  // Increase score for events matching attack type
  if (attackType.includes('brute') && entry.outcome === 'failure') {
    score += 0.3;
  }
  
  if (attackType === 'sql_injection' && entry.message.toLowerCase().includes('sql')) {
    score += 0.3;
  }
  
  if (attackType === 'privilege_escalation' && 
      (entry.action === 'sudo' || entry.tags.includes('privilege_escalation'))) {
    score += 0.4;
  }
  
  // Severity boost
  if (entry.severity === 'critical') score += 0.2;
  if (entry.severity === 'error') score += 0.15;
  if (entry.severity === 'warning') score += 0.1;
  
  return Math.min(score, 1.0);
}

/**
 * Determine attack stage based on events
 */
function determineAttackStage(
  events: CorrelatedEvent[],
  attackType: AttackType
): AttackChain['stage'] {
  const sources = new Set(events.map(e => e.logSource));
  const hasSuccess = events.some(e => e.outcome === 'success');
  const hasFailures = events.some(e => e.outcome === 'failure');
  
  // Multi-source typically means advanced stage
  if (sources.size > 2) {
    if (hasSuccess && attackType !== 'reconnaissance') {
      return 'lateral_movement';
    }
    return 'execution';
  }
  
  // Map attack types to typical stages
  if (['port_scan', 'reconnaissance'].includes(attackType)) {
    return 'reconnaissance';
  }
  
  if (['bruteforce', 'password_spray', 'credential_stuffing', 'account_takeover'].includes(attackType)) {
    return hasSuccess ? 'initial_access' : 'reconnaissance';
  }
  
  if (attackType === 'privilege_escalation') {
    return 'privilege_escalation';
  }
  
  if (attackType === 'data_exfiltration') {
    return 'exfiltration';
  }
  
  if (attackType === 'lateral_movement') {
    return 'lateral_movement';
  }
  
  return 'execution';
}

/**
 * Generate recommendation for attack chain
 */
function generateChainRecommendation(attackType: AttackType, events: CorrelatedEvent[]): string {
  const recommendations: Partial<Record<AttackType, string>> = {
    // Credential attacks
    bruteforce: 'Implement account lockout policy, enable MFA, and consider blocking source IPs.',
    password_spray: 'Enable MFA for all accounts, implement login anomaly detection, and review password policies.',
    credential_stuffing: 'Enable MFA, monitor for credential leaks, and implement CAPTCHA on login.',
    mfa_bypass: 'Review MFA implementation, check for session token leaks, and monitor for anomalous authentication.',
    mfa_fatigue: 'Implement number matching MFA, rate limit push notifications, and alert users about attacks.',
    session_hijacking: 'Implement session binding, use secure cookies, and monitor for IP changes mid-session.',
    account_takeover: 'Force password reset, revoke sessions, and review recent account activity.',
    kerberoasting: 'Review service account passwords (use 25+ char), enable AES encryption for Kerberos, monitor Event ID 4769 with 0x17 encryption.',
    pass_the_hash: 'Enable Credential Guard, restrict NTLM authentication, implement LSA protection, segment admin workstations.',
    golden_ticket: 'CRITICAL: Reset krbtgt password twice. Investigate all domain controllers. Assume full domain compromise.',
    
    // Web attacks
    sql_injection: 'Use parameterized queries, implement WAF, and review input validation.',
    xss_attack: 'Implement CSP headers, sanitize outputs, and review frontend security.',
    path_traversal: 'Validate file paths, restrict file access, and use chroot jails.',
    command_injection: 'Sanitize inputs, avoid shell commands, and implement least privilege.',
    ssrf_attack: 'Implement URL allowlisting, block requests to internal IPs/metadata endpoints, validate and sanitize URLs.',
    xxe_attack: 'Disable external entity processing in XML parsers, use less complex formats like JSON where possible.',
    deserialization: 'Implement integrity checks, avoid deserializing untrusted data, use allowlists for allowed classes.',
    ldap_injection: 'Use parameterized LDAP queries, validate inputs, implement least privilege for LDAP binds.',
    log4shell: 'CRITICAL: Patch Log4j to 2.17.1+. Block outbound LDAP/RMI. Set log4j2.formatMsgNoLookups=true.',
    prototype_pollution: 'Freeze Object.prototype, validate JSON schema, sanitize property assignments.',
    
    // Infrastructure attacks
    privilege_escalation: 'Review sudo policies, audit privileged commands, and implement just-in-time access.',
    lateral_movement: 'Segment network, implement zero-trust, and monitor internal traffic.',
    data_exfiltration: 'Implement DLP, monitor outbound traffic, and review data access patterns.',
    port_scan: 'Review firewall rules, enable port scan detection, and rate limit connections.',
    ddos: 'Enable DDoS protection, implement rate limiting, and prepare incident response.',
    reconnaissance: 'Monitor for scanning activity, implement honeypots, and review exposed services.',
    dns_tunneling: 'Implement DNS filtering, monitor for high-entropy queries, block TXT record abuse, consider DNS over HTTPS inspection.',
    cryptomining: 'Terminate mining processes, block mining pool domains, investigate initial access vector, check for persistence.',
    ransomware: 'CRITICAL: Isolate systems immediately. Do not pay ransom. Restore from offline backups. Engage incident response.',
    supply_chain: 'Verify software integrity, review update mechanisms, implement software bill of materials (SBOM) monitoring.',
    
    // APT
    malware_activity: 'Isolate affected systems, run antivirus scans, and investigate IOCs.',
    c2_communication: 'Block suspicious domains, monitor DNS queries, and isolate affected hosts.',
    insider_threat: 'Review access patterns, implement UEBA, and conduct investigation.',
    apt_activity: 'CRITICAL: Engage incident response team. Preserve forensic evidence. Assume network-wide compromise.',
    zero_day_exploit: 'Isolate affected systems, capture forensic data, engage threat intelligence, implement compensating controls.',
    webshell: 'Remove webshell files, review web server logs, check file integrity, investigate initial compromise.',
    living_off_the_land: 'Monitor for unusual use of certutil/mshta/PowerShell, implement application allowlisting, enable command-line logging.',
    
    // Generic
    anomaly: 'Investigate unusual activity, review baseline, and document findings.',
    unknown: 'Review events, correlate with other sources, and document for further analysis.',
  };
  
  const sourceIps = [...new Set(events.map(e => e.sourceIp).filter(Boolean))];
  const targetUsers = [...new Set(events.map(e => e.targetUser).filter(Boolean))];
  
  let recommendation = recommendations[attackType] || recommendations.unknown!;
  
  if (sourceIps.length > 0) {
    recommendation += ` Consider blocking IPs: ${sourceIps.slice(0, 3).join(', ')}${sourceIps.length > 3 ? '...' : ''}.`;
  }
  
  if (targetUsers.length > 0) {
    recommendation += ` Affected users: ${targetUsers.slice(0, 3).join(', ')}${targetUsers.length > 3 ? '...' : ''}.`;
  }
  
  return recommendation;
}

/**
 * Build unified timeline from all events
 */
function buildTimeline(
  entries: ParsedLogEntry[],
  attackChains: AttackChain[],
  sourceNames: Map<string, string>
): TimelineEvent[] {
  // Create map of event IDs to attack chains
  const eventToChain = new Map<string, string>();
  for (const chain of attackChains) {
    for (const event of chain.events) {
      eventToChain.set(event.id, chain.id);
    }
  }
  
  // Convert all entries to timeline events
  const timeline: TimelineEvent[] = entries
    .filter(e => e.timestamp)
    .map(entry => {
      const attackChainId = eventToChain.get(entry.id);
      const chain = attackChainId 
        ? attackChains.find(c => c.id === attackChainId)
        : undefined;
      
      return {
        id: entry.id,
        timestamp: entry.timestamp!,
        logSource: getLogSource(entry.logType),
        eventType: entry.action || entry.logType,
        severity: mapSeverity(entry.severity),
        title: generateEventTitle(entry),
        description: entry.message,
        sourceIp: entry.source.ip,
        targetUser: entry.user?.name,
        relatedAttackChainId: attackChainId,
        isAnomaly: !!attackChainId,
        anomalyScore: chain ? chain.prediction.confidence : 0,
      };
    })
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  
  return timeline;
}

/**
 * Map log severity to timeline severity
 */
function mapSeverity(severity: string): TimelineEvent['severity'] {
  const map: Record<string, TimelineEvent['severity']> = {
    debug: 'info',
    info: 'info',
    warning: 'low',
    error: 'medium',
    critical: 'critical',
    unknown: 'info',
  };
  return map[severity] || 'info';
}

/**
 * Generate event title for timeline
 */
function generateEventTitle(entry: ParsedLogEntry): string {
  if (entry.action) {
    const outcome = entry.outcome ? ` (${entry.outcome})` : '';
    return `${entry.action}${outcome}`;
  }
  
  if (entry.outcome === 'failure') {
    return 'Failed operation';
  }
  
  if (entry.outcome === 'success') {
    return 'Successful operation';
  }
  
  return entry.logType.replace(/_/g, ' ');
}

/**
 * Generate summary statistics
 */
function generateSummary(
  entries: ParsedLogEntry[],
  validChains: AttackChain[],
  falsePositivesFiltered: number
): CorrelationResult['summary'] {
  // Count alerts by severity
  const criticalAlerts = validChains.filter(c => 
    c.prediction.confidence >= 0.8 || 
    c.attackType === 'account_takeover' ||
    c.attackType === 'data_exfiltration'
  ).length;
  
  // Get attack types
  const attackTypesDetected = [...new Set(validChains.map(c => c.attackType))];
  
  // Get most targeted users
  const userCounts = new Map<string, number>();
  for (const chain of validChains) {
    for (const user of chain.targetUsers) {
      userCounts.set(user, (userCounts.get(user) || 0) + 1);
    }
  }
  const mostTargetedUsers = [...userCounts.entries()]
    .map(([user, count]) => ({ user, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
  
  // Get most active source IPs with threat scores
  const ipCounts = new Map<string, { count: number; threatScore: number }>();
  for (const chain of validChains) {
    for (const ip of chain.sourceIps) {
      const current = ipCounts.get(ip) || { count: 0, threatScore: 0 };
      current.count += 1;
      current.threatScore = Math.max(current.threatScore, chain.prediction.confidence);
      ipCounts.set(ip, current);
    }
  }
  const mostActiveSourceIps = [...ipCounts.entries()]
    .map(([ip, data]) => ({ ip, count: data.count, threatScore: data.threatScore }))
    .sort((a, b) => b.threatScore - a.threatScore)
    .slice(0, 10);
  
  // Calculate overall risk score
  const riskScore = calculateOverallRisk(validChains, entries.length);
  
  return {
    totalAlerts: validChains.length,
    criticalAlerts,
    falsePositivesFiltered,
    attackTypesDetected,
    mostTargetedUsers,
    mostActiveSourceIps,
    riskScore,
  };
}

/**
 * Calculate overall risk score (0-100)
 */
function calculateOverallRisk(chains: AttackChain[], totalEvents: number): number {
  if (chains.length === 0) return 0;
  
  let risk = 0;
  
  // Base risk from number of attack chains
  risk += Math.min(chains.length * 10, 40);
  
  // Critical threat types (instant high risk)
  const criticalTypes: AttackType[] = [
    'ransomware', 'golden_ticket', 'apt_activity', 'log4shell', 'zero_day_exploit'
  ];
  const hasCriticalThreat = chains.some(c => criticalTypes.includes(c.attackType));
  if (hasCriticalThreat) risk += 50;
  
  // High severity types
  const highTypes: AttackType[] = [
    'account_takeover', 'data_exfiltration', 'privilege_escalation',
    'lateral_movement', 'c2_communication', 'malware_activity',
    'pass_the_hash', 'kerberoasting', 'webshell', 'living_off_the_land',
    'supply_chain', 'dns_tunneling'
  ];
  const hasHighSeverity = chains.some(c => highTypes.includes(c.attackType));
  if (hasHighSeverity && !hasCriticalThreat) risk += 30;
  
  // Risk from confidence scores
  const avgConfidence = chains.reduce((sum, c) => sum + c.prediction.confidence, 0) / chains.length;
  risk += avgConfidence * 20;
  
  // Risk from attack progression
  const advancedStages = ['lateral_movement', 'exfiltration', 'complete'];
  const hasAdvanced = chains.some(c => advancedStages.includes(c.stage));
  if (hasAdvanced) risk += 10;
  
  // Multiple attack types indicate coordinated attack
  const uniqueTypes = new Set(chains.map(c => c.attackType));
  if (uniqueTypes.size >= 3) risk += 10;
  
  return Math.min(Math.round(risk), 100);
}

/**
 * Generate recommendations based on detected attacks
 */
function generateRecommendations(chains: AttackChain[]): string[] {
  const recommendations: string[] = [];
  const seenTypes = new Set<AttackType>();
  
  // Check for critical attacks requiring immediate action
  const criticalTypes: AttackType[] = ['ransomware', 'golden_ticket', 'apt_activity', 'log4shell'];
  const hasCritical = chains.some(c => criticalTypes.includes(c.attackType));
  
  if (hasCritical) {
    recommendations.push('CRITICAL: Activate incident response plan immediately.');
    recommendations.push('CRITICAL: Consider isolating affected systems from the network.');
  } else if (chains.length > 0) {
    recommendations.push('IMMEDIATE: Review all detected attack chains and validate findings.');
  }
  
  for (const chain of chains) {
    if (seenTypes.has(chain.attackType)) continue;
    seenTypes.add(chain.attackType);
    
    // Add attack-specific recommendations
    switch (chain.attackType) {
      // Credential attacks
      case 'bruteforce':
      case 'password_spray':
        recommendations.push('Enable multi-factor authentication (MFA) for all user accounts.');
        recommendations.push('Implement account lockout policies after failed login attempts.');
        break;
        
      case 'account_takeover':
        recommendations.push('Force password reset for compromised accounts.');
        recommendations.push('Review and revoke active sessions for affected users.');
        break;
        
      case 'kerberoasting':
        recommendations.push('Review and strengthen service account passwords (25+ characters).');
        recommendations.push('Enable AES encryption for Kerberos authentication.');
        recommendations.push('Monitor Event ID 4769 for unusual ticket requests.');
        break;
        
      case 'pass_the_hash':
        recommendations.push('Enable Windows Credential Guard on domain-joined systems.');
        recommendations.push('Restrict NTLM authentication where possible.');
        recommendations.push('Implement Local Administrator Password Solution (LAPS).');
        break;
        
      case 'golden_ticket':
        recommendations.push('CRITICAL: Reset krbtgt password twice (allow replication between resets).');
        recommendations.push('Investigate all domain controllers for compromise.');
        recommendations.push('Review all privileged access and trust relationships.');
        break;
        
      // Web attacks
      case 'sql_injection':
        recommendations.push('Review and patch vulnerable web application endpoints.');
        recommendations.push('Implement Web Application Firewall (WAF) rules.');
        recommendations.push('Use parameterized queries for all database operations.');
        break;
        
      case 'ssrf_attack':
        recommendations.push('Implement URL allowlisting for outbound requests.');
        recommendations.push('Block access to cloud metadata endpoints (169.254.169.254).');
        break;
        
      case 'xxe_attack':
        recommendations.push('Disable external entity processing in XML parsers.');
        recommendations.push('Consider using JSON instead of XML where possible.');
        break;
        
      case 'log4shell':
        recommendations.push('CRITICAL: Patch Log4j to version 2.17.1 or later immediately.');
        recommendations.push('Set log4j2.formatMsgNoLookups=true as temporary mitigation.');
        recommendations.push('Block outbound LDAP, RMI, and DNS requests from application servers.');
        break;
        
      // Infrastructure attacks
      case 'privilege_escalation':
        recommendations.push('Review sudo and administrative access policies.');
        recommendations.push('Implement just-in-time privileged access management.');
        break;
        
      case 'lateral_movement':
        recommendations.push('Implement network segmentation.');
        recommendations.push('Enable micro-segmentation and zero-trust policies.');
        recommendations.push('Restrict use of administrative tools like PsExec.');
        break;
        
      case 'data_exfiltration':
        recommendations.push('Review and strengthen Data Loss Prevention (DLP) policies.');
        recommendations.push('Monitor and alert on unusual data transfer patterns.');
        break;
        
      case 'dns_tunneling':
        recommendations.push('Implement DNS filtering and monitoring.');
        recommendations.push('Block or alert on high-entropy DNS queries.');
        recommendations.push('Consider DNS over HTTPS inspection at network edge.');
        break;
        
      case 'cryptomining':
        recommendations.push('Terminate unauthorized mining processes.');
        recommendations.push('Block connections to known mining pool domains.');
        recommendations.push('Investigate initial access vector for miner deployment.');
        break;
        
      case 'ransomware':
        recommendations.push('CRITICAL: Isolate affected systems immediately - do not shut down.');
        recommendations.push('CRITICAL: Do not pay the ransom - engage law enforcement.');
        recommendations.push('Restore from offline backups after full investigation.');
        recommendations.push('Check shadow copies and backup integrity before restoration.');
        break;
        
      // APT
      case 'apt_activity':
        recommendations.push('Engage professional incident response team.');
        recommendations.push('Preserve all forensic evidence for analysis.');
        recommendations.push('Assume network-wide compromise until proven otherwise.');
        recommendations.push('Consider threat intelligence sharing with industry peers.');
        break;
        
      case 'webshell':
        recommendations.push('Identify and remove all webshell files from web servers.');
        recommendations.push('Review web server access logs for initial compromise.');
        recommendations.push('Implement file integrity monitoring on web directories.');
        break;
        
      case 'living_off_the_land':
        recommendations.push('Implement application allowlisting policies.');
        recommendations.push('Enable PowerShell script block logging and constrained language mode.');
        recommendations.push('Monitor for unusual use of certutil, mshta, regsvr32, and similar tools.');
        break;
        
      case 'c2_communication':
        recommendations.push('Block identified C2 domains and IP addresses.');
        recommendations.push('Monitor for beaconing patterns in network traffic.');
        recommendations.push('Isolate potentially compromised hosts for investigation.');
        break;
    }
  }
  
  // Block malicious IPs
  const maliciousIps = new Set<string>();
  for (const chain of chains) {
    if (chain.prediction.confidence >= 0.8) {
      chain.sourceIps.forEach(ip => maliciousIps.add(ip));
    }
  }
  
  if (maliciousIps.size > 0) {
    recommendations.push(`Consider blocking ${maliciousIps.size} malicious IP addresses at the firewall.`);
  }
  
  // General recommendations
  if (chains.length > 0) {
    recommendations.push('Document incident findings and update threat intelligence.');
    recommendations.push('Review and update incident response procedures.');
    recommendations.push('Consider security awareness training based on attack vectors observed.');
  }
  
  return [...new Set(recommendations)]; // Remove duplicates
}

/**
 * Create empty result
 */
function createEmptyResult(): CorrelationResult {
  return {
    success: true,
    totalEvents: 0,
    correlatedEvents: 0,
    attackChains: [],
    timeline: [],
    summary: {
      totalAlerts: 0,
      criticalAlerts: 0,
      falsePositivesFiltered: 0,
      attackTypesDetected: [],
      mostTargetedUsers: [],
      mostActiveSourceIps: [],
      riskScore: 0,
    },
    recommendations: [],
  };
}
