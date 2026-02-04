// Enhanced Multi-Log Correlation Engine
// Correlates events across multiple log sources to detect and visualize attack chains

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

type LogSource = 'auth' | 'web' | 'database' | 'firewall' | 'system' | 'mail' | 'network' | 'other';

function getLogSource(logType: string): LogSource {
  const sourceMap: Record<string, LogSource> = {
    ssh_auth: 'auth', pam: 'auth', vsftpd: 'auth', proftpd: 'auth',
    apache: 'web', nginx: 'web', iis: 'web', django: 'web', flask: 'web',
    rails: 'web', express: 'web', fastapi: 'web', gunicorn: 'web', uvicorn: 'web',
    mysql_error: 'database', mysql_query: 'database', mysql_slow: 'database',
    postgres_error: 'database', postgres_auth: 'database', postgres_statement: 'database',
    oracle_alert: 'database', oracle_listener: 'database', oracle_audit: 'database',
    sqlserver_error: 'database', sqlserver_audit: 'database', sqlserver_transaction: 'database',
    mongodb_server: 'database', mongodb_audit: 'database',
    iptables: 'firewall', ufw: 'firewall', nftables: 'firewall', firewalld: 'firewall',
    windows_firewall: 'firewall', palo_alto: 'firewall', fortigate: 'firewall',
    cisco_asa: 'firewall', checkpoint: 'firewall', aws_vpc_flow: 'firewall',
    azure_nsg: 'firewall', gcp_vpc: 'firewall',
    syslog: 'system', systemd: 'system', kernel: 'system', audit: 'system',
    package: 'system', cron: 'system', daemon: 'system',
    windows_security: 'system', windows_system: 'system', windows_application: 'system',
    postfix: 'mail', sendmail: 'mail', exim: 'mail', dovecot: 'mail', exchange: 'mail',
    dns: 'network', dhcp: 'network', proxy: 'network',
    windows_event: 'system', windows_event_viewer: 'system',
  };
  return sourceMap[logType] || 'other';
}

export function correlateMultipleLogs(
  logSources: Array<{ name: string; entries: ParsedLogEntry[] }>
): CorrelationResult {
  const allEntries: ParsedLogEntry[] = [];
  const sourceNames = new Map<string, string>();
  
  for (const source of logSources) {
    for (const entry of source.entries) {
      allEntries.push(entry);
      sourceNames.set(entry.id, source.name);
    }
  }
  
  if (allEntries.length === 0) {
    return createEmptyResult();
  }
  
  const sortedEntries = [...allEntries]
    .filter(e => {
      if (!e.timestamp) return false;
      const time = new Date(e.timestamp).getTime();
      return !isNaN(time) && time > 0;
    })
    .sort((a, b) => new Date(a.timestamp!).getTime() - new Date(b.timestamp!).getTime());
  
  const baseline = buildBaseline(sortedEntries);
  
  // Build comprehensive attack chains
  const attackChains = detectAttackChains(sortedEntries, baseline, sourceNames);
  
  // Build enhanced timeline
  const timeline = buildEnhancedTimeline(sortedEntries, attackChains, sourceNames);
  
  // Generate summary with attack progression
  const summary = generateEnhancedSummary(sortedEntries, attackChains);
  
  // Generate recommendations
  const recommendations = generateRecommendations(attackChains);
  
  return {
    success: true,
    totalEvents: allEntries.length,
    correlatedEvents: attackChains.reduce((sum, c) => sum + c.events.length, 0),
    attackChains,
    timeline,
    summary,
    recommendations,
  };
}

function detectAttackChains(
  entries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>,
  sourceNames: Map<string, string>
): AttackChain[] {
  const chains: AttackChain[] = [];
  const processedIds = new Set<string>();
  
  // Phase 1: Single-source attack chains
  const byIp = groupBySourceIp(entries);
  const byUser = groupByUser(entries);
  
  for (const [ip, ipEntries] of byIp) {
    const chain = buildIpAttackChain(ip, ipEntries, baseline, sourceNames);
    if (chain) {
      chains.push(chain);
      chain.events.forEach(e => processedIds.add(e.id));
    }
  }
  
  for (const [user, userEntries] of byUser) {
    const uncovered = userEntries.filter(e => !processedIds.has(e.id));
    if (uncovered.length >= 3) {
      const chain = buildUserAttackChain(user, uncovered, baseline, sourceNames);
      if (chain) {
        chains.push(chain);
        chain.events.forEach(e => processedIds.add(e.id));
      }
    }
  }
  
  // Phase 2: Cross-source attack chains (kill chain detection)
  const crossSourceChains = detectKillChains(entries, baseline, sourceNames);
  for (const chain of crossSourceChains) {
    if (!chain.events.some(e => processedIds.has(e.id))) {
      chains.push(chain);
    }
  }
  
  // Phase 3: Temporal attack patterns
  const temporalChains = detectTemporalPatterns(entries, baseline, sourceNames);
  for (const chain of temporalChains) {
    if (!chain.events.some(e => processedIds.has(e.id))) {
      chains.push(chain);
    }
  }
  
  return chains.filter(c => !c.prediction.isFalsePositive);
}

function groupBySourceIp(entries: ParsedLogEntry[]): Map<string, ParsedLogEntry[]> {
  const groups = new Map<string, ParsedLogEntry[]>();
  for (const entry of entries) {
    const ip = entry.source.ip;
    if (!ip) continue;
    if (!groups.has(ip)) groups.set(ip, []);
    groups.get(ip)!.push(entry);
  }
  return groups;
}

function groupByUser(entries: ParsedLogEntry[]): Map<string, ParsedLogEntry[]> {
  const groups = new Map<string, ParsedLogEntry[]>();
  for (const entry of entries) {
    const user = entry.user?.name;
    if (!user) continue;
    if (!groups.has(user)) groups.set(user, []);
    groups.get(user)!.push(entry);
  }
  return groups;
}

function buildIpAttackChain(
  ip: string,
  entries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>,
  sourceNames: Map<string, string>
): AttackChain | null {
  if (entries.length < 3) return null;
  
  const features = extractFeatures(entries, baseline);
  const predictions = classifyAttack(features);
  if (predictions.length === 0) return null;
  
  const topPred = predictions[0];
  if (topPred.isFalsePositive) return null;
  
  const events = entries
    .sort((a, b) => new Date(a.timestamp!).getTime() - new Date(b.timestamp!).getTime())
    .map((entry, idx) => createCorrelatedEvent(entry, sourceNames, topPred.attackType, idx / entries.length));
  
  const startTime = new Date(events[0].timestamp).getTime();
  const endTime = new Date(events[events.length - 1].timestamp).getTime();
  const durationMinutes = (endTime - startTime) / 60000;
  
  return {
    id: generateId(),
    startTime: events[0].timestamp,
    endTime: events[events.length - 1].timestamp,
    attackType: topPred.attackType,
    stage: determineAttackStage(events, topPred.attackType),
    events,
    sourceIps: [ip],
    targetUsers: [...new Set(events.map(e => e.targetUser).filter(Boolean))] as string[],
    targetHosts: [...new Set(events.map(e => e.targetHost).filter(Boolean))] as string[],
    prediction: topPred,
    mitreTactics: getMitreTactics(topPred.attackType),
    mitreTechniques: getMitreTechniques(topPred.attackType),
    recommendation: generateRecommendation(topPred.attackType, events, durationMinutes),
  };
}

function buildUserAttackChain(
  user: string,
  entries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>,
  sourceNames: Map<string, string>
): AttackChain | null {
  if (entries.length < 3) return null;
  
  const features = extractFeatures(entries, baseline);
  const predictions = classifyAttack(features);
  if (predictions.length === 0) return null;
  
  const topPred = predictions[0];
  if (topPred.isFalsePositive) return null;
  
  const events = entries
    .sort((a, b) => new Date(a.timestamp!).getTime() - new Date(b.timestamp!).getTime())
    .map((entry, idx) => createCorrelatedEvent(entry, sourceNames, topPred.attackType, idx / entries.length));
  
  const uniqueIps = [...new Set(events.map(e => e.sourceIp).filter(Boolean))];
  const durationMinutes = (new Date(events[events.length - 1].timestamp).getTime() - new Date(events[0].timestamp).getTime()) / 60000;
  
  return {
    id: generateId(),
    startTime: events[0].timestamp,
    endTime: events[events.length - 1].timestamp,
    attackType: topPred.attackType,
    stage: determineAttackStage(events, topPred.attackType),
    events,
    sourceIps: uniqueIps,
    targetUsers: [user],
    targetHosts: [...new Set(events.map(e => e.targetHost).filter(Boolean))] as string[],
    prediction: topPred,
    mitreTactics: getMitreTactics(topPred.attackType),
    mitreTechniques: getMitreTechniques(topPred.attackType),
    recommendation: generateRecommendation(topPred.attackType, events, durationMinutes),
  };
}

function detectKillChains(
  entries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>,
  sourceNames: Map<string, string>
): AttackChain[] {
  const chains: AttackChain[] = [];
  
  const webEntries = entries.filter(e => getLogSource(e.logType) === 'web');
  const dbEntries = entries.filter(e => getLogSource(e.logType) === 'database');
  const authEntries = entries.filter(e => getLogSource(e.logType) === 'auth');
  const sysEntries = entries.filter(e => getLogSource(e.logType) === 'system');
  const fwEntries = entries.filter(e => getLogSource(e.logType) === 'firewall');
  const netEntries = entries.filter(e => getLogSource(e.logType) === 'network');
  
  // SQL Injection Chain: Web -> Database
  if (webEntries.length > 0 && dbEntries.length > 0) {
    const chain = detectSqlInjectionChain(webEntries, dbEntries, baseline, sourceNames);
    if (chain) chains.push(chain);
  }
  
  // Account Takeover: Auth failures -> Success
  if (authEntries.length > 0) {
    const chain = detectAccountTakeover(authEntries, fwEntries, baseline, sourceNames);
    if (chain) chains.push(chain);
  }
  
  // Privilege Escalation: Auth success with admin access
  const adminAccess = authEntries.filter(e => 
    e.outcome === 'success' && 
    /admin|root|administrator|system/i.test(e.user?.name || '')
  );
  if (adminAccess.length > 0) {
    const chain = buildSimpleChain(
      adminAccess, 'privilege_escalation', 'privilege_escalation',
      baseline, sourceNames
    );
    if (chain) chains.push(chain);
  }
  
  // Ransomware indicators
  const ransomwareIndicators = sysEntries.filter(e =>
    /vssadmin.*delete|shadowcopy.*delete|encrypt|\.locked|bcdedit.*recoverydisabled/i.test(e.message)
  );
  if (ransomwareIndicators.length >= 2) {
    const chain = buildSimpleChain(
      ransomwareIndicators, 'ransomware', 'complete',
      baseline, sourceNames
    );
    if (chain) chains.push(chain);
  }
  
  // Web shell patterns
  const webshellPatterns = webEntries.filter(e =>
    /\.(php|asp|aspx|jsp)\?cmd=|c99|r57|b374k|wso/i.test(e.message)
  );
  if (webshellPatterns.length > 0) {
    const chain = buildSimpleChain(webshellPatterns, 'webshell', 'persistence', baseline, sourceNames);
    if (chain) chains.push(chain);
  }
  
  // Brute force pattern
  const failures = authEntries.filter(e => e.outcome === 'failure');
  const ipGroups = groupBySourceIp(failures);
  for (const [ip, fails] of ipGroups) {
    if (fails.length >= 5) {
      const chain = buildSimpleChain(fails, 'bruteforce', 'reconnaissance', baseline, sourceNames);
      if (chain) chains.push(chain);
    }
  }
  
  return chains;
}

function detectSqlInjectionChain(
  webEntries: ParsedLogEntry[],
  dbEntries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>,
  sourceNames: Map<string, string>
): AttackChain | null {
  const suspiciousWeb = webEntries.filter(e =>
    e.severity === 'error' || e.severity === 'warning' ||
    /sql|union|select|insert|delete|drop|'.*or.*'|1=1/i.test(e.message)
  );
  
  if (suspiciousWeb.length === 0) return null;
  
  const webTime = new Date(suspiciousWeb[0].timestamp!).getTime();
  const relatedDb = dbEntries.filter(db => {
    const dbTime = new Date(db.timestamp!).getTime();
    return dbTime > webTime && dbTime - webTime < 60000;
  });
  
  if (relatedDb.length === 0) return null;
  
  const allEvents = [...suspiciousWeb, ...relatedDb].map((e, idx) => 
    createCorrelatedEvent(e, sourceNames, 'sql_injection', idx / (suspiciousWeb.length + relatedDb.length))
  );
  
  return {
    id: generateId(),
    startTime: allEvents[0].timestamp,
    endTime: allEvents[allEvents.length - 1].timestamp,
    attackType: 'sql_injection',
    stage: 'execution',
    events: allEvents.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()),
    sourceIps: [...new Set(allEvents.map(e => e.sourceIp).filter(Boolean))] as string[],
    targetUsers: [],
    targetHosts: [],
    prediction: {
      attackType: 'sql_injection',
      confidence: 0.85,
      probability: 0.85,
      features: {},
      explanation: ['SQL injection attempt detected', 'Followed by database query execution'],
      isFalsePositive: false,
    },
    mitreTactics: getMitreTactics('sql_injection'),
    mitreTechniques: getMitreTechniques('sql_injection'),
    recommendation: 'Review web application input validation. Patch vulnerable endpoints. Implement prepared statements.',
  };
}

function detectAccountTakeover(
  authEntries: ParsedLogEntry[],
  fwEntries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>,
  sourceNames: Map<string, string>
): AttackChain | null {
  const userGroups = new Map<string, ParsedLogEntry[]>();
  for (const entry of authEntries) {
    if (!entry.user?.name) continue;
    if (!userGroups.has(entry.user.name)) userGroups.set(entry.user.name, []);
    userGroups.get(entry.user.name)!.push(entry);
  }
  
  for (const [user, events] of userGroups) {
    const failures = events.filter(e => e.outcome === 'failure');
    const successes = events.filter(e => e.outcome === 'success');
    
    if (failures.length >= 5 && successes.length > 0) {
      const firstFail = new Date(failures[0].timestamp!).getTime();
      const firstSuccess = new Date(successes[0].timestamp!).getTime();
      const uniqueIps = new Set(failures.map(e => e.source.ip).filter(Boolean));
      
      if (firstSuccess > firstFail && uniqueIps.size >= 2) {
        const allEvents = [...failures, ...successes].map((e, idx) =>
          createCorrelatedEvent(e, sourceNames, 'account_takeover', idx / (failures.length + successes.length))
        ).sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
        
        return {
          id: generateId(),
          startTime: allEvents[0].timestamp,
          endTime: allEvents[allEvents.length - 1].timestamp,
          attackType: 'account_takeover',
          stage: 'initial_access',
          events: allEvents,
          sourceIps: [...uniqueIps] as string[],
          targetUsers: [user],
          targetHosts: [],
          prediction: {
            attackType: 'account_takeover',
            confidence: 0.9,
            probability: 0.9,
            features: {},
            explanation: [
              `${failures.length} failed login attempts`,
              `Successful login after ${uniqueIps.size} different source IPs`,
              'Account compromise likely'
            ],
            isFalsePositive: false,
          },
          mitreTactics: getMitreTactics('account_takeover'),
          mitreTechniques: getMitreTechniques('account_takeover'),
          recommendation: `Force password reset for user "${user}". Review recent login locations. Enable MFA.`,
        };
      }
    }
  }
  return null;
}

function detectTemporalPatterns(
  entries: ParsedLogEntry[],
  baseline: ReturnType<typeof buildBaseline>,
  sourceNames: Map<string, string>
): AttackChain[] {
  const chains: AttackChain[] = [];
  
  // Detect burst activity (more than 10 events in 1 minute from same IP)
  const byIp = groupBySourceIp(entries);
  for (const [ip, ipEntries] of byIp) {
    if (ipEntries.length < 10) continue;
    
    const sorted = ipEntries.sort((a, b) => new Date(a.timestamp!).getTime() - new Date(b.timestamp!).getTime());
    const firstTime = new Date(sorted[0].timestamp!).getTime();
    
    const burstEntries = sorted.filter(e => {
      const time = new Date(e.timestamp!).getTime();
      return time - firstTime < 60000;
    });
    
    if (burstEntries.length >= 10) {
      const chain = buildSimpleChain(burstEntries, 'ddos', 'execution', baseline, sourceNames);
      if (chain) chains.push(chain);
    }
  }
  
  return chains;
}

function buildSimpleChain(
  entries: ParsedLogEntry[],
  attackType: AttackType,
  stage: AttackChain['stage'],
  baseline: ReturnType<typeof buildBaseline>,
  sourceNames: Map<string, string>
): AttackChain | null {
  if (entries.length < 2) return null;
  
  const events = entries
    .sort((a, b) => new Date(a.timestamp!).getTime() - new Date(b.timestamp!).getTime())
    .map((e, idx) => createCorrelatedEvent(e, sourceNames, attackType, idx / entries.length));
  
  return {
    id: generateId(),
    startTime: events[0].timestamp,
    endTime: events[events.length - 1].timestamp,
    attackType,
    stage,
    events,
    sourceIps: [...new Set(events.map(e => e.sourceIp).filter(Boolean))] as string[],
    targetUsers: [...new Set(events.map(e => e.targetUser).filter(Boolean))] as string[],
    targetHosts: [...new Set(events.map(e => e.targetHost).filter(Boolean))] as string[],
    prediction: {
      attackType,
      confidence: 0.7,
      probability: 0.7,
      features: {},
      explanation: [`${entries.length} events detected matching ${attackType} pattern`],
      isFalsePositive: false,
    },
    mitreTactics: getMitreTactics(attackType),
    mitreTechniques: getMitreTechniques(attackType),
    recommendation: generateRecommendation(attackType, events, 0),
  };
}

function createCorrelatedEvent(
  entry: ParsedLogEntry,
  sourceNames: Map<string, string>,
  attackType: AttackType,
  progress: number
): CorrelatedEvent {
  const severityScores: Record<string, number> = {
    critical: 1.0, high: 0.8, error: 0.6, warning: 0.4, info: 0.2, debug: 0.1, unknown: 0.2
  };
  
  return {
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
    correlationScore: Math.min(0.5 + progress * 0.5, severityScores[entry.severity] || 0.5),
  };
}

function determineAttackStage(events: CorrelatedEvent[], attackType: AttackType): AttackChain['stage'] {
  const sources = new Set(events.map(e => e.logSource));
  const hasSuccess = events.some(e => e.outcome === 'success');
  const hasFailure = events.some(e => e.outcome === 'failure');
  
  const attackTypeStages: Record<string, AttackChain['stage']> = {
    bruteforce: hasSuccess ? 'initial_access' : 'reconnaissance',
    password_spray: hasSuccess ? 'initial_access' : 'reconnaissance',
    sql_injection: 'execution',
    xss_attack: 'execution',
    command_injection: 'execution',
    privilege_escalation: 'privilege_escalation',
    lateral_movement: 'lateral_movement',
    data_exfiltration: 'exfiltration',
    ransomware: 'complete',
    webshell: 'persistence',
    c2_communication: 'execution',
    apt_activity: sources.size > 3 ? 'complete' : 'execution',
  };
  
  if (attackTypeStages[attackType]) return attackTypeStages[attackType];
  
  if (sources.size > 2) return 'execution';
  if (hasSuccess && !hasFailure) return 'complete';
  return 'execution';
}

function generateRecommendation(attackType: AttackType, events: CorrelatedEvent[], durationMinutes: number): string {
  const recommendations: Record<string, string> = {
    bruteforce: 'Implement account lockout policies. Use strong passwords. Enable MFA.',
    password_spray: 'Monitor for unusual login patterns. Block suspicious IPs. Use MFA.',
    sql_injection: 'Review input validation. Use prepared statements. Patch vulnerabilities.',
    xss_attack: 'Implement CSP headers. Sanitize user inputs. Use framework security features.',
    command_injection: 'Avoid system() calls. Use parameterized commands. Validate all inputs.',
    privilege_escalation: 'Review sudo/admin permissions. Enable LSA protection. Monitor admin activity.',
    lateral_movement: 'Implement network segmentation. Restrict remote access. Monitor authentication patterns.',
    data_exfiltration: 'Block unusual data transfers. Implement DLP. Monitor DNS queries.',
    ransomware: 'Restore from backups immediately. Isolate affected systems. Do not pay ransom.',
    webshell: 'Remove webshell files. Review web server logs. Check file integrity.',
    c2_communication: 'Block suspicious domains. Implement DNS filtering. Investigate hosts.',
    default: 'Review the attack chain. Implement defense-in-depth. Enable enhanced monitoring.',
  };
  
  const prefix = durationMinutes > 0 ? `Attack occurred over ${durationMinutes.toFixed(1)} minutes. ` : '';
  return prefix + (recommendations[attackType] || recommendations.default);
}

function buildEnhancedTimeline(
  entries: ParsedLogEntry[],
  chains: AttackChain[],
  sourceNames: Map<string, string>
): TimelineEvent[] {
  const events: TimelineEvent[] = [];
  const chainIds = new Set(chains.map(c => c.id));
  
  // Add all entries as timeline events
  for (const entry of entries) {
    const chain = chains.find(c => c.events.some(e => e.id === entry.id));
    const isAnomaly = chain !== undefined;
    
    events.push({
      id: entry.id,
      timestamp: entry.timestamp!,
      logSource: getLogSource(entry.logType),
      eventType: entry.logType,
      severity: entry.severity as TimelineEvent['severity'],
      title: generateEventTitle(entry),
      description: entry.message.slice(0, 200),
      sourceIp: entry.source.ip,
      targetUser: entry.user?.name,
      relatedAttackChainId: chain?.id,
      isAnomaly,
      anomalyScore: chain ? chain.prediction.confidence : 0,
    });
  }
  
  // Sort by timestamp
  return events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
}

function generateEventTitle(entry: ParsedLogEntry): string {
  if (entry.source.ip && entry.action) {
    return `${entry.source.ip} ${entry.action}`;
  }
  if (entry.user?.name) {
    return `${entry.user.name} ${entry.outcome || ''}`.trim();
  }
  if (entry.severity) {
    return `${entry.severity.toUpperCase()} event`;
  }
  return 'Log Entry';
}

function generateEnhancedSummary(entries: ParsedLogEntry[], chains: AttackChain[]) {
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const entry of entries) {
    const s = entry.severity?.toLowerCase();
    if (s in severityCounts) severityCounts[s as keyof typeof severityCounts]++;
  }
  
  const ipThreats = new Map<string, { count: number; types: Set<string> }>();
  const userTargets = new Map<string, number>();
  
  for (const chain of chains) {
    for (const ip of chain.sourceIps) {
      if (!ipThreats.has(ip)) ipThreats.set(ip, { count: 0, types: new Set() });
      ipThreats.get(ip)!.count++;
      ipThreats.get(ip)!.types.add(chain.attackType);
    }
    for (const user of chain.targetUsers) {
      userTargets.set(user, (userTargets.get(user) || 0) + 1);
    }
  }
  
  const sortedIpThreats = [...ipThreats.entries()]
    .map(([ip, data]) => ({
      ip,
      count: data.count,
      threatScore: data.count * data.types.size,
      attackTypes: [...data.types],
    }))
    .sort((a, b) => b.threatScore - a.threatScore)
    .slice(0, 10);
  
  const sortedUsers = [...userTargets.entries()]
    .map(([user, count]) => ({ user, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
  
  const attackTypesDetected = [...new Set(chains.map(c => c.attackType))];
  
  const riskScore = Math.min(
    chains.length * 15 + 
    severityCounts.critical * 20 +
    severityCounts.high * 10 +
    sortedIpThreats.length * 5,
    100
  );
  
  return {
    totalAlerts: entries.length,
    criticalAlerts: severityCounts.critical,
    falsePositivesFiltered: chains.filter(c => c.prediction.isFalsePositive).length,
    attackTypesDetected: attackTypesDetected as AttackType[],
    mostTargetedUsers: sortedUsers,
    mostActiveSourceIps: sortedIpThreats,
    riskScore,
  };
}

function generateRecommendations(chains: AttackChain[]): string[] {
  const recs = new Set<string>();
  
  for (const chain of chains) {
    recs.add(chain.recommendation);
    
    if (chain.attackType === 'bruteforce') {
      recs.add('Consider implementing rate limiting on authentication endpoints');
    }
    if (chain.attackType === 'sql_injection') {
      recs.add('Review and patch all web application inputs');
    }
    if (chain.stage === 'complete') {
      recs.add('CRITICAL: Immediate investigation required - attack completed');
    }
  }
  
  return [...recs].slice(0, 10);
}

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
    recommendations: ['No anomalies detected in the provided logs'],
  };
}
