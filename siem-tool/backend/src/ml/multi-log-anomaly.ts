// Multi-Log Type Anomaly Detection
// TypeScript inference engine using trained statistical models

import type { ParsedLogEntry } from '../types';
import type { AttackType } from './types';

export interface TrainedModel {
  log_type: string;
  category: string;
  description: string;
  version: string;
  trained_at: string;
  feature_names: string[];
  features: string[];
  attack_patterns: string[];
  feature_statistics: {
    means: number[];
    stds: number[];
    mins: number[];
    maxs: number[];
  };
  model: {
    type: string;
    n_estimators?: number;
    contamination?: number;
    score_range: [number, number];
    score_mean: number;
    score_std: number;
    anomaly_threshold: number;
    training_samples: number;
    accuracy?: number;
    score_distribution: {
      min: number;
      max: number;
      mean: number;
      percentile_5: number;
      percentile_95: number;
    };
  };
  attack_labels: Record<string, number>;
}

export interface LogTypePrediction {
  logType: string;
  anomalyScore: number;
  isAnomaly: boolean;
  confidence: number;
  detectedAttackTypes: string[];
  featureScores: Record<string, number>;
  explanation: string[];
}

interface ModelRegistry {
  models: Record<string, TrainedModel>;
  loadedAt: string;
}

const MODEL_CACHE: Map<string, TrainedModel> = new Map();
let MODEL_REGISTRY: ModelRegistry | null = null;

export function getLogTypeFromEntries(entries: ParsedLogEntry[]): string {
  const logTypes = new Map<string, number>();
  
  for (const entry of entries) {
    if (entry.logType && entry.logType !== 'unknown') {
      logTypes.set(entry.logType, (logTypes.get(entry.logType) || 0) + 1);
    }
  }
  
  let bestType = 'generic';
  let bestCount = 0;
  for (const [type, count] of logTypes) {
    if (count > bestCount) {
      bestCount = count;
      bestType = type;
    }
  }
  
  return mapLogTypeToModel(bestType);
}

function mapLogTypeToModel(logType: string): string {
  const mapping: Record<string, string> = {
    'apache': 'apache',
    'nginx': 'nginx',
    'iis': 'iis',
    'express': 'apache',
    'django': 'apache',
    'flask': 'apache',
    'rails': 'apache',
    'gunicorn': 'apache',
    'fastapi': 'apache',
    'laravel': 'apache',
    'sshd': 'ssh_auth',
    'ssh_auth': 'ssh_auth',
    'ssh_failed': 'ssh_auth',
    'ssh_accepted': 'ssh_auth',
    'syslog': 'syslog',
    'systemd': 'syslog',
    'kernel': 'linux_kernel',
    'audit': 'syslog',
    'iptables': 'firewall',
    'ufw': 'firewall',
    'firewalld': 'firewall',
    'windows_firewall': 'firewall',
    'palo_alto': 'firewall',
    'fortigate': 'firewall',
    'cisco_asa': 'firewall',
    'aws_vpc_flow': 'aws_vpc_flow',
    'azure_nsg': 'azure_nsg',
    'mysql_error': 'mysql_error',
    'mysql_query': 'mysql_error',
    'mysql_slow': 'mysql_error',
    'postgres_error': 'postgres_error',
    'postgres_auth': 'postgres_error',
    'postgres_statement': 'postgres_error',
    'mongodb': 'mongodb',
    'postfix': 'postfix',
    'sendmail': 'postfix',
    'exim': 'postfix',
    'dovecot': 'postfix',
    'suricata': 'suricata',
    'zeek': 'zeek',
    'ossec': 'ossec',
    'cloudtrail': 'cloudtrail',
    'cloudflare': 'cloudtrail',
    'kubernetes': 'kubernetes',
    'docker': 'kubernetes',
    'elasticsearch': 'elasticsearch',
    'redis': 'elasticsearch',
    'rabbitmq': 'rabbitmq',
    'kafka': 'rabbitmq',
    'squid': 'squid',
    'dns': 'dns',
    'dhcp': 'dhcp',
    'windows_event': 'windows_event',
    'windows': 'windows_event',
  };
  
  return mapping[logType.toLowerCase()] || 'generic';
}

export function extractFeaturesByLogType(entries: ParsedLogEntry[], logType: string): Record<string, number> {
  const features: Record<string, number> = {};
  
  if (logType === 'apache' || logType === 'nginx' || logType === 'iis') {
    return extractWebserverFeatures(entries);
  } else if (logType === 'ssh_auth') {
    return extractSSHAuthFeatures(entries);
  } else if (logType === 'syslog' || logType === 'linux_kernel') {
    return extractSyslogFeatures(entries);
  } else if (logType === 'firewall' || logType === 'aws_vpc_flow' || logType === 'azure_nsg') {
    return extractFirewallFeatures(entries);
  } else if (logType === 'mysql_error' || logType === 'postgres_error') {
    return extractDatabaseFeatures(entries);
  } else if (logType === 'postfix' || logType === 'mail') {
    return extractMailFeatures(entries);
  } else if (logType === 'suricata' || logType === 'zeek' || logType === 'ossec') {
    return extractSecurityToolFeatures(entries);
  }
  
  return extractGenericFeatures(entries);
}

function extractWebserverFeatures(entries: ParsedLogEntry[]): Record<string, number> {
  const features: Record<string, number> = {
    status_5xx_ratio: 0,
    avg_response_time: 0,
    unique_urls: 0,
    unique_ips: 0,
    requests_per_minute: 0,
    bytes_per_request: 0,
    error_rate: 0,
    unique_user_agents: 0,
    get_post_ratio: 0,
    unique_referers: 0,
    total_requests: entries.length,
  };
  
  const statusCodes: number[] = [];
  const responseSizes: number[] = [];
  const urls = new Set<string>();
  const ips = new Set<string>();
  const userAgents = new Set<string>();
  const referers = new Set<string>();
  const getCount = 0;
  const postCount = 0;
  
  for (const entry of entries) {
    const msg = entry.message || '';
    
    const statusMatch = msg.match(/" (\d{3}) /);
    if (statusMatch) {
      statusCodes.push(parseInt(statusMatch[1]));
    }
    
    const urlMatch = msg.match(/"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) (\S+) /);
    if (urlMatch) {
      urls.add(urlMatch[1]);
    }
    
    if (entry.source?.ip) {
      ips.add(entry.source.ip);
    }
    
    const uaMatch = msg.match(/"[^"]*" "([^"]*)"/);
    if (uaMatch) {
      userAgents.add(uaMatch[1]);
    }
    
    const refMatch = msg.match(/"[^"]*" "([^"]*)" "/);
    if (refMatch && refMatch[1] !== '-') {
      referers.add(refMatch[1]);
    }
    
    if (msg.toLowerCase().includes('error') || msg.toLowerCase().includes('fail')) {
      features.error_rate += 1;
    }
  }
  
  features.status_5xx_ratio = statusCodes.length > 0 
    ? statusCodes.filter(s => s >= 500).length / statusCodes.length 
    : 0;
  features.unique_urls = urls.size;
  features.unique_ips = ips.size;
  features.unique_user_agents = userAgents.size;
  features.unique_referers = referers.size;
  features.error_rate = features.error_rate / entries.length;
  
  return features;
}

function extractSSHAuthFeatures(entries: ParsedLogEntry[]): Record<string, number> {
  const features: Record<string, number> = {
    failed_login_count: 0,
    successful_login_count: 0,
    failed_login_rate: 0,
    unique_ips: 0,
    unique_users: 0,
    unique_ips_per_user: 0,
    authentication_failures: 0,
  };
  
  const ips = new Set<string>();
  const users = new Set<string>();
  const failedLogins: string[] = [];
  const successfulLogins: string[] = [];
  
  for (const entry of entries) {
    const msg = entry.message || '';
    
    if (msg.toLowerCase().includes('failed') || msg.toLowerCase().includes('failure')) {
      features.failed_login_count++;
      failedLogins.push(msg);
    } else if (msg.toLowerCase().includes('accepted') || msg.toLowerCase().includes('success')) {
      features.successful_login_count++;
      successfulLogins.push(msg);
    }
    
    const ipMatch = msg.match(/from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    if (ipMatch) {
      ips.add(ipMatch[1]);
    }
    
    const userMatch = msg.match(/for (?:invalid user )?(\S+)/);
    if (userMatch) {
      users.add(userMatch[1]);
    }
  }
  
  features.unique_ips = ips.size;
  features.unique_users = users.size;
  features.unique_ips_per_user = users.size > 0 ? ips.size / users.size : 0;
  
  const total = features.failed_login_count + features.successful_login_count;
  features.failed_login_rate = total > 0 ? features.failed_login_count / total : 0;
  
  return features;
}

function extractSyslogFeatures(entries: ParsedLogEntry[]): Record<string, number> {
  const features: Record<string, number> = {
    error_count: 0,
    warning_count: 0,
    critical_count: 0,
    error_rate: 0,
    unique_programs: 0,
    severity_score: 0,
    total_entries: entries.length,
  };
  
  const programs = new Set<string>();
  
  for (const entry of entries) {
    const msg = entry.message || '';
    
    if (msg.toLowerCase().includes('error') || msg.includes('ERROR')) {
      features.error_count++;
    }
    if (msg.toLowerCase().includes('warning') || msg.includes('WARNING')) {
      features.warning_count++;
    }
    if (msg.toLowerCase().includes('critical') || msg.includes('CRIT')) {
      features.critical_count++;
    }
    
    const progMatch = msg.match(/\s+(\S+)\[(\d+)\]:/);
    if (progMatch) {
      programs.add(progMatch[1]);
    }
  }
  
  features.unique_programs = programs.size;
  features.error_rate = features.error_count / entries.length;
  features.severity_score = (
    features.error_count * 2 + 
    features.warning_count + 
    features.critical_count * 3
  ) / entries.length;
  
  return features;
}

function extractFirewallFeatures(entries: ParsedLogEntry[]): Record<string, number> {
  const features: Record<string, number> = {
    dropped_packets: 0,
    accepted_packets: 0,
    drop_rate: 0,
    unique_source_ips: 0,
    unique_destination_ips: 0,
    unique_ports: 0,
    port_scan_indicator: 0,
    total_entries: entries.length,
  };
  
  const srcIps = new Set<string>();
  const dstIps = new Set<string>();
  const ports = new Set<number>();
  
  for (const entry of entries) {
    const msg = entry.message || '';
    
    if (msg.includes('DROP') || msg.includes('BLOCK') || msg.includes('DENY')) {
      features.dropped_packets++;
    } else if (msg.includes('ACCEPT') || msg.includes('ALLOW')) {
      features.accepted_packets++;
    }
    
    const srcMatch = msg.match(/SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    if (srcMatch) {
      srcIps.add(srcMatch[1]);
    }
    
    const dstMatch = msg.match(/DST=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    if (dstMatch) {
      dstIps.add(dstMatch[1]);
    }
    
    const dportMatch = msg.match(/DPT=(\d+)/);
    if (dportMatch) {
      ports.add(parseInt(dportMatch[1]));
    }
  }
  
  features.unique_source_ips = srcIps.size;
  features.unique_destination_ips = dstIps.size;
  features.unique_ports = ports.size;
  
  const total = features.dropped_packets + features.accepted_packets;
  features.drop_rate = total > 0 ? features.dropped_packets / total : 0;
  features.port_scan_indicator = ports.size > 50 && features.dropped_packets > 100 ? 1 : 0;
  
  return features;
}

function extractDatabaseFeatures(entries: ParsedLogEntry[]): Record<string, number> {
  const features: Record<string, number> = {
    error_count: 0,
    slow_query_count: 0,
    connection_count: 0,
    abort_count: 0,
    error_rate: 0,
    critical_rate: 0,
    total_entries: entries.length,
  };
  
  for (const entry of entries) {
    const msg = entry.message || '';
    
    if (msg.includes('ERROR') || msg.toLowerCase().includes('error')) {
      features.error_count++;
    }
    if (msg.toLowerCase().includes('slow')) {
      features.slow_query_count++;
    }
    if (msg.toLowerCase().includes('connection')) {
      features.connection_count++;
    }
    if (msg.toLowerCase().includes('abort') || msg.toLowerCase().includes('aborting')) {
      features.abort_count++;
    }
  }
  
  features.error_rate = features.error_count / entries.length;
  features.critical_rate = (features.error_count + features.abort_count) / entries.length;
  
  return features;
}

function extractMailFeatures(entries: ParsedLogEntry[]): Record<string, number> {
  const features: Record<string, number> = {
    mail_count: 0,
    unique_senders: 0,
    unique_recipients: 0,
    relay_rate: 0,
    connection_failures: 0,
    size_distribution: 0,
    message_rate: 0,
    total_entries: entries.length,
  };
  
  const senders = new Set<string>();
  const recipients = new Set<string>();
  
  for (const entry of entries) {
    const msg = entry.message || '';
    
    if (msg.toLowerCase().includes('from=') || msg.toLowerCase().includes('from :')) {
      const fromMatch = msg.match(/from=<([^>]+)>/);
      if (fromMatch) {
        senders.add(fromMatch[1]);
      }
    }
    
    if (msg.toLowerCase().includes('to=') || msg.toLowerCase().includes('to :')) {
      const toMatch = msg.match(/to=<([^>]+)>/);
      if (toMatch) {
        recipients.add(toMatch[1]);
      }
    }
    
    if (msg.includes('NOQUEUE') || msg.toLowerCase().includes('reject')) {
      features.connection_failures++;
    }
  }
  
  features.unique_senders = senders.size;
  features.unique_recipients = recipients.size;
  features.mail_count = entries.length;
  
  return features;
}

function extractSecurityToolFeatures(entries: ParsedLogEntry[]): Record<string, number> {
  const features: Record<string, number> = {
    alert_count: 0,
    unique_signatures: 0,
    severity_distribution: 0,
    source_ip_count: 0,
    target_ip_count: 0,
    protocol_distribution: 0,
    attack_category_count: 0,
    priority_distribution: 0,
    total_entries: entries.length,
  };
  
  const signatures = new Set<string>();
  const srcIps = new Set<string>();
  const dstIps = new Set<string>();
  
  for (const entry of entries) {
    const msg = entry.message || '';
    
    if (entry.severity === 'critical' || entry.severity === 'high' || msg.includes('[**]')) {
      features.alert_count++;
    }
    
    const sigMatch = msg.match(/\[\*\*\] (.*?) \[\*\*\]/);
    if (sigMatch) {
      signatures.add(sigMatch[1]);
    }
    
    if (entry.source?.ip) {
      srcIps.add(entry.source.ip);
    }
    
    if (entry.target?.host || entry.target?.ip) {
      dstIps.add(entry.target.ip || entry.target.host || '');
    }
  }
  
  features.unique_signatures = signatures.size;
  features.source_ip_count = srcIps.size;
  features.target_ip_count = dstIps.size;
  features.severity_distribution = features.alert_count / entries.length;
  
  return features;
}

function extractGenericFeatures(entries: ParsedLogEntry[]): Record<string, number> {
  const features: Record<string, number> = {
    error_count: 0,
    error_rate: 0,
    unique_ips: 0,
    line_count: entries.length,
  };
  
  const ips = new Set<string>();
  const errorKeywords = ['error', 'fail', 'denied', 'refused', 'timeout', 'exception'];
  
  for (const entry of entries) {
    const msg = entry.message || '';
    
    for (const keyword of errorKeywords) {
      if (msg.toLowerCase().includes(keyword)) {
        features.error_count++;
        break;
      }
    }
    
    if (entry.source?.ip) {
      ips.add(entry.source.ip);
    }
  }
  
  features.unique_ips = ips.size;
  features.error_rate = features.error_count / entries.length;
  
  return features;
}

function calculateAnomalyScore(features: Record<string, number>, model: TrainedModel): {
  score: number;
  featureScores: Record<string, number>;
} {
  const featureScores: Record<string, number> = {};
  
  if (!model?.feature_statistics?.means || !model?.feature_names) {
    return { score: 0, featureScores: {} };
  }
  
  const stats = model.feature_statistics;
  const featureNames = model.feature_names;
  
  let totalScore = 0;
  let weightSum = 0;
  
  for (let i = 0; i < featureNames.length; i++) {
    const featureName = featureNames[i];
    if (!featureName) continue;
    
    const value = features[featureName] ?? 0;
    const mean = stats.means[i] ?? 0;
    const std = (stats.stds[i] ?? 1) + 0.0001;
    
    if (std > 0) {
      const zScore = Math.abs((value - mean) / std);
      featureScores[featureName] = zScore;
      
      if (zScore > 3) {
        totalScore += Math.min(zScore / 5, 1);
        weightSum += 1;
      }
    } else {
      featureScores[featureName] = 0;
    }
  }
  
  const anomalyScore = weightSum > 0 ? Math.min(totalScore / weightSum, 1) : 0;
  
  return { score: anomalyScore, featureScores };
}

function detectAttackTypes(features: Record<string, number>, model: TrainedModel): string[] {
  const detectedAttacks: string[] = [];
  const patterns = model.attack_patterns || [];
  
  for (const pattern of patterns) {
    const lowerPattern = pattern.toLowerCase();
    
    if (lowerPattern === 'sql_injection' && features.error_rate > 0.1) {
      detectedAttacks.push('sql_injection');
    } else if (lowerPattern === 'xss' && features.error_rate > 0.05) {
      detectedAttacks.push('xss_attack');
    } else if (lowerPattern === 'bruteforce') {
      if (features.failed_login_rate !== undefined && features.failed_login_rate > 0.3) {
        detectedAttacks.push('bruteforce');
      }
    } else if (lowerPattern === 'port_scan') {
      if (features.port_scan_indicator !== undefined && features.port_scan_indicator > 0) {
        detectedAttacks.push('port_scan');
      }
    } else if (lowerPattern === 'dos' && features.error_rate > 0.2) {
      detectedAttacks.push('dos');
    } else if (lowerPattern === 'data_exfiltration') {
      if (features.drop_rate !== undefined && features.drop_rate > 0.5) {
        detectedAttacks.push('data_exfiltration');
      }
    }
  }
  
  return detectedAttacks;
}

function generateExplanation(
  features: Record<string, number>,
  featureScores: Record<string, number>,
  detectedAttacks: string[]
): string[] {
  const explanations: string[] = [];
  
  const sortedFeatures = Object.entries(featureScores)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5);
  
  for (const [feature, score] of sortedFeatures) {
    if (score > 2) {
      explanations.push(`${feature}: ${features[feature]?.toFixed(2) || 'N/A'} (deviation: ${score.toFixed(2)}σ)`);
    }
  }
  
  for (const attack of detectedAttacks) {
    explanations.push(`Attack pattern detected: ${attack}`);
  }
  
  if (explanations.length === 0) {
    explanations.push('No significant anomalies detected');
  }
  
  return explanations;
}

export function detectAnomaly(entries: ParsedLogEntry[]): LogTypePrediction | null {
  if (entries.length === 0) {
    return null;
  }
  
  const logType = getLogTypeFromEntries(entries);
  const modelKey = logType;
  
  let model = MODEL_CACHE.get(modelKey);
  
  if (!model) {
    try {
      const modelPath = `@siem/models/all_log_types/${modelKey}_model.json`;
      const modelJson = (globalThis as any).SIEM_MODELS?.[modelKey];
      
      if (modelJson) {
        model = modelJson as TrainedModel;
        MODEL_CACHE.set(modelKey, model);
      }
    } catch {
      model = null;
    }
  }
  
  const features = extractFeaturesByLogType(entries, logType);
  
  if (model) {
    const { score, featureScores } = calculateAnomalyScore(features, model);
    const detectedAttacks = detectAttackTypes(features, model);
    const explanation = generateExplanation(features, featureScores, detectedAttacks);
    
    const isAnomaly = score > 0.3 || detectedAttacks.length > 0;
    const confidence = Math.min(score * 1.2 + detectedAttacks.length * 0.1, 0.95);
    
    return {
      logType,
      anomalyScore: score,
      isAnomaly,
      confidence,
      detectedAttackTypes: detectedAttacks,
      featureScores,
      explanation,
    };
  }
  
  const genericFeatures = extractGenericFeatures(entries);
  const errorRate = genericFeatures.error_rate;
  const isAnomaly = errorRate > 0.15;
  
  return {
    logType,
    anomalyScore: errorRate,
    isAnomaly,
    confidence: isAnomaly ? 0.7 : 0.5,
    detectedAttackTypes: isAnomaly ? ['anomaly'] : [],
    featureScores: { error_rate: errorRate },
    explanation: isAnomaly 
      ? [`High error rate detected: ${(errorRate * 100).toFixed(1)}%`] 
      : ['Normal behavior patterns observed'],
  };
}

export function detectAnomaliesForAllTypes(entries: ParsedLogEntry[]): LogTypePrediction[] {
  const predictions: LogTypePrediction[] = [];
  
  const logTypes = new Set<string>();
  for (const entry of entries) {
    if (entry.logType && entry.logType !== 'unknown') {
      logTypes.add(mapLogTypeToModel(entry.logType));
    }
  }
  
  if (logTypes.size === 0) {
    logTypes.add('generic');
  }
  
  for (const logType of logTypes) {
    const typeEntries = entries.filter(e => 
      mapLogTypeToModel(e.logType) === logType || 
      (e.logType === 'unknown' && logType === 'generic')
    );
    
    const prediction = detectAnomaly(typeEntries);
    if (prediction) {
      predictions.push(prediction);
    }
  }
  
  return predictions;
}

export function getModelRegistry(): ModelRegistry | null {
  return MODEL_REGISTRY;
}

export function registerModels(registry: ModelRegistry): void {
  MODEL_REGISTRY = registry;
  
  for (const [logType, model] of Object.entries(registry.models)) {
    MODEL_CACHE.set(logType, model);
  }
}

export function clearModelCache(): void {
  MODEL_CACHE.clear();
  MODEL_REGISTRY = null;
}
