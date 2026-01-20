// Security Alert Detection Engine
// Based on ~/ISEA/Raju-ISEA/auth_dashboard.py detection logic

import { ParsedLogEntry, Alert } from '../types';
import { generateId } from '../utils/helpers';

interface DetectionConfig {
  bruteforceThreshold: number;      // Number of failures before alert
  bruteforceWindowMinutes: number;  // Time window for bruteforce detection
  sprayUsersThreshold: number;      // Number of unique users for spray detection
  sprayWindowMinutes: number;       // Time window for spray detection
  successAfterFailuresThreshold: number; // Failures before success
  successAfterWindowMinutes: number;     // Time window for success-after-failures
}

const DEFAULT_CONFIG: DetectionConfig = {
  bruteforceThreshold: 10,
  bruteforceWindowMinutes: 5,
  sprayUsersThreshold: 10,
  sprayWindowMinutes: 10,
  successAfterFailuresThreshold: 3,
  successAfterWindowMinutes: 10,
};

/**
 * Run all detection rules on parsed log entries
 */
export function runDetections(
  entries: ParsedLogEntry[],
  config: Partial<DetectionConfig> = {}
): Alert[] {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const alerts: Alert[] = [];

  // Sort entries by timestamp
  const sorted = [...entries]
    .filter(e => e.timestamp)
    .sort((a, b) => {
      const ta = new Date(a.timestamp!).getTime();
      const tb = new Date(b.timestamp!).getTime();
      return ta - tb;
    });

  // Run each detection
  alerts.push(...detectBruteforce(sorted, cfg));
  alerts.push(...detectPasswordSpray(sorted, cfg));
  alerts.push(...detectSuccessAfterFailures(sorted, cfg));
  alerts.push(...detectSuspiciousActivity(sorted));

  return alerts;
}

/**
 * Detect brute force attacks
 * Many failures from same IP to same user within time window
 */
function detectBruteforce(entries: ParsedLogEntry[], cfg: DetectionConfig): Alert[] {
  const alerts: Alert[] = [];
  const windowMs = cfg.bruteforceWindowMinutes * 60 * 1000;

  // Filter to auth failures
  const failures = entries.filter(
    e => e.outcome === 'failure' && 
         e.source.ip && 
         e.user?.name &&
         (e.tags.includes('auth') || e.tags.includes('ssh') || e.logType === 'ssh_auth')
  );

  // Group by (IP, user)
  const groups = new Map<string, ParsedLogEntry[]>();
  for (const entry of failures) {
    const key = `${entry.source.ip}|${entry.user?.name}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(entry);
  }

  // Check each group for brute force pattern
  for (const [key, group] of groups) {
    if (group.length < cfg.bruteforceThreshold) continue;

    const [ip, user] = key.split('|');
    
    // Sliding window check
    for (let i = 0; i <= group.length - cfg.bruteforceThreshold; i++) {
      const windowStart = new Date(group[i].timestamp!).getTime();
      let count = 1;
      let windowEnd = windowStart;

      for (let j = i + 1; j < group.length; j++) {
        const time = new Date(group[j].timestamp!).getTime();
        if (time - windowStart <= windowMs) {
          count++;
          windowEnd = time;
        } else {
          break;
        }
      }

      if (count >= cfg.bruteforceThreshold) {
        alerts.push({
          id: generateId(),
          type: 'bruteforce',
          severity: 'high',
          confidence: 'high',
          title: `Brute Force Attack Detected`,
          description: `${count} failed login attempts from ${ip} to user "${user}" within ${cfg.bruteforceWindowMinutes} minutes`,
          timestamp: new Date().toISOString(),
          sourceIps: [ip],
          targetUsers: [user],
          relatedEvents: group.slice(i, i + count).map(e => e.id),
          metadata: {
            count,
            windowStart: new Date(windowStart).toISOString(),
            windowEnd: new Date(windowEnd).toISOString(),
          },
        });
        break; // One alert per (IP, user) pair
      }
    }
  }

  return alerts;
}

/**
 * Detect password spray attacks
 * Same IP targeting many unique users within time window
 */
function detectPasswordSpray(entries: ParsedLogEntry[], cfg: DetectionConfig): Alert[] {
  const alerts: Alert[] = [];
  const windowMs = cfg.sprayWindowMinutes * 60 * 1000;

  // Filter to auth failures
  const failures = entries.filter(
    e => e.outcome === 'failure' && 
         e.source.ip && 
         e.user?.name &&
         (e.tags.includes('auth') || e.tags.includes('ssh') || e.logType === 'ssh_auth')
  );

  // Group by IP
  const byIp = new Map<string, ParsedLogEntry[]>();
  for (const entry of failures) {
    const ip = entry.source.ip!;
    if (!byIp.has(ip)) byIp.set(ip, []);
    byIp.get(ip)!.push(entry);
  }

  // Check each IP for spray pattern
  for (const [ip, group] of byIp) {
    // Sliding window to find unique users
    for (let i = 0; i < group.length; i++) {
      const windowStart = new Date(group[i].timestamp!).getTime();
      const usersInWindow = new Set<string>();
      let windowEnd = windowStart;

      for (let j = i; j < group.length; j++) {
        const time = new Date(group[j].timestamp!).getTime();
        if (time - windowStart <= windowMs) {
          usersInWindow.add(group[j].user!.name!);
          windowEnd = time;
        } else {
          break;
        }
      }

      if (usersInWindow.size >= cfg.sprayUsersThreshold) {
        alerts.push({
          id: generateId(),
          type: 'password_spray',
          severity: 'high',
          confidence: 'high',
          title: `Password Spray Attack Detected`,
          description: `${ip} targeted ${usersInWindow.size} unique users within ${cfg.sprayWindowMinutes} minutes`,
          timestamp: new Date().toISOString(),
          sourceIps: [ip],
          targetUsers: Array.from(usersInWindow),
          relatedEvents: group.filter(e => usersInWindow.has(e.user!.name!)).map(e => e.id),
          metadata: {
            uniqueUsers: usersInWindow.size,
            windowStart: new Date(windowStart).toISOString(),
            windowEnd: new Date(windowEnd).toISOString(),
          },
        });
        break; // One alert per IP
      }
    }
  }

  return alerts;
}

/**
 * Detect successful login after multiple failures
 * Potential credential compromise
 */
function detectSuccessAfterFailures(entries: ParsedLogEntry[], cfg: DetectionConfig): Alert[] {
  const alerts: Alert[] = [];
  const windowMs = cfg.successAfterWindowMinutes * 60 * 1000;

  // Get auth events
  const authEvents = entries.filter(
    e => e.user?.name && 
         (e.tags.includes('auth') || e.tags.includes('ssh') || e.logType === 'ssh_auth')
  );

  // Group by user
  const byUser = new Map<string, ParsedLogEntry[]>();
  for (const entry of authEvents) {
    const user = entry.user!.name!;
    if (!byUser.has(user)) byUser.set(user, []);
    byUser.get(user)!.push(entry);
  }

  // Check for success-after-failures pattern
  for (const [user, group] of byUser) {
    const successes = group.filter(e => e.outcome === 'success');
    const failures = group.filter(e => e.outcome === 'failure');

    for (const success of successes) {
      const successTime = new Date(success.timestamp!).getTime();
      
      // Count failures in window before success
      const recentFailures = failures.filter(f => {
        const failTime = new Date(f.timestamp!).getTime();
        return failTime < successTime && successTime - failTime <= windowMs;
      });

      if (recentFailures.length >= cfg.successAfterFailuresThreshold) {
        const sourceIps = [...new Set(recentFailures.map(f => f.source.ip).filter(Boolean))] as string[];
        
        alerts.push({
          id: generateId(),
          type: 'suspicious_activity',
          severity: 'medium',
          confidence: 'medium',
          title: `Successful Login After Multiple Failures`,
          description: `User "${user}" logged in successfully after ${recentFailures.length} failed attempts within ${cfg.successAfterWindowMinutes} minutes`,
          timestamp: new Date().toISOString(),
          sourceIps,
          targetUsers: [user],
          relatedEvents: [...recentFailures.map(e => e.id), success.id],
          metadata: {
            failureCount: recentFailures.length,
            successTime: success.timestamp,
          },
        });
      }
    }
  }

  return alerts;
}

/**
 * Detect other suspicious activities
 */
function detectSuspiciousActivity(entries: ParsedLogEntry[]): Alert[] {
  const alerts: Alert[] = [];

  // Detect privilege escalation (sudo/su)
  const privEsc = entries.filter(
    e => e.tags.includes('privilege_escalation') || 
         e.action === 'sudo' || 
         e.action === 'su'
  );

  // Group by user
  const sudoByUser = new Map<string, number>();
  for (const entry of privEsc) {
    const user = entry.user?.name || 'unknown';
    sudoByUser.set(user, (sudoByUser.get(user) || 0) + 1);
  }

  // Alert if excessive sudo/su usage
  for (const [user, count] of sudoByUser) {
    if (count > 20) { // Threshold for excessive privilege escalation
      alerts.push({
        id: generateId(),
        type: 'privilege_escalation',
        severity: 'medium',
        confidence: 'low',
        title: `Excessive Privilege Escalation`,
        description: `User "${user}" performed ${count} privilege escalation operations`,
        timestamp: new Date().toISOString(),
        sourceIps: [],
        targetUsers: [user],
        relatedEvents: privEsc.filter(e => e.user?.name === user).map(e => e.id).slice(0, 10),
        metadata: { count },
      });
    }
  }

  // Detect firewall blocks from same IP
  const firewallBlocks = entries.filter(
    e => e.tags.includes('firewall') && 
         (e.action === 'drop' || e.action === 'block' || e.action === 'deny') &&
         e.source.ip
  );

  const blocksByIp = new Map<string, number>();
  for (const entry of firewallBlocks) {
    const ip = entry.source.ip!;
    blocksByIp.set(ip, (blocksByIp.get(ip) || 0) + 1);
  }

  // Alert for IPs with many blocks
  for (const [ip, count] of blocksByIp) {
    if (count > 50) {
      alerts.push({
        id: generateId(),
        type: 'anomaly',
        severity: 'low',
        confidence: 'medium',
        title: `High Volume Firewall Blocks`,
        description: `${count} firewall blocks from IP ${ip}`,
        timestamp: new Date().toISOString(),
        sourceIps: [ip],
        targetUsers: [],
        relatedEvents: firewallBlocks.filter(e => e.source.ip === ip).map(e => e.id).slice(0, 10),
        metadata: { count },
      });
    }
  }

  return alerts;
}

/**
 * Generate statistics from parsed entries
 */
export function generateStats(entries: ParsedLogEntry[]) {
  const byType: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  const byOutcome: Record<string, number> = {};
  const sourceCount: Record<string, number> = {};
  const userCount: Record<string, number> = {};
  const timelineMap: Record<string, number> = {};

  for (const entry of entries) {
    // By type
    byType[entry.logType] = (byType[entry.logType] || 0) + 1;
    
    // By severity
    bySeverity[entry.severity] = (bySeverity[entry.severity] || 0) + 1;
    
    // By outcome
    if (entry.outcome) {
      byOutcome[entry.outcome] = (byOutcome[entry.outcome] || 0) + 1;
    }
    
    // Source IPs
    if (entry.source.ip) {
      sourceCount[entry.source.ip] = (sourceCount[entry.source.ip] || 0) + 1;
    }
    
    // Users
    if (entry.user?.name) {
      userCount[entry.user.name] = (userCount[entry.user.name] || 0) + 1;
    }
    
    // Timeline (group by minute)
    if (entry.timestamp) {
      const minute = entry.timestamp.substring(0, 16); // YYYY-MM-DDTHH:MM
      timelineMap[minute] = (timelineMap[minute] || 0) + 1;
    }
  }

  // Convert to sorted arrays
  const topSources = Object.entries(sourceCount)
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  const topUsers = Object.entries(userCount)
    .map(([user, count]) => ({ user, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  const timeline = Object.entries(timelineMap)
    .map(([time, count]) => ({ time, count }))
    .sort((a, b) => a.time.localeCompare(b.time));

  return {
    byType,
    bySeverity,
    byOutcome,
    topSources,
    topUsers,
    timeline,
  };
}
