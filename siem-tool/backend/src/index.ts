// SIEM Backend API - Cloudflare Workers with Hono
// Main entry point for the log parsing and analysis API

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { autoParse, detectLogType, allParsers, analyzeLogStructureAndSuggestLabels } from './parsers';
import { runDetections, generateStats } from './detectors/alerts';
import { correlateMultipleLogs, CorrelationResult, detectAttacksInEntries, enrichEntriesWithAttacks } from './ml';
import type { ParseResponse, LogType, ParsedLogEntry } from './types';

// Types for Cloudflare Workers
type Bindings = {
  // Add any bindings here (KV, D1, etc.)
};

const app = new Hono<{ Bindings: Bindings }>();

// Enable CORS for frontend with specific origins
app.use('*', cors({
  origin: 'https://freekhana-frontend.pages.dev',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With'],
  exposeHeaders: ['Content-Length', 'X-Custom-Header'],
  maxAge: 86400,
  credentials: false,
}));

// Handle preflight OPTIONS requests explicitly
app.options('*', (c) => {
  return c.text('', 200, {
    'Access-Control-Allow-Origin': 'https://freekhana-frontend.pages.dev',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, Accept, Origin, X-Requested-With',
    'Access-Control-Max-Age': '86400',
  });
});

// Health check
app.get('/', (c) => {
  return c.json({
    status: 'ok',
    name: 'FreeKhana SIEM API',
    version: '2.0.0',
    features: [
      'Multi-log parsing (56+ log types)',
      'ML-based anomaly detection',
      'Cross-log correlation',
      'Attack chain detection',
      'False positive filtering',
      'MITRE ATT&CK mapping',
    ],
    endpoints: [
      'GET / - Health check',
      'GET /parsers - List available parsers',
      'POST /parse - Parse single log file',
      'POST /correlate - Multi-log correlation with ML',
      'POST /detect - Detect log type only',
      'POST /stream - Stream parsing (line by line)',
      'POST /analyze - Dynamic field detection and labeling',
    ],
  });
});

// List available parsers
app.get('/parsers', (c) => {
  const parsers = allParsers.map(p => ({
    name: p.name,
    logType: p.logType,
  }));
  
  // Group by category
  const categories = {
    database: parsers.filter(p => ['mysql_error', 'mysql_query', 'mysql_slow', 'postgres_error', 'postgres_auth', 'postgres_statement', 'oracle_alert', 'oracle_listener', 'oracle_audit', 'sqlserver_error', 'sqlserver_audit', 'sqlserver_transaction', 'mongodb_server', 'mongodb_audit'].includes(p.logType)),
    webserver: parsers.filter(p => ['apache', 'nginx', 'iis', 'django', 'flask', 'laravel', 'rails', 'express', 'fastapi', 'gunicorn', 'uvicorn'].includes(p.logType)),
    system: parsers.filter(p => ['syslog', 'systemd', 'kernel', 'audit', 'package', 'cron', 'daemon'].includes(p.logType)),
    auth: parsers.filter(p => ['ssh_auth', 'pam', 'vsftpd', 'proftpd'].includes(p.logType)),
    firewall: parsers.filter(p => ['iptables', 'ufw', 'nftables', 'firewalld', 'windows_firewall', 'palo_alto', 'fortigate', 'cisco_asa', 'checkpoint', 'aws_vpc_flow', 'azure_nsg', 'gcp_vpc'].includes(p.logType)),
    mail: parsers.filter(p => ['postfix', 'sendmail', 'exim', 'dovecot', 'exchange'].includes(p.logType)),
  };

  return c.json({
    total: parsers.length,
    categories,
    all: parsers,
  });
});

// Detect log type without full parsing
app.post('/detect', async (c) => {
  try {
    const body = await c.req.text();
    
    if (!body || body.trim().length === 0) {
      return c.json({ error: 'No log content provided' }, 400);
    }

    const lines = body.split('\n').filter(l => l.trim());
    const detectedType = detectLogType(body);

    return c.json({
      detectedType,
      sampleSize: Math.min(lines.length, 50),
      totalLines: lines.length,
    });
  } catch (error) {
    return c.json({ error: 'Failed to detect log type', details: String(error) }, 500);
  }
});

// Main parse endpoint (single file)
app.post('/parse', async (c) => {
  try {
    const contentType = c.req.header('Content-Type') || '';
    let content: string;
    let forceType: LogType | undefined;

    // Handle different content types
    if (contentType.includes('multipart/form-data')) {
      const formData = await c.req.formData();
      const file = formData.get('file') as File | null;
      const type = formData.get('type') as string | null;
      
      if (!file) {
        return c.json({ error: 'No file provided' }, 400);
      }
      
      content = await file.text();
      if (type && type !== 'auto') {
        forceType = type as LogType;
      }
    } else if (contentType.includes('application/json')) {
      const json = await c.req.json();
      content = json.content || json.logs || '';
      forceType = json.type;
    } else {
      content = await c.req.text();
    }

    if (!content || content.trim().length === 0) {
      return c.json({ error: 'No log content provided' }, 400);
    }

    // Parse logs
    const { detectedType, entries, stats: parseStats } = autoParse(content);
    
    // Use forced type if provided
    const finalType = forceType || detectedType;

    // Run detections
    const alerts = runDetections(entries);
    
    // Run ML-based per-entry attack detection
    const enrichedEntries = enrichEntriesWithAttacks(entries);
    const detectedAttacks = detectAttacksInEntries(enrichedEntries);
    
    // Generate attack summary
    const attackTypes = [...new Set(detectedAttacks.map(a => a.attack.attackType))];
    const attackSummary = {
      totalAttacks: detectedAttacks.length,
      attackTypes,
      uniqueSources: new Set(entries.map(e => e.source.ip).filter(Boolean)).size,
      riskScore: Math.min(detectedAttacks.length * 10, 100),
    };
    
    // Generate statistics
    const stats = generateStats(entries);

    const response: ParseResponse = {
      success: true,
      detectedType: finalType,
      totalLines: parseStats.totalLines,
      parsedLines: parseStats.parsedLines,
      failedLines: parseStats.failedLines,
      entries: enrichedEntries,
      alerts,
      stats,
      mlAttacks: detectedAttacks,
      attackSummary,
    };

    return c.json(response);
  } catch (error) {
    console.error('Parse error:', error);
    return c.json({ 
      success: false,
      error: 'Failed to parse logs', 
      details: String(error) 
    }, 500);
  }
});

// Multi-log correlation endpoint with ML-based detection
app.post('/correlate', async (c) => {
  try {
    const contentType = c.req.header('Content-Type') || '';
    
    interface LogSource {
      name: string;
      entries: ParsedLogEntry[];
    }
    
    const logSources: LogSource[] = [];

    if (contentType.includes('multipart/form-data')) {
      // Handle multiple file uploads
      const formData = await c.req.formData();
      const files: File[] = [];
      
      // Try multiple files field
      const multipleFiles = formData.getAll('files');
      for (const f of multipleFiles) {
        if (typeof f !== 'string' && 'text' in f) {
          files.push(f as File);
        }
      }
      
      // Try single file field
      if (files.length === 0) {
        const singleFile = formData.get('file');
        if (singleFile && typeof singleFile !== 'string' && 'text' in singleFile) {
          files.push(singleFile as File);
        }
      }
      
      if (files.length === 0) {
        return c.json({ error: 'No files provided' }, 400);
      }

      // Parse each file
      for (const file of files) {
        const content = await file.text();
        if (!content.trim()) continue;
        
        const { entries } = autoParse(content);
        logSources.push({
          name: file.name || `file_${logSources.length + 1}`,
          entries,
        });
      }
    } else if (contentType.includes('application/json')) {
      // Handle JSON payload with multiple log sources
      const json = await c.req.json();
      
      if (Array.isArray(json.logs)) {
        // Array of log sources: [{ name: "auth", content: "..." }, ...]
        for (const source of json.logs) {
          if (!source.content) continue;
          
          const { entries } = autoParse(source.content);
          logSources.push({
            name: source.name || `source_${logSources.length + 1}`,
            entries,
          });
        }
      } else if (json.content) {
        // Single content with optional name
        const { entries } = autoParse(json.content);
        logSources.push({
          name: json.name || 'logs',
          entries,
        });
      }
    } else {
      // Plain text - treat as single source
      const content = await c.req.text();
      if (!content.trim()) {
        return c.json({ error: 'No log content provided' }, 400);
      }
      
      const { entries } = autoParse(content);
      logSources.push({
        name: 'logs',
        entries,
      });
    }

    if (logSources.length === 0 || logSources.every(s => s.entries.length === 0)) {
      return c.json({ error: 'No valid log entries found in provided sources' }, 400);
    }

    // Run ML-based correlation
    const correlationResult: CorrelationResult = correlateMultipleLogs(logSources);

    // Also run traditional detections for comparison
    const allEntries = logSources.flatMap(s => s.entries);
    const traditionalAlerts = runDetections(allEntries);
    const stats = generateStats(allEntries);

    return c.json({
      success: true,
      sources: logSources.map(s => ({ name: s.name, entryCount: s.entries.length })),
      correlation: correlationResult,
      traditionalAlerts, // For comparison/fallback
      stats,
    });
  } catch (error) {
    console.error('Correlation error:', error);
    return c.json({ 
      success: false,
      error: 'Failed to correlate logs', 
      details: String(error) 
    }, 500);
  }
});

// Stream parsing - parse a single line or batch of lines
app.post('/stream', async (c) => {
  try {
    const json = await c.req.json();
    const lines: string[] = Array.isArray(json.lines) ? json.lines : [json.line || json.content];
    
    if (lines.length === 0 || !lines[0]) {
      return c.json({ error: 'No lines provided' }, 400);
    }

    const content = lines.join('\n');
    const { detectedType, entries, stats } = autoParse(content);
    
    // Run detections on the batch
    const alerts = runDetections(entries);

    return c.json({
      success: true,
      detectedType,
      entries,
      alerts,
      stats: {
        totalLines: stats.totalLines,
        parsedLines: stats.parsedLines,
        failedLines: stats.failedLines,
      },
    });
  } catch (error) {
    return c.json({ 
      success: false,
      error: 'Failed to parse stream', 
      details: String(error) 
    }, 500);
  }
});

// Attack types reference endpoint
app.get('/attacks', (c) => {
  return c.json({
    attackTypes: [
      { type: 'bruteforce', description: 'Multiple failed login attempts to same account' },
      { type: 'password_spray', description: 'Same password tried against multiple accounts' },
      { type: 'credential_stuffing', description: 'Automated login attempts with stolen credentials' },
      { type: 'mfa_bypass', description: 'Attempts to circumvent multi-factor authentication' },
      { type: 'mfa_fatigue', description: 'Repeated MFA push notifications to exhaust user' },
      { type: 'session_hijacking', description: 'Unauthorized use of valid session tokens' },
      { type: 'privilege_escalation', description: 'Attempts to gain elevated access' },
      { type: 'lateral_movement', description: 'Movement between systems in network' },
      { type: 'data_exfiltration', description: 'Unauthorized data transfer out of network' },
      { type: 'sql_injection', description: 'SQL commands injected into application' },
      { type: 'xss_attack', description: 'Cross-site scripting attack' },
      { type: 'path_traversal', description: 'Directory traversal to access restricted files' },
      { type: 'command_injection', description: 'OS commands injected into application' },
      { type: 'port_scan', description: 'Network reconnaissance scanning ports' },
      { type: 'ddos', description: 'Distributed denial of service attack' },
      { type: 'reconnaissance', description: 'Information gathering activity' },
      { type: 'malware_activity', description: 'Potential malware execution detected' },
      { type: 'c2_communication', description: 'Command and control server communication' },
      { type: 'insider_threat', description: 'Suspicious activity from authorized user' },
      { type: 'account_takeover', description: 'Unauthorized account access' },
    ],
    mitreTactics: [
      'TA0001 - Initial Access',
      'TA0002 - Execution',
      'TA0003 - Persistence',
      'TA0004 - Privilege Escalation',
      'TA0005 - Defense Evasion',
      'TA0006 - Credential Access',
      'TA0007 - Discovery',
      'TA0008 - Lateral Movement',
      'TA0009 - Collection',
      'TA0010 - Exfiltration',
      'TA0011 - Command and Control',
      'TA0040 - Impact',
      'TA0043 - Reconnaissance',
    ],
  });
});

// Dynamic log analysis endpoint - analyze unknown logs and suggest field labels
app.post('/analyze', async (c) => {
  try {
    const contentType = c.req.header('Content-Type') || '';
    let content: string;

    if (contentType.includes('multipart/form-data')) {
      const formData = await c.req.formData();
      const file = formData.get('file') as File | null;

      if (!file) {
        return c.json({ error: 'No file provided' }, 400);
      }

      content = await file.text();
    } else if (contentType.includes('application/json')) {
      const json = await c.req.json();
      content = json.content || json.logs || '';
    } else {
      content = await c.req.text();
    }

    if (!content || content.trim().length === 0) {
      return c.json({ error: 'No log content provided' }, 400);
    }

    const lines = content.split('\n').filter(l => l.trim());
    if (lines.length === 0) {
      return c.json({ error: 'No valid log lines found' }, 400);
    }

    // Analyze log structure and suggest labels
    const analysis = analyzeLogStructureAndSuggestLabels(lines);

    // Detect log type using existing parsers
    const detectedType = detectLogType(content);

    return c.json({
      success: true,
      detectedType,
      totalLines: lines.length,
      structure: {
        separator: analysis.structure.separator,
        columns: analysis.structure.columns,
        hasTimestamp: analysis.structure.hasTimestamp,
        timestampIndex: analysis.structure.timestampIndex,
        hasKeyPairs: analysis.structure.hasKeyPairs,
      },
      detectedFields: analysis.detectedFields,
      suggestedLabels: analysis.suggestedLabels,
      sampleFields: analysis.sampleFields.slice(0, 5),
      summary: {
        fieldCount: analysis.detectedFields.length,
        confidenceScore: analysis.suggestedLabels.reduce((sum: number, l: any) => sum + l.confidence, 0) / analysis.suggestedLabels.length,
        isStructured: analysis.structure.separator !== 'unknown' || analysis.structure.hasKeyPairs,
      },
    });
  } catch (error) {
    console.error('Analysis error:', error);
    return c.json({
      success: false,
      error: 'Failed to analyze logs',
      details: String(error)
    }, 500);
  }
});

// Submit feedback for a log entry
app.post('/feedback', async (c) => {
  try {
    const json = await c.req.json();

    if (!json.entry_id || !json.user_label) {
      return c.json({ error: 'Missing required fields: entry_id, user_label' }, 400);
    }

    if (!['safe', 'unsafe', 'attack_pattern'].includes(json.user_label)) {
      return c.json({ error: 'user_label must be "safe", "unsafe", or "attack_pattern"' }, 400);
    }

    // In a real implementation, this would store to a database
    // For now, we just acknowledge the feedback
    const feedbackId = `${json.entry_id}_${Date.now()}`;

    console.log(`Feedback received: ${json.user_label} - Entry ${json.entry_id}`);

    return c.json({
      success: true,
      message: `Feedback submitted: Entry ${json.entry_id} marked as ${json.user_label}`,
      feedback_id: feedbackId
    });
  } catch (error) {
    console.error('Feedback error:', error);
    return c.json({
      success: false,
      error: 'Failed to submit feedback',
      details: String(error)
    }, 500);
  }
});

// Submit bulk feedback for multiple entries
app.post('/feedback/bulk', async (c) => {
  try {
    const json = await c.req.json();

    if (!json.entries || !Array.isArray(json.entries)) {
      return c.json({ error: 'Missing or invalid entries array' }, 400);
    }

    const { entries, user_label, attack_type } = json;

    if (!['safe', 'unsafe', 'attack_pattern'].includes(user_label)) {
      return c.json({ error: 'user_label must be "safe", "unsafe", or "attack_pattern"' }, 400);
    }

    if (user_label === 'attack_pattern' && !attack_type) {
      return c.json({ error: 'attack_type is required when user_label is "attack_pattern"' }, 400);
    }

    const results: { id: string; success: boolean }[] = [];

    for (const entry of entries) {
      const feedbackId = `${entry.entry_id}_${Date.now()}_${Math.random().toString(36).slice(2)}`;

      results.push({
        id: entry.entry_id,
        success: true
      });

      console.log(`Bulk feedback: ${user_label} - Entry ${entry.entry_id} - Attack type: ${attack_type || 'N/A'}`);
    }

    return c.json({
      success: true,
      message: `Bulk feedback submitted for ${results.length} entries`,
      results
    });
  } catch (error) {
    console.error('Bulk feedback error:', error);
    return c.json({
      success: false,
      error: 'Failed to submit bulk feedback',
      details: String(error)
    }, 500);
  }
});

// Get available attack types for manual classification
app.get('/feedback/attack-types', (c) => {
  return c.json({
    attackTypes: [
      { type: 'sql_injection', label: 'SQL Injection', description: 'SQL commands injected into application queries' },
      { type: 'xss_attack', label: 'Cross-Site Scripting (XSS)', description: 'Malicious scripts injected into web pages' },
      { type: 'command_injection', label: 'Command Injection', description: 'OS commands injected through application input' },
      { type: 'path_traversal', label: 'Path Traversal', description: 'Directory traversal to access restricted files' },
      { type: 'file_inclusion', label: 'File Inclusion', description: 'Remote/local file inclusion attacks' },
      { type: 'bruteforce', label: 'Brute Force', description: 'Multiple failed login attempts to same account' },
      { type: 'password_spray', label: 'Password Spray', description: 'Same password tried against multiple accounts' },
      { type: 'credential_stuffing', label: 'Credential Stuffing', description: 'Automated login with stolen credentials' },
      { type: 'port_scan', label: 'Port Scan', description: 'Network reconnaissance scanning ports' },
      { type: 'ddos', label: 'DDoS', description: 'Distributed denial of service attack' },
      { type: 'reconnaissance', label: 'Reconnaissance', description: 'Information gathering activity' },
      { type: 'privilege_escalation', label: 'Privilege Escalation', description: 'Attempts to gain elevated access' },
      { type: 'lateral_movement', label: 'Lateral Movement', description: 'Movement between systems in network' },
      { type: 'data_exfiltration', label: 'Data Exfiltration', description: 'Unauthorized data transfer out of network' },
      { type: 'c2_communication', label: 'C2 Communication', description: 'Command and control server communication' },
      { type: 'malware_activity', label: 'Malware Activity', description: 'Potential malware execution detected' },
      { type: 'insider_threat', label: 'Insider Threat', description: 'Suspicious activity from authorized user' },
      { type: 'account_takeover', label: 'Account Takeover', description: 'Unauthorized account access' },
      { type: 'mfa_bypass', label: 'MFA Bypass', description: 'Attempts to circumvent multi-factor authentication' },
      { type: 'session_hijacking', label: 'Session Hijacking', description: 'Unauthorized use of valid session tokens' },
    ]
  });
});

// Get feedback statistics
app.get('/feedback/stats', (c) => {
  // In a real implementation, this would query a database
  return c.json({
    success: true,
    stats: {
      total_feedback: 0,
      safe_count: 0,
      unsafe_count: 0,
      attack_pattern_count: 0,
      by_attack_type: {}
    }
  });
});

// Export for Cloudflare Workers
export default app;
