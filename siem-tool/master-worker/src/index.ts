// SIEM Master Worker - Load Balancer with Auto-Recovery
// Routes requests to workers and auto-redeploys unhealthy workers

import { Hono } from 'hono';
import { cors } from 'hono/cors';

type Bindings = {
  // For auto-deployment via Cloudflare API
  CF_API_TOKEN?: string;
  CF_ACCOUNT_ID?: string;
};

const app = new Hono<{ Bindings: Bindings }>();

// ============================================
// WORKER CONFIGURATION - ADD MORE WORKERS HERE
// ============================================
interface WorkerConfig {
  name: string;
  url: string;
  healthy: boolean;
  requests: number;
  lastHealthCheck: number;
  failedAttempts: number;
}

const WORKERS: WorkerConfig[] = [
  { name: 'siem-worker-1', url: 'siem-worker-1.tanubhavj.workers.dev', healthy: true, requests: 0, lastHealthCheck: 0, failedAttempts: 0 },
  { name: 'siem-worker-2', url: 'siem-worker-2.tanubhavj.workers.dev', healthy: true, requests: 0, lastHealthCheck: 0, failedAttempts: 0 },
  { name: 'siem-worker-3', url: 'siem-worker-3.tanubhavj.workers.dev', healthy: true, requests: 0, lastHealthCheck: 0, failedAttempts: 0 },
  { name: 'siem-worker-4', url: 'siem-worker-4.tanubhavj.workers.dev', healthy: true, requests: 0, lastHealthCheck: 0, failedAttempts: 0 },
  { name: 'siem-worker-5', url: 'siem-worker-5.tanubhavj.workers.dev', healthy: true, requests: 0, lastHealthCheck: 0, failedAttempts: 0 },
  { name: 'siem-worker-6', url: 'siem-worker-6.tanubhavj.workers.dev', healthy: true, requests: 0, lastHealthCheck: 0, failedAttempts: 0 },
  { name: 'siem-worker-7', url: 'siem-worker-7.tanubhavj.workers.dev', healthy: true, requests: 0, lastHealthCheck: 0, failedAttempts: 0 },
  { name: 'siem-worker-8', url: 'siem-worker-8.tanubhavj.workers.dev', healthy: true, requests: 0, lastHealthCheck: 0, failedAttempts: 0 },
  { name: 'siem-worker-9', url: 'siem-worker-9.tanubhavj.workers.dev', healthy: true, requests: 0, lastHealthCheck: 0, failedAttempts: 0 },
  { name: 'siem-worker-10', url: 'siem-worker-10.tanubhavj.workers.dev', healthy: true, requests: 0, lastHealthCheck: 0, failedAttempts: 0 },

];

const MAX_FAILED_ATTEMPTS = 3;
const HEALTH_CHECK_INTERVAL = 30000; // 30 seconds
const REQUEST_TIMEOUT = 30000; // 30 seconds timeout for worker requests
const MAX_RETRIES = 2; // Maximum retries for failed chunks

function getHealthyWorkers(): WorkerConfig[] {
  return WORKERS.filter(w => w.healthy);
}

function getLeastLoadedWorker(): WorkerConfig | null {
  const healthy = getHealthyWorkers();
  if (healthy.length === 0) return null;
  return healthy.reduce((min, w) => w.requests < min.requests ? w : min);
}

function incrementRequests(workerName: string) {
  const worker = WORKERS.find(w => w.name === workerName);
  if (worker) worker.requests++;
}

function decrementRequests(workerName: string) {
  const worker = WORKERS.find(w => w.name === workerName);
  if (worker && worker.requests > 0) worker.requests--;
}

function markWorkerUnhealthy(workerName: string) {
  const worker = WORKERS.find(w => w.name === workerName);
  if (worker) {
    worker.healthy = false;
    worker.failedAttempts++;
  }
}

function markWorkerHealthy(workerName: string) {
  const worker = WORKERS.find(w => w.name === workerName);
  if (worker) {
    worker.healthy = true;
    worker.failedAttempts = 0;
    worker.lastHealthCheck = Date.now();
  }
}

function resetRequestCounts() {
  WORKERS.forEach(w => w.requests = 0);
}

// ============================================
// WORKER AUTO-REDEPLOYMENT
// ============================================

async function redeployWorker(workerName: string): Promise<boolean> {
  const env = process.env;
  const apiToken = env.CF_API_TOKEN || '';
  const accountId = env.CF_ACCOUNT_ID || '';
  
  if (!apiToken || !accountId) {
    console.log(`Cannot redeploy ${workerName}: CF_API_TOKEN or CF_ACCOUNT_ID not configured`);
    return false;
  }
  
  try {
    console.log(`Attempting to redeploy ${workerName}...`);
    
    // Trigger deployment via Cloudflare API
    const response = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${workerName}/deployments`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          // Triggers a new deployment from the current deployed version
          force: true
        })
      }
    );
    
    if (response.ok) {
      console.log(`Successfully triggered redeployment for ${workerName}`);
      return true;
    } else {
      const error = await response.text();
      console.log(`Failed to redeploy ${workerName}: ${error}`);
      return false;
    }
  } catch (error) {
    console.log(`Error redeploying ${workerName}: ${String(error)}`);
    return false;
  }
}

// Quick health check - runs on every request to ensure fresh worker status
async function checkAndRecoverWorkers(quickCheck = true) {
  const now = Date.now();
  const unhealthyWorkers: WorkerConfig[] = [];
  
  for (const worker of WORKERS) {
    // For quick checks, only check workers that haven't been checked recently (5s)
    // For full checks, use the longer interval (30s)
    const minInterval = quickCheck ? 5000 : HEALTH_CHECK_INTERVAL;
    
    if (now - worker.lastHealthCheck < minInterval) {
      continue;
    }
    
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout for quick health checks
      
      const response = await fetch(`https://${worker.url}/`, {
        method: 'GET',
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      if (response.ok) {
        if (!worker.healthy) {
          markWorkerHealthy(worker.name);
          console.log(`Worker ${worker.name}: recovered and healthy`);
        }
      } else {
        if (worker.healthy) {
          console.log(`Worker ${worker.name}: health check returned ${response.status}`);
        }
        unhealthyWorkers.push(worker);
      }
    } catch (error) {
      if (worker.healthy) {
        console.log(`Worker ${worker.name}: health check failed - ${String(error)}`);
      }
      unhealthyWorkers.push(worker);
    }
    
    worker.lastHealthCheck = now;
  }
  
  // Attempt to recover unhealthy workers
  for (const worker of unhealthyWorkers) {
    worker.failedAttempts++;
    console.log(`Worker ${worker.name}: unhealthy (${worker.failedAttempts}/${MAX_FAILED_ATTEMPTS} failed attempts)`);
    
    if (worker.failedAttempts >= MAX_FAILED_ATTEMPTS) {
      console.log(`Attempting to redeploy ${worker.name}...`);
      const redeployed = await redeployWorker(worker.name);
      
      if (redeployed) {
        // Reset failed attempts, health will be updated on next check
        worker.failedAttempts = 0;
        worker.lastHealthCheck = now - 25000; // Check again in 5 seconds
      }
    } else {
      // Mark as unhealthy so we don't route to it
      markWorkerUnhealthy(worker.name);
    }
  }
}

// Trigger health check on every request - runs in background
// This ensures we always know which workers are healthy before routing
async function triggerHealthCheck(c: any, quickCheck = true) {
  // Run health check in background without blocking response
  // quickCheck=true: only check workers not checked in last 5s (for request routing)
  // quickCheck=false: full health check (for /health endpoint)
  c.executionCtx.waitUntil(checkAndRecoverWorkers(quickCheck));
}

// Reset request counts every minute
function scheduleRequestReset(c: any) {
  c.executionCtx.waitUntil(
    (async () => {
      while (true) {
        await new Promise(resolve => setTimeout(resolve, 60000));
        resetRequestCounts();
      }
    })()
  );
}

// ============================================
// FILE DISTRIBUTION FUNCTIONS
// ============================================

interface FileChunk {
  workerIndex: number;
  content: string;
  startLine: number;
  endLine: number;
  size: number;
}

/**
 * Check if a line is the start of a new log entry
 * Different log types have different patterns for new entries
 */
function isNewLogEntry(line: string): boolean {
  if (!line || line.trim() === '') return false;
  
  // Common patterns that indicate start of a new log entry:
  
  // 1. Timestamp patterns (most common)
  // ISO format: 2024-01-15T10:30:00Z or 2024-01-15 10:30:00
  if (/^\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}/.test(line)) return true;
  
  // Unix timestamp: 1705315800 or 1705315800.123
  if (/^\d{10,13}(\.\d+)?\s/.test(line)) return true;
  
  // 2. Syslog format: Jan 15 10:30:00
  if (/^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/.test(line)) return true;
  
  // 3. Log level indicators at start
  if (/^(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL|TRACE)\s*[\[:\-]/i.test(line)) return true;
  
  // 4. Bracketed timestamps: [2024-01-15 10:30:00]
  if (/^\[\d{4}[-/]\d{2}[-/]\d{2}/.test(line)) return true;
  
  // 5. Apache/Nginx format: 127.0.0.1 - - [15/Jan/2024:10:30:00
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\S+\s+\S+\s+\[/.test(line)) return true;
  
  // 6. JSON logs starting with {"timestamp": or {"time":
  if (/^\{\s*"(timestamp|time|ts|date)"\s*:/.test(line)) return true;
  
  // 7. Windows Event Log format
  if (/^\d{4}[-\d\s:]+,(Information|Warning|Error|Success|Failure)/i.test(line)) return true;
  
  // 8. Common application log prefixes
  if (/^\[?[A-Z][a-z]+\s+\d{1,2},?\s+\d{4}/.test(line)) return true;
  
  return false;
}

/**
 * Check if a line is a continuation of the previous log entry (multiline)
 * Examples: stack traces, indented lines, etc.
 */
function isContinuationLine(line: string): boolean {
  if (!line) return false;
  
  // Stack trace lines (Java, Python, etc.)
  if (/^\s+(at|File|line|in)\s+/.test(line)) return true;
  if (/^\s+\d+\s+│\s*/.test(line)) return true; // Python tracebacks with │
  
  // Indented continuation (spaces or tabs at start)
  if (/^[\t ]{2,}/.test(line)) return true;
  
  // Caused by / Exception lines in stack traces
  if (/^(Caused by|Exception|Traceback|\s+\.{3}\s+\d+ more)/i.test(line)) return true;
  
  // JSON continuation (lines starting with whitespace and quotes)
  if (/^[\t ]+"/.test(line)) return true;
  
  // XML/HTML continuation
  if (/^[\t ]*[<\/]/.test(line)) return true;
  
  return false;
}

/**
 * Group lines into complete log entries
 * Ensures multiline entries stay together
 */
function groupIntoLogEntries(lines: string[]): string[] {
  const entries: string[] = [];
  let currentEntry: string[] = [];
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const nextLine = lines[i + 1];
    
    // Empty line - might be separator between entries
    if (line.trim() === '') {
      if (currentEntry.length > 0) {
        entries.push(currentEntry.join('\n'));
        currentEntry = [];
      }
      continue;
    }
    
    // Check if this is a new log entry
    if (isNewLogEntry(line)) {
      // Save previous entry if exists
      if (currentEntry.length > 0) {
        entries.push(currentEntry.join('\n'));
      }
      currentEntry = [line];
    } else if (isContinuationLine(line) && currentEntry.length > 0) {
      // This is a continuation of current entry (stack trace, etc.)
      currentEntry.push(line);
    } else if (currentEntry.length === 0) {
      // Start of file without clear timestamp - assume new entry
      currentEntry = [line];
    } else {
      // Ambiguous - check if next line is a new entry
      if (nextLine && isNewLogEntry(nextLine)) {
        // Current line is end of previous entry
        currentEntry.push(line);
        entries.push(currentEntry.join('\n'));
        currentEntry = [];
      } else {
        // Likely continuation
        currentEntry.push(line);
      }
    }
  }
  
  // Don't forget the last entry
  if (currentEntry.length > 0) {
    entries.push(currentEntry.join('\n'));
  }
  
  return entries;
}

function distributeContent(content: string, numWorkers: number): FileChunk[] {
  const lines = content.split('\n');
  
  // Group lines into complete log entries
  const logEntries = groupIntoLogEntries(lines);
  const totalEntries = logEntries.length;
  
  console.log(`Grouped ${lines.length} lines into ${totalEntries} complete log entries`);
  
  if (totalEntries === 0) {
    return [];
  }
  
  // Calculate entries per worker
  const entriesPerWorker = Math.ceil(totalEntries / numWorkers);
  
  const chunks: FileChunk[] = [];
  
  for (let i = 0; i < numWorkers; i++) {
    const startEntry = i * entriesPerWorker;
    const endEntry = Math.min(startEntry + entriesPerWorker, totalEntries);
    
    if (startEntry >= totalEntries) {
      break; // No more entries for this worker
    }
    
    // Get all entries for this chunk
    const chunkEntries = logEntries.slice(startEntry, endEntry);
    
    // Reconstruct the content preserving original format
    // Join entries with single newline (since each entry already has its internal newlines)
    const chunkContent = chunkEntries.join('\n');
    
    // Calculate original line numbers
    let startLine = 0;
    let endLine = 0;
    let currentEntryIdx = 0;
    let lineIdx = 0;
    
    // Build a map of entry index to start line number
    const entryStartLines: number[] = [];
    let currentLineIdx = 0;
    
    for (const entry of logEntries) {
      entryStartLines.push(currentLineIdx);
      currentLineIdx += entry.split('\n').length;
    }
    
    startLine = entryStartLines[startEntry] || 0;
    
    // Calculate end line
    const lastEntryIdx = endEntry - 1;
    if (lastEntryIdx < logEntries.length) {
      const lastEntry = logEntries[lastEntryIdx];
      const lastEntryStart = entryStartLines[lastEntryIdx] || 0;
      const lastEntryLines = lastEntry.split('\n').length;
      endLine = lastEntryStart + lastEntryLines - 1;
    } else {
      endLine = lines.length - 1;
    }
    
    if (chunkContent.trim()) {
      chunks.push({
        workerIndex: i,
        content: chunkContent,
        startLine,
        endLine,
        size: new TextEncoder().encode(chunkContent).length
      });
      
      console.log(`Chunk ${i}: entries ${startEntry}-${endEntry - 1}, lines ${startLine}-${endLine}, ${chunkEntries.length} entries`);
    }
  }
  
  return chunks;
}

async function processChunkWithRetry(
  chunk: FileChunk,
  worker: WorkerConfig,
  fileName: string,
  totalChunks: number,
  retryCount = 0
): Promise<any> {
  incrementRequests(worker.name);
  
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
    
    const response = await fetch(`https://${worker.url}/parse`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Chunk-Index': String(chunk.workerIndex),
        'X-Total-Chunks': String(totalChunks),
        'X-File-Name': fileName,
      },
      body: JSON.stringify({ 
        content: chunk.content,
        forceType: 'auto',
        _chunkMetadata: {
          chunkIndex: chunk.workerIndex,
          totalChunks: totalChunks,
          startLine: chunk.startLine,
          endLine: chunk.endLine,
          isDistributed: true
        }
      }),
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    decrementRequests(worker.name);
    
    if (!response.ok) {
      throw new Error(`Worker ${worker.name} returned ${response.status}`);
    }
    
    const result = await response.json();
    
    return {
      worker: worker.name,
      chunkIndex: chunk.workerIndex,
      success: true,
      data: result
    };
  } catch (error) {
    decrementRequests(worker.name);
    
    // Retry logic
    if (retryCount < MAX_RETRIES) {
      console.log(`Retrying chunk ${chunk.workerIndex} on ${worker.name} (attempt ${retryCount + 1}/${MAX_RETRIES})`);
      await new Promise(resolve => setTimeout(resolve, 1000 * (retryCount + 1))); // Exponential backoff
      return processChunkWithRetry(chunk, worker, fileName, totalChunks, retryCount + 1);
    }
    
    markWorkerUnhealthy(worker.name);
    
    return {
      worker: worker.name,
      chunkIndex: chunk.workerIndex,
      success: false,
      error: String(error)
    };
  }
}

async function distributeFileToWorkers(
  content: string, 
  fileName: string,
  healthyWorkers: WorkerConfig[],
  onProgress?: (progress: number) => void
): Promise<any> {
  console.log(`Distributing file ${fileName} (${content.length} bytes) to ${healthyWorkers.length} workers`);
  
  const chunks = distributeContent(content, healthyWorkers.length);
  console.log(`Split into ${chunks.length} chunks`);
  
  const promises = chunks.map(async (chunk, idx) => {
    const worker = healthyWorkers[idx];
    const result = await processChunkWithRetry(chunk, worker, fileName, chunks.length);
    onProgress?.(((idx + 1) / chunks.length) * 100);
    return result;
  });
  
  const results = await Promise.all(promises);
  
  return {
    chunks: results,
    totalWorkers: healthyWorkers.length,
    successful: results.filter(r => r.success).length,
    failed: results.filter(r => !r.success).length
  };
}

function mergeResults(results: any[]): any {
  const successfulResults = results.filter(r => r.success && r.data);
  
  if (successfulResults.length === 0) {
    throw new Error('All workers failed');
  }
  
  const baseResult = successfulResults[0].data;
  
  const allEntries = successfulResults.flatMap(r => r.data.entries || []);
  const allAlerts = successfulResults.flatMap(r => r.data.alerts || []);
  const allMlAttacks = successfulResults.flatMap(r => r.data.mlAttacks || []);
  const allMlPredictions = successfulResults.flatMap(r => r.data.mlPredictions || []);
  const allMultiLogAnomalies = successfulResults.flatMap(r => r.data.multiLogAnomalies || []);
  
  const bySeverity: Record<string, number> = {};
  const byLogType: Record<string, number> = {};
  const uniqueIPs = new Set<string>();
  const uniqueUsers = new Set<string>();
  let totalLines = 0;
  let parsedLines = 0;
  let failedLines = 0;
  let totalEvents = 0;
  let parsedEvents = 0;
  let failedEvents = 0;
  
  successfulResults.forEach(r => {
    const stats = r.data.stats || {};
    
    if (stats.bySeverity) {
      Object.entries(stats.bySeverity).forEach(([sev, count]) => {
        bySeverity[sev] = (bySeverity[sev] || 0) + (count as number);
      });
    } else if (stats.severityBreakdown) {
      Object.entries(stats.severityBreakdown).forEach(([sev, count]) => {
        bySeverity[sev] = (bySeverity[sev] || 0) + (count as number);
      });
    }
    
    if (stats.byLogType) {
      Object.entries(stats.byLogType).forEach(([type, count]) => {
        byLogType[type] = (byLogType[type] || 0) + (count as number);
      });
    } else if (stats.logTypeBreakdown) {
      Object.entries(stats.logTypeBreakdown).forEach(([type, count]) => {
        byLogType[type] = (byLogType[type] || 0) + (count as number);
      });
    }
    
    r.data.entries?.forEach((e: any) => {
      if (e.source?.ip) uniqueIPs.add(e.source.ip);
      if (e.user?.name) uniqueUsers.add(e.user.name);
    });
    
    totalLines += stats.totalLines || r.data.totalLines || 0;
    parsedLines += stats.parsedLines || r.data.parsedLines || 0;
    failedLines += stats.failedLines || r.data.failedLines || 0;
    totalEvents += stats.totalEvents || 0;
    parsedEvents += stats.parsedEvents || 0;
    failedEvents += stats.failedEvents || 0;
  });
  
  const attackTypes = [...new Set(allMlAttacks.map((a: any) => a.attack?.attackType).filter(Boolean))];
  const mlAttackTypes = [...new Set(allMlPredictions.map((p: any) => p.attackType).filter(Boolean))];
  const multiLogAttackTypes = [...new Set(allMultiLogAnomalies.flatMap((a: any) => a.detectedAttackTypes || []))];
  const allAttackTypes = [...new Set([...attackTypes, ...mlAttackTypes, ...multiLogAttackTypes])];
  
  const attackSummary = {
    totalAttacks: allMlAttacks.length + allMlPredictions.length + allMultiLogAnomalies.filter((a: any) => a.isAnomaly).length,
    attackTypes: allAttackTypes,
    uniqueSources: uniqueIPs.size,
    riskScore: Math.min(Math.max(allMlAttacks.length, allMlPredictions.length) * 10, 100),
    multiLogRiskScore: Math.min(allMultiLogAnomalies.reduce((sum: number, a: any) => sum + (a.anomalyScore || 0), 0) * 20, 100),
  };
  
  return {
    success: true,
    detectedType: baseResult.detectedType || 'distributed',
    distributed: true,
    totalLines,
    parsedLines,
    failedLines,
    successRate: totalLines > 0 ? Math.round(((totalLines - failedLines) / totalLines) * 100) : 0,
    totalEvents,
    parsedEvents,
    failedEvents,
    entries: allEntries,
    alerts: allAlerts,
    stats: {
      totalLines,
      parsedLines,
      failedLines,
      totalEvents,
      parsedEvents,
      failedEvents,
      bySeverity,
      byLogType,
      uniqueIPs: uniqueIPs.size,
      uniqueUsers: uniqueUsers.size,
    },
    mlAttacks: allMlAttacks,
    mlPredictions: allMlPredictions,
    multiLogAnomalies: allMultiLogAnomalies,
    attackSummary,
    distribution: {
      totalWorkers: successfulResults.length,
      chunksPerWorker: 1,
      entriesPerWorker: Math.round(allEntries.length / successfulResults.length),
    }
  };
}

// ============================================
// CORS CONFIGURATION
// ============================================

app.use('*', cors({
  origin: (origin) => {
    const allowed = [
      'https://freekhana-frontend.pages.dev',
      'http://localhost:5173',
      'http://127.0.0.1:5173',
      'http://localhost:5000',
      'http://127.0.0.1:5000',
    ];
    return allowed.includes(origin) ? origin : '*';
  },
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With', 'X-File-Name', 'X-Chunk-Index', 'X-Total-Chunks'],
  credentials: false,
}));

// ============================================
// ENDPOINTS
// ============================================

app.get('/', (c) => {
  // Trigger health check in background and schedule request reset
  triggerHealthCheck(c, true);
  scheduleRequestReset(c);
  
  return c.json({
    status: 'ok',
    name: 'FreeKhana SIEM Master',
    version: '2.0.0',
    type: 'load_balancer_with_auto_recovery',
    workers: WORKERS.map(w => ({
      name: w.name,
      url: w.url,
      healthy: w.healthy,
      currentRequests: w.requests,
      failedAttempts: w.failedAttempts,
    })),
    totalWorkers: WORKERS.length,
    healthyWorkers: WORKERS.filter(w => w.healthy).length,
    autoRecovery: {
      enabled: true,
      maxFailedAttempts: MAX_FAILED_ATTEMPTS,
      healthCheckInterval: `${HEALTH_CHECK_INTERVAL / 1000}s`,
      redeployOnFailure: true,
    },
    endpoints: {
      health: '/health',
      stats: '/stats',
      recover: '/recover (POST - force redeploy all workers)',
    },
  });
});

app.get('/health', async (c) => {
  // Trigger immediate full health check (not quick check)
  await checkAndRecoverWorkers(false);
  
  const results = WORKERS.map(worker => ({
    name: worker.name,
    url: worker.url,
    status: worker.healthy ? 'healthy' : 'unhealthy',
    failedAttempts: worker.failedAttempts,
  }));
  
  const healthy = results.filter(r => r.status === 'healthy').length;
  const unhealthy = results.filter(r => r.status === 'unhealthy');
  
  return c.json({
    summary: { total: WORKERS.length, healthy, unhealthy: unhealthy.length },
    workers: results,
    autoRecovery: unhealthy.length > 0 ? 'Some workers unhealthy - recovery may be triggered' : 'All workers healthy',
  });
});

app.post('/recover', async (c) => {
  const results: { name: string; status: string; redeployed: boolean }[] = [];
  
  for (const worker of WORKERS) {
    const redeployed = await redeployWorker(worker.name);
    results.push({
      name: worker.name,
      status: redeployed ? 'redeployment_triggered' : 'failed',
      redeployed
    });
    
    // Reset for fresh health check
    worker.healthy = true;
    worker.failedAttempts = 0;
    worker.lastHealthCheck = 0;
  }
  
  // Trigger immediate health check
  c.executionCtx.waitUntil(checkAndRecoverWorkers());
  
  return c.json({
    message: 'Recovery triggered for all workers',
    results
  });
});

app.get('/stats', (c) => {
  const total = WORKERS.reduce((sum, w) => sum + w.requests, 0);
  
  return c.json({
    totalRequests: total,
    workers: WORKERS.map(w => ({
      name: w.name,
      url: w.url,
      healthy: w.healthy,
      requests: w.requests,
      loadPercentage: total > 0 ? Math.round((w.requests / total) * 100) : 0,
    })),
    configuration: {
      totalWorkers: WORKERS.length,
      addWorkers: 'Edit WORKERS array in src/index.ts to add more workers',
    }
  });
});

// ============================================
// PARSE ENDPOINT
// ============================================

app.post('/parse', async (c) => {
  // Trigger health check in background before processing
  // This ensures we have latest worker status without blocking the request
  triggerHealthCheck(c, true);
  
  const contentType = c.req.header('Content-Type') || '';
  let content: string;
  let fileName = 'unknown';
  
  try {
    if (contentType.includes('multipart/form-data')) {
      const formData = await c.req.formData();
      const file = formData.get('file') as File | null;
      if (!file) {
        return c.json({ error: 'No file provided' }, 400);
      }
      fileName = file.name;
      content = await file.text();
    } else {
      content = await c.req.text();
      fileName = c.req.header('x-file-name') || c.req.header('X-File-Name') || 'logs.log';
    }
    
    if (!content || content.trim().length === 0) {
      return c.json({ error: 'No log content provided' }, 400);
    }
    
    const healthyWorkers = getHealthyWorkers();
    if (healthyWorkers.length === 0) {
      return c.json({ error: 'No healthy workers available. Try /recover endpoint.' }, 503);
    }
    
    console.log(`Processing file ${fileName} (${content.length} bytes) with ${healthyWorkers.length} workers`);
    
    if (healthyWorkers.length === 1) {
      // Single worker
      const worker = healthyWorkers[0];
      incrementRequests(worker.name);
      
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
        
        const response = await fetch(`https://${worker.url}/parse`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-File-Name': fileName,
          },
          body: JSON.stringify({ content, forceType: 'auto' }),
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        decrementRequests(worker.name);
        
        if (!response.ok) {
          return c.text(await response.text(), response.status);
        }
        
        const result = await response.json();
        const wrappedResult = mergeResults([{
          worker: worker.name,
          chunkIndex: 0,
          success: true,
          data: result
        }]);
        
        return c.json(wrappedResult);
        
      } catch (error) {
        decrementRequests(worker.name);
        markWorkerUnhealthy(worker.name);
        return c.json({ error: 'Worker request failed', details: String(error) }, 502);
      }
    }
    
    // Multiple workers - distribute
    console.log(`Distributing to ${healthyWorkers.length} workers`);
    
    const distributionResult = await distributeFileToWorkers(content, fileName, healthyWorkers);
    
    if (distributionResult.successful === 0) {
      return c.json({ 
        error: 'All workers failed to process the file',
        distribution: distributionResult,
        suggestion: 'Try POST /recover to redeploy all workers'
      }, 502);
    }
    
    const mergedResult = mergeResults(distributionResult.chunks);
    return c.json(mergedResult);
    
  } catch (error) {
    console.error('Parse error:', error);
    return c.json({ 
      success: false,
      error: 'Failed to parse logs', 
      details: String(error) 
    }, 500);
  }
});

// ============================================
// ROUTE OTHER REQUESTS
// ============================================

async function routeToWorker(c: any, path: string, body: string | null): Promise<Response> {
  const worker = getLeastLoadedWorker();
  if (!worker) {
    return c.json({ error: 'No healthy workers available. Try /recover endpoint.' }, 503);
  }
  
  incrementRequests(worker.name);
  try {
    const url = `https://${worker.url}${path}`;
    const method = c.req.method;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Forwarded-For': c.req.header('CF-Connecting-IP') || 'unknown',
      'X-Master-Worker': 'siem-master',
    };
    
    const relevantHeaders = ['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With', 'X-File-Name'];
    for (const header of relevantHeaders) {
      const value = c.req.header(header.toLowerCase());
      if (value) headers[header] = value;
    }
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
    
    const response = await fetch(url, { 
      method, 
      headers, 
      body: body || undefined,
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    decrementRequests(worker.name);
    
    if (path === '/parsers') {
      return c.json(await response.json());
    }
    
    return c.text(await response.text(), response.status);
  } catch (error) {
    decrementRequests(worker.name);
    markWorkerUnhealthy(worker.name);
    return c.json({ error: 'Routing failed', target: worker.name, details: String(error) }, 502);
  }
}

app.all('/correlate', async (c) => routeToWorker(c, '/correlate', await c.req.text()));
app.all('/stream', async (c) => routeToWorker(c, '/stream', await c.req.text()));
app.all('/analyze', async (c) => routeToWorker(c, '/analyze', await c.req.text()));
app.all('/detect', async (c) => routeToWorker(c, '/detect', await c.req.text()));
app.all('/feedback', async (c) => routeToWorker(c, '/feedback', await c.req.text()));
app.all('/feedback/bulk', async (c) => routeToWorker(c, '/feedback/bulk', await c.req.text()));
app.all('/parsers', async (c) => routeToWorker(c, '/parsers', null));
app.all('/attacks', async (c) => routeToWorker(c, '/attacks', null));
app.all('/limits', async (c) => routeToWorker(c, '/limits', null));
app.all('/feedback/attack-types', async (c) => routeToWorker(c, '/feedback/attack-types', null));
app.all('/feedback/stats', async (c) => routeToWorker(c, '/feedback/stats', null));
app.all('/parse/chunked', async (c) => routeToWorker(c, '/parse/chunked', await c.req.text()));
app.all('/parse/stream', async (c) => routeToWorker(c, '/parse/stream', await c.req.text()));

export default app;
