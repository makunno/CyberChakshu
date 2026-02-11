# Master Worker Load Balancer Fixes

## Issues Fixed

### 1. **Worker URL Configuration Bug** (Lines 36-37)
**Problem**: Workers 9 and 10 both pointed to `siem-worker-8.tanubhavj.workers.dev`
**Fix**: Changed to correct URLs:
- Worker 9: `siem-worker-9.tanubhavj.workers.dev`
- Worker 10: `siem-worker-10.tanubhavj.workers.dev`

### 2. **Multiline Log Entry Splitting** (CRITICAL)
**Problem**: Line-based distribution was splitting multiline log entries across workers, causing:
- Stack traces getting cut off
- JSON logs split mid-object
- Incomplete log entries in parsed results

**Solution**: Smart log entry grouping
- New `isNewLogEntry()` function detects start of log entries by pattern matching
- New `isContinuationLine()` function identifies multiline continuations (stack traces, indented lines, etc.)
- New `groupIntoLogEntries()` groups lines into complete entries before distribution
- Each worker receives **complete log entries only**

**Supported Patterns**:
- Timestamps: `2024-01-15 10:30:00`, `Jan 15 10:30:00`, `1705315800`
- Log levels: `ERROR`, `INFO`, `DEBUG`, `WARN` at start of line
- Bracketed: `[2024-01-15 10:30:00] ...`
- Apache/Nginx: `127.0.0.1 - - [15/Jan/2024:10:30:00`
- JSON logs: `{"timestamp": ...`, `{"time": ...`
- Windows: `2024-01-15 10:30:00,Information,...`
- Continuations: stack traces (`at ...`, `Caused by: ...`), indented lines, JSON/XML continuations

### 3. **Health Check on Every Request**
**Problem**: Health checks were creating infinite loops when scheduled on every request
**Solution**: 
- Health checks now trigger on every request but run in background via `waitUntil`
- Quick checks (5s interval) run during normal requests to get fresh worker status
- Full checks (30s interval) run on `/health` endpoint
- Non-blocking: uses `c.executionCtx.waitUntil()` to not delay responses

### 4. **No Request Timeouts**
**Problem**: Worker requests could hang indefinitely without timeout
**Fix**: 
- Added `REQUEST_TIMEOUT = 30000ms` (30 seconds)
- Added `AbortController` with timeout to all fetch requests
- Single worker requests, distributed chunks, and routed requests all have timeouts

### 5. **No Retry Logic**
**Problem**: Failed chunks were not retried, causing partial failures
**Fix**: 
- Added `MAX_RETRIES = 2` with exponential backoff
- New `processChunkWithRetry()` function handles retries
- 1s delay before first retry, 2s before second

### 6. **Frontend Using Wrong Endpoint**
**Problem**: Frontend pointed directly to `siem-backend` instead of master worker
**Fix**: Updated `.env.production`:
```
VITE_API_URL=https://siem-master.tanubhavj.workers.dev
```

## Architecture

```
Frontend → Master Worker → 10 Workers (load balanced)
                ↓
         ┌──────┴──────┐
         ↓             ↓
   Health Check    Route Request
   (background)    (foreground)
         ↓             ↓
   Auto-recovery   Retry on failure
   Redeploy        Exponential backoff
```

## Health Check Strategy

### Quick Health Check (on every request)
- **Interval**: 5 seconds between checks per worker
- **Timeout**: 5 seconds
- **Runs in background**: Non-blocking via `waitUntil`
- **Purpose**: Ensure fresh worker status before routing
- **Trigger**: Every API request (`/`, `/parse`, etc.)

### Full Health Check (on /health endpoint)
- **Interval**: 30 seconds between checks per worker
- **Timeout**: 5 seconds
- **Runs synchronously**: Blocking, returns full status
- **Purpose**: Get complete health report
- **Trigger**: Manual `/health` endpoint calls

### Health Check Flow
1. Request comes in → trigger background health check
2. Check workers not checked in last 5 seconds
3. Mark unhealthy workers, increment failed attempts
4. If 3+ failures → trigger redeployment
5. Route request only to healthy workers

## Features

- **Multiline Log Support**: Smart grouping ensures complete log entries go to single worker (no splitting)
- **Health-Aware Routing**: Every request triggers health check, routes only to healthy workers
- **Least-Connections Load Balancing**: Routes to worker with lowest active requests
- **Auto-Recovery**: Redeploys failed workers after 3 consecutive failures
- **Retry Logic**: Retries failed chunks up to 2 times with exponential backoff
- **Timeout Protection**: 30-second timeout on all worker requests
- **Request Tracking**: Tracks active requests per worker, resets every minute
- **Result Merging**: Combines results from all workers into single response
- **Graceful Degradation**: If some workers fail, continues with remaining healthy workers

## Multiline Log Handling

### The Problem
Traditional line-based splitting breaks multiline log entries:
```
2024-01-15 10:30:00 ERROR Exception occurred
    at com.example.Main.process(Main.java:45)  ← Worker 1 gets this
    at com.example.Main.main(Main.java:20)     ← Worker 2 gets this (BROKEN!)
Caused by: java.lang.NullPointerException
    at com.example.Utils.parse(Utils.java:10)
```

### The Solution
The master worker now intelligently groups lines into complete log entries before distribution:

1. **Entry Detection**: Identifies start of new log entries using patterns (timestamps, log levels, etc.)
2. **Continuation Detection**: Recognizes continuation lines (stack traces, indented lines)
3. **Complete Entry Grouping**: Groups all lines belonging to single entry together
4. **Entry-Based Distribution**: Distributes complete entries to workers (never splits an entry)

### Supported Log Types
- **Java/Python Stack Traces**: Multiline exceptions with "at ...", "Caused by: ..."
- **JSON Logs**: Multiline JSON objects
- **XML/HTML Logs**: Multiline markup
- **Syslog**: Standard and custom formats
- **Windows Event Logs**: EVTX exported formats
- **Application Logs**: Any timestamped log format

### Example Distribution
```
Original file with 3 multiline entries:
┌─ Entry 1 (5 lines: timestamp + stack trace)
├─ Entry 2 (3 lines: timestamp + error)
└─ Entry 3 (7 lines: timestamp + nested exception)

Distributed to 2 workers:
Worker 1: Entry 1 (complete, 5 lines)
Worker 2: Entry 2 + Entry 3 (complete, 10 lines)

Result: Each entry is parsed as complete unit
```

## Deployment

1. Deploy all 10 workers first:
   ```bash
   cd siem-tool/backend
   wrangler deploy  # for each worker
   ```

2. Deploy master worker:
   ```bash
   cd siem-tool/master-worker
   wrangler deploy
   ```

3. Frontend automatically uses master worker via `VITE_API_URL`

## Environment Variables

Required in Cloudflare for auto-redeployment:
- `CF_API_TOKEN` - Cloudflare API token with Workers Scripts:Edit permission
- `CF_ACCOUNT_ID` - Your Cloudflare account ID

## Testing

Check master worker health:
```bash
curl https://siem-master.tanubhavj.workers.dev/health
```

Force recovery of all workers:
```bash
curl -X POST https://siem-master.tanubhavj.workers.dev/recover
```

View load balancer stats:
```bash
curl https://siem-master.tanubhavj.workers.dev/stats
```

Check master worker status:
```bash
curl https://siem-master.tanubhavj.workers.dev/
```

## How It Works

### Request Flow
1. **Frontend** sends file to `/parse`
2. **Master Worker** triggers background health check (updates worker status)
3. **Master Worker** groups lines into complete log entries (handles multiline entries)
4. **Master Worker** distributes complete entries to workers (never splits an entry)
5. **Master Worker** sends chunks to workers in parallel
6. **Each Worker** processes its complete entries
6. **Master Worker** collects results, retries failed chunks
7. **Master Worker** merges all results into single response
8. **Frontend** receives unified parsed data

### Failure Handling
- **Worker fails during request**: Chunk is retried up to 2 times with exponential backoff
- **Worker consistently fails**: Marked unhealthy after 3 failures, triggers redeployment
- **All workers fail**: Returns 503 error with recovery instructions
- **Partial failure**: Returns successful chunks, logs failed ones

### Auto-Recovery
- Monitors all 10 workers continuously
- Marks workers unhealthy on failure
- After 3 failures, triggers Cloudflare API redeployment
- Worker comes back online after ~30 seconds
- No manual intervention required
