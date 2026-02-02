// FASTAPI and Python Web Framework Parsers
// ISEA-style static parser methods

import { ParsedLogEntry, LogType } from '../types';
import { generateId } from '../utils/helpers';

export class FastAPIParsers {

  static fastapi(line: string): Record<string, any> | null {
    // FastAPI/Uvicorn format:
    // INFO:     127.0.0.1:8000 - "GET /docs HTTP/1.1" 200
    // INFO:uvicorn.access: 127.0.0.1:56390 - "GET /api/users HTTP/1.1" 200 1234 (27.74ms)
    
    const match = line.match(
      /^(INFO|WARNING|ERROR|DEBUG)(?::\s*)?(?:uvicorn\.access:\s+)?(\d+\.\d+\.\d+\.\d+):(\d+)\s+-\s+"(\w+)\s+(\S+)\s+(\S+)"\s+(\d+)(?:\s+(\d+))?(?:\s+\(([\d.]+)ms\))?$/
    );
    if (!match) return null;
    
    const [, level, ip, port, method, path, protocol, status, bytes, responseTime] = match;
    
    return {
      timestamp: new Date().toISOString(),
      host: 'fastapi',
      service: 'fastapi',
      source: { ip, port: parseInt(port) },
      method,
      path,
      protocol,
      status: parseInt(status),
      bytes: bytes ? parseInt(bytes) : null,
      response_time_ms: responseTime ? parseFloat(responseTime) : null,
      level: level.toLowerCase()
    };
  }

  static aiohttp(line: string): Record<string, any> | null {
    // Aiohttp server format:
    // 127.0.0.1 [02/Feb/2025:12:00:00 +0000] "GET /api HTTP/1.1" 200 1234 0.027
    
    const match = line.match(
      /^(\d+\.\d+\.\d+\.\d+)\s+\[(\d{2}\/[A-Z][a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]\s+"(\w+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)\s+([\d.]+)$/
    );
    if (!match) return null;
    
    const [, ip, timestamp, method, path, protocol, status, bytes, responseTime] = match;
    
    return {
      timestamp: new Date(timestamp).toISOString(),
      host: 'aiohttp',
      service: 'aiohttp',
      source: { ip },
      method,
      path,
      protocol,
      status: parseInt(status),
      bytes: parseInt(bytes),
      response_time_ms: parseFloat(responseTime) * 1000
    };
  }

  static starlette(line: string): Record<string, any> | null {
    // Starlette ASGI format (JSON):
    // {"time": "2025-02-02T12:00:00Z", "level": "INFO", "message": "...", "request": {...}}
    
    try {
      const data = JSON.parse(line);
      if (!data.time && !data.request) return null;
      
      return {
        timestamp: data.time || new Date().toISOString(),
        host: 'starlette',
        service: 'starlette',
        level: data.level?.toLowerCase() || 'info',
        message: data.message || '',
        request: data.request,
        scope: data.scope
      };
    } catch {
      return null;
    }
  }
}
