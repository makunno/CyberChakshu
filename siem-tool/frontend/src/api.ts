// API client for SIEM backend

import type { ParseResponse, CorrelateResponse } from './types';

const API_URL = import.meta.env.VITE_API_URL || 'https://siem-backend.tanubhavj.workers.dev';
const CHUNK_SIZE = 50 * 1024; // 50KB chunks (well under 100KB limit)
const BINARY_TYPES = ['.evtx', '.evt', '.bin'];

function isBinaryFile(file: File): boolean {
  return BINARY_TYPES.some(ext => file.name.toLowerCase().endsWith(ext)) ||
         file.type === 'application/octet-stream';
}

async function uploadBinaryFile(file: File): Promise<ParseResponse> {
  const arrayBuffer = await file.arrayBuffer();
  
  const response = await fetch(`${API_URL}/parse`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-File-Name': file.name,
    },
    body: arrayBuffer,
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || `Failed to parse EVTX file: ${response.statusText}`);
  }

  return response.json();
}

async function uploadInChunks(file: File): Promise<ParseResponse> {
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
  const chunks: string[] = [];
  
  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, file.size);
    const chunk = await file.slice(start, end).text();
    chunks.push(chunk);
  }
  
  const response = await fetch(`${API_URL}/parse/chunked`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chunks,
      fileName: file.name,
      totalSize: file.size
    })
  });
  
  if (!response.ok) {
    throw new Error(`Failed to parse logs: ${response.statusText}`);
  }
  
  return response.json();
}

export async function parseLogsFromFile(file: File): Promise<ParseResponse> {
  // Handle binary files (EVTX) specially - don't convert to text
  if (isBinaryFile(file)) {
    console.log('Detected binary file:', file.name, 'size:', file.size);
    return uploadBinaryFile(file);
  }
  
  if (file.size > CHUNK_SIZE) {
    return uploadInChunks(file);
  }
  
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_URL}/parse`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    throw new Error(`Failed to parse logs: ${response.statusText}`);
  }

  return response.json();
}

export async function parseLogsFromText(content: string): Promise<ParseResponse> {
  const response = await fetch(`${API_URL}/parse`, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain',
    },
    body: content,
  });

  if (!response.ok) {
    throw new Error(`Failed to parse logs: ${response.statusText}`);
  }

  return response.json();
}

export async function correlateMultipleFiles(files: File[]): Promise<CorrelateResponse> {
  const formData = new FormData();
  
  for (const file of files) {
    formData.append('files', file);
  }

  const response = await fetch(`${API_URL}/correlate`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    throw new Error(`Failed to correlate logs: ${response.statusText}`);
  }

  return response.json();
}

export async function correlateLogsFromText(
  logs: Array<{ name: string; content: string }>
): Promise<CorrelateResponse> {
  const response = await fetch(`${API_URL}/correlate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ logs }),
  });

  if (!response.ok) {
    throw new Error(`Failed to correlate logs: ${response.statusText}`);
  }

  return response.json();
}

export async function detectLogType(content: string): Promise<{
  detectedType: string;
  sampleSize: number;
  totalLines: number;
}> {
  const response = await fetch(`${API_URL}/detect`, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain',
    },
    body: content,
  });

  if (!response.ok) {
    throw new Error(`Failed to detect log type: ${response.statusText}`);
  }

  return response.json();
}

export async function streamParseLogs(lines: string[]): Promise<ParseResponse> {
  const response = await fetch(`${API_URL}/stream`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ lines }),
  });

  if (!response.ok) {
    throw new Error(`Failed to stream parse logs: ${response.statusText}`);
  }

  return response.json();
}

export async function getAvailableParsers(): Promise<{
  total: number;
  categories: Record<string, Array<{ name: string; logType: string }>>;
  all: Array<{ name: string; logType: string }>;
}> {
  const response = await fetch(`${API_URL}/parsers`);

  if (!response.ok) {
    throw new Error(`Failed to get parsers: ${response.statusText}`);
  }

  return response.json();
}

export async function getAttackTypes(): Promise<{
  attackTypes: Array<{ type: string; description: string }>;
  mitreTactics: string[];
}> {
  const response = await fetch(`${API_URL}/attacks`);

  if (!response.ok) {
    throw new Error(`Failed to get attack types: ${response.statusText}`);
  }

  return response.json();
}
