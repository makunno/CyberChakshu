// API client for SIEM backend

import type { ParseResponse, CorrelateResponse } from './types';

const API_URL = import.meta.env.VITE_API_URL || 'https://siem-backend.tanubhavj.workers.dev';
const AUTO_SPLIT_THRESHOLD = 2 * 1024 * 1024;
const CHUNK_SIZE = 2 * 1024 * 1024;

export function isEVTXFile(file: File): boolean {
  const ext = file.name.toLowerCase().split('.').pop();
  return ext === 'evtx' || ext === 'evt';
}

export class EVTXUploadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EVTXUploadError';
  }
}

export class AutoSplitRequiredError extends Error {
  splitConfig: {
    totalChunks: number;
    chunkSizeMB: number;
    originalFileName: string;
    cliCommand: string;
  };

  constructor(message: string, splitConfig: AutoSplitRequiredError['splitConfig']) {
    super(message);
    this.name = 'AutoSplitRequiredError';
    this.splitConfig = splitConfig;
  }
}

export interface SplitChunk {
  index: number;
  name: string;
  lineCount: number;
  byteSize: number;
}

export interface AutoSplitResponse {
  status: 'auto_split';
  message: string;
  originalFile: {
    sizeMB: number;
    lineCount: number;
    name: string;
  };
  splitConfig: {
    chunkSizeMB: number;
    totalChunks: number;
    format: string;
  };
  chunks: SplitChunk[];
  usage: {
    option1: string;
    option2: string;
    apiCall: string;
  };
  cliCommand: string;
}

export function isAutoSplitResponse(obj: ParseResponse | AutoSplitResponse): obj is AutoSplitResponse {
  return 'status' in obj && obj.status === 'auto_split';
}

export function splitFileOnFrontend(file: File): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const content = reader.result as string;
      const lines = content.split('\n');
      const chunks: string[] = [];
      let currentChunk = '';
      let currentSize = 0;
      
      for (const line of lines) {
        const lineWithNewline = line + '\n';
        const lineSize = new Blob([lineWithNewline]).size;
        
        if (currentSize + lineSize > CHUNK_SIZE && currentChunk.length > 0) {
          chunks.push(currentChunk.trimEnd());
          currentChunk = lineWithNewline;
          currentSize = lineSize;
        } else {
          currentChunk += lineWithNewline;
          currentSize += lineSize;
        }
      }
      
      if (currentChunk.trimEnd().length > 0) {
        chunks.push(currentChunk.trimEnd());
      }
      
      resolve(chunks);
    };
    reader.onerror = reject;
    reader.readAsText(file);
  });
}

export async function parseLogsFromFile(file: File): Promise<ParseResponse | AutoSplitResponse> {
  if (isEVTXFile(file)) {
    throw new EVTXUploadError(
      'EVTX files are not directly supported. Please export your Windows Event Log as TXT format using Event Viewer, then upload the TXT file.'
    );
  }

  if (file.size > AUTO_SPLIT_THRESHOLD) {
    const text = await file.text();
    
    const response = await fetch(`${API_URL}/parse`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: text,
    });

    if (response.status === 413) {
      const errorText = await response.text();
      let errorData;
      try {
        errorData = JSON.parse(errorText);
      } catch {
        throw new Error('File too large and backend rejected');
      }

      throw new AutoSplitRequiredError(
        errorData.message || 'File too large - auto-split required',
        {
          totalChunks: Math.ceil(file.size / CHUNK_SIZE),
          chunkSizeMB: CHUNK_SIZE / 1024 / 1024,
          originalFileName: file.name,
          cliCommand: errorData.cliCommand || `node split-log-file.js ${file.name} 2048 ./chunks`
        }
      );
    }

    if (!response.ok) {
      throw new Error(`Failed to parse logs: ${response.statusText}`);
    }

    return response.json();
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
