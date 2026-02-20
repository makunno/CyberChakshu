// API client for SIEM backend

import type { ParseResponse, CorrelateResponse } from './types';

// Read API URL from environment or injected window variable
// - VITE_API_URL: set during build for Cloudflare deployment
// - window.FREEKHANA_API_URL: injected by Flask for local development
const ENV_API_URL = import.meta.env.VITE_API_URL || '';
const INJECTED_API_URL = typeof window !== 'undefined' ? (window as any).FREEKHANA_API_URL : '';
const API_URL = ENV_API_URL || INJECTED_API_URL || '';

const CLIENT_SPLIT_THRESHOLD = 200 * 1024; // 200KB - split on frontend

function getApiUrl(path: string): string {
  // Use absolute URL if set, otherwise use relative URL
  if (API_URL) {
    return `${API_URL}${path.startsWith('/') ? path : '/' + path}`;
  }
  return path; // Relative URL for same-origin requests
}

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

export interface ChunkInfo {
  index: number;
  name: string;
  content: string;
  size: number;
  lineCount: number;
}

export interface SplitFileResult {
  originalFile: {
    name: string;
    size: number;
    sizeMB: number;
    lineCount: number;
  };
  chunks: ChunkInfo[];
  totalChunks: number;
  chunkSizeMB: number;
}

export async function splitFileClient(file: File): Promise<SplitFileResult> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    
    reader.onload = () => {
      try {
        const content = reader.result as string;
        const lines = content.split('\n');
        
        const chunks: ChunkInfo[] = [];
        let currentChunk = '';
        let currentSize = 0;
        let chunkIndex = 1;
        let totalLines = 0;
        
        for (const line of lines) {
          const lineWithNewline = line + '\n';
          const lineSize = new Blob([lineWithNewline]).size;
          
          if (currentSize + lineSize > CLIENT_SPLIT_THRESHOLD && currentChunk.length > 0) {
            const trimmed = currentChunk.trimEnd();
            chunks.push({
              index: chunkIndex,
              name: `${file.name.replace(/\.[^/.]+$/, '')}_chunk_${String(chunkIndex).padStart(3, '0')}.log`,
              content: trimmed,
              size: new Blob([trimmed]).size,
              lineCount: trimmed.split('\n').length
            });
            chunkIndex++;
            currentChunk = lineWithNewline;
            currentSize = lineSize;
          } else {
            currentChunk += lineWithNewline;
            currentSize += lineSize;
          }
          totalLines++;
        }
        
        if (currentChunk.trimEnd().length > 0) {
          const trimmed = currentChunk.trimEnd();
          chunks.push({
            index: chunkIndex,
            name: `${file.name.replace(/\.[^/.]+$/, '')}_chunk_${String(chunkIndex).padStart(3, '0')}.log`,
            content: trimmed,
            size: new Blob([trimmed]).size,
            lineCount: trimmed.split('\n').length
          });
        }
        
        resolve({
          originalFile: {
            name: file.name,
            size: file.size,
            sizeMB: file.size / 1024 / 1024,
            lineCount: totalLines
          },
          chunks,
          totalChunks: chunks.length,
          chunkSizeMB: CLIENT_SPLIT_THRESHOLD / 1024 / 1024
        });
      } catch (err) {
        reject(err);
      }
    };
    
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.readAsText(file);
  });
}

export async function parseLogsFromFile(file: File): Promise<ParseResponse> {
  if (isEVTXFile(file)) {
    throw new EVTXUploadError(
      'EVTX files are not directly supported. Please export your Windows Event Log as TXT format using Event Viewer, then upload the TXT file.'
    );
  }

  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(getApiUrl('/parse'), {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    throw new Error(`Failed to parse logs: ${response.statusText}`);
  }

  const data = await response.json();
  
  // Handle auto-split response - return special response that frontend can use
  if (data.status === 'auto_split') {
    return {
      success: true,
      detectedType: 'unknown',
      totalLines: data.originalFile?.lineCount || 0,
      parsedLines: 0,
      failedLines: 0,
      entries: [],
      alerts: [],
      stats: {
        byType: {},
        bySeverity: {},
        byOutcome: {},
        topSources: [],
        topUsers: [],
        timeline: []
      },
      autoSplitInfo: {
        originalFile: data.originalFile,
        splitConfig: data.splitConfig,
        chunks: data.chunks
      }
    } as unknown as ParseResponse;
  }

  return data;
}

export async function parseLogsFromChunkedFile(
  chunks: string[], 
  fileName: string
): Promise<ParseResponse> {
  const response = await fetch(getApiUrl('/parse/chunked'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chunks, fileName })
  });

  if (!response.ok) {
    throw new Error(`Failed to parse logs: ${response.statusText}`);
  }

  return response.json();
}

export async function parseLogsFromText(content: string): Promise<ParseResponse> {
  const response = await fetch(getApiUrl('/parse'), {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
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

  const response = await fetch(getApiUrl('/correlate'), {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    throw new Error(`Failed to correlate logs: ${response.statusText}`);
  }

  return response.json();
}

export async function correlateFromChunkedFiles(
  fileChunks: Array<{ name: string; chunks: string[] }>
): Promise<CorrelateResponse> {
  const logs = fileChunks.map(f => ({
    name: f.name,
    content: f.chunks.join('\n')
  }));

  const response = await fetch(getApiUrl('/correlate'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ logs })
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
  const response = await fetch(getApiUrl('/detect'), {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: content,
  });

  if (!response.ok) {
    throw new Error(`Failed to detect log type: ${response.statusText}`);
  }

  return response.json();
}

export async function streamParseLogs(lines: string[]): Promise<ParseResponse> {
  const response = await fetch(getApiUrl('/stream'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ lines })
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
  const response = await fetch(getApiUrl('/parsers'));

  if (!response.ok) {
    throw new Error(`Failed to get parsers: ${response.statusText}`);
  }

  return response.json();
}

export async function getAttackTypes(): Promise<{
  attackTypes: Array<{ type: string; description: string }>;
  mitreTactics: string[];
}> {
  const response = await fetch(getApiUrl('/attacks'));

  if (!response.ok) {
    throw new Error(`Failed to get attack types: ${response.statusText}`);
  }

  return response.json();
}

// SOC Analyst LLM API
export interface LogAnalysisResponse {
  analysis: string;
  attack_detected: boolean;
  severity: string;
}

export interface ChatResponse {
  response: string;
}

export async function analyzeLogWithAI(logEntry: string, logType: string): Promise<LogAnalysisResponse> {
  const response = await fetch(getApiUrl('/soc-analyze'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ log_entry: logEntry, log_type: logType }),
  });

  if (!response.ok) {
    if (response.status === 503) {
      throw new Error('SOC Analyst AI is loading or not available. The model is being initialized. Please wait a moment and try again.');
    }
    throw new Error(`Failed to analyze log: ${response.statusText}`);
  }

  return response.json();
}

export async function getSocAnalystChat(message: string, context: Array<{role: string, content: string}> = []): Promise<string> {
  const response = await fetch(getApiUrl('/soc-chat'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, context }),
  });

  if (!response.ok) {
    if (response.status === 503) {
      throw new Error('SOC Analyst AI is loading or not available. The model is being initialized. Please wait a moment and try again.');
    }
    throw new Error(`Failed to get chat response: ${response.statusText}`);
  }

  const data: ChatResponse = await response.json();
  return data.response;
}

export interface FeedbackRequest {
  message_id: string;
  rating: 1 | 5;
  feedback_text?: string;
  original_prompt: string;
  llm_response: string;
  log_context?: string;
}

export interface FeedbackResponse {
  status: string;
  message: string;
  training_examples_count: number;
}

export async function submitFeedback(feedback: FeedbackRequest): Promise<FeedbackResponse> {
  const response = await fetch(getApiUrl('/soc-feedback'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(feedback),
  });

  if (!response.ok) {
    throw new Error(`Failed to submit feedback: ${response.statusText}`);
  }

  return response.json();
}

export async function triggerTraining(epochs: number = 1): Promise<{status: string; message: string}> {
  const response = await fetch(getApiUrl('/soc-train'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ epochs }),
  });

  if (!response.ok) {
    throw new Error(`Failed to start training: ${response.statusText}`);
  }

  return response.json();
}

export async function getFeedbackStats(): Promise<{total_feedback: number; likes: number; dislikes: number}> {
  const response = await fetch(getApiUrl('/soc-feedback/stats'), {
    method: 'GET',
  });

  if (!response.ok) {
    throw new Error(`Failed to get feedback stats: ${response.statusText}`);
  }

  return response.json();
}

export async function checkSocAnalystHealth(): Promise<{status: string; llm_loaded: boolean}> {
  try {
    const response = await fetch(getApiUrl('/soc-analyze'), {
      method: 'GET',
    });
    
    if (response.ok) {
      return await response.json();
    }
    return { status: 'unavailable', llm_loaded: false };
  } catch {
    return { status: 'unavailable', llm_loaded: false };
  }
}
