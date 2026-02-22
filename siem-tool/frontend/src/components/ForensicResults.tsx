import { AlertTriangle, Shield, Clock, FileSearch, HardDrive, FolderOpen, Download, Loader2 } from 'lucide-react';
import { downloadForensicPdf } from '../api';
import { useState } from 'react';

export interface ForensicFinding {
  technique: string;
  severity: string;
  evidence: string;
  explanation: string;
  recommendation: string;
  confidence: number;
}

export interface ForensicResults {
  task_id: string;
  status: string;
  output_dir: string;
  findings: ForensicFinding[];
  summary: string;
  risk_level: string;
  recommendations: string[];
  timestamp: string;
  model: string;
  analysis_time_seconds: number;
}

interface ForensicResultsProps {
  results: ForensicResults;
  onReset: () => void;
}

const SEVERITY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: 'rgba(220, 38, 38, 0.2)', text: '#ef4444', border: '#dc2626' },
  HIGH: { bg: 'rgba(234, 88, 12, 0.2)', text: '#ea580c', border: '#ea580c' },
  MEDIUM: { bg: 'rgba(202, 138, 4, 0.2)', text: '#ca8a04', border: '#ca8a04' },
  LOW: { bg: 'rgba(22, 163, 74, 0.2)', text: '#16a34a', border: '#16a34a' },
  UNKNOWN: { bg: 'rgba(107, 114, 128, 0.2)', text: '#6b7280', border: '#6b7280' },
};

const TECHNIQUE_ICONS: Record<string, string> = {
  timestomping: '⏰',
  shadow_deletion: '🗑️',
  ads: '📎',
  deletion: '❌',
  log_clearing: '📋',
  registry_tampering: '🔐',
  other: '❓',
};

const TECHNIQUE_LABELS: Record<string, string> = {
  timestomping: 'Timestamp Manipulation',
  shadow_deletion: 'Shadow Copy Deletion',
  ads: 'Alternate Data Streams',
  deletion: 'File Deletion/Wiping',
  log_clearing: 'Log Clearing',
  registry_tampering: 'Registry Tampering',
  other: 'Other Activity',
};

export function ForensicResults({ results, onReset }: ForensicResultsProps) {
  const [pdfDownloading, setPdfDownloading] = useState(false);
  const [pdfError, setPdfError] = useState<string | null>(null);
  
  const riskColor = SEVERITY_COLORS[results.risk_level] || SEVERITY_COLORS.UNKNOWN;
  
  const handleDownloadPdf = async () => {
    setPdfDownloading(true);
    setPdfError(null);
    try {
      await downloadForensicPdf(results.task_id);
    } catch (err) {
      setPdfError(err instanceof Error ? err.message : 'Failed to download PDF');
    } finally {
      setPdfDownloading(false);
    }
  };
  
  const findingsBySeverity = results.findings.reduce((acc, finding) => {
    const sev = finding.severity || 'UNKNOWN';
    if (!acc[sev]) acc[sev] = [];
    acc[sev].push(finding);
    return acc;
  }, {} as Record<string, ForensicFinding[]>);

  const criticalCount = findingsBySeverity['CRITICAL']?.length || 0;
  const highCount = findingsBySeverity['HIGH']?.length || 0;
  const mediumCount = findingsBySeverity['MEDIUM']?.length || 0;
  const lowCount = findingsBySeverity['LOW']?.length || 0;

  return (
    <div className="forensic-results fade-in">
      <div className="forensic-toolbar">
        <button className="btn btn-secondary" onClick={onReset}>
          <HardDrive size={16} />
          New Analysis
        </button>
        <button 
          className="btn btn-primary" 
          onClick={handleDownloadPdf}
          disabled={pdfDownloading}
        >
          {pdfDownloading ? (
            <Loader2 size={16} className="spin" />
          ) : (
            <Download size={16} />
          )}
          Export PDF Report
        </button>
      </div>
      {pdfError && (
        <div className="error-banner">
          {pdfError}
        </div>
      )}

      <div className="forensic-header">
        <div className="forensic-title-section">
          <FileSearch size={32} className="forensic-icon" />
          <div>
            <h1>Forensic Analysis Report</h1>
            <p className="forensic-meta">
              <Clock size={14} />
              {results.timestamp ? new Date(results.timestamp).toLocaleString() : 'N/A'}
              <span className="meta-separator">•</span>
              Analysis time: {results.analysis_time_seconds?.toFixed(1) || 0}s
              <span className="meta-separator">•</span>
              Model: {results.model || 'N/A'}
            </p>
          </div>
        </div>
        <div className="risk-badge-container">
          <div 
            className="risk-badge-large"
            style={{ 
              background: riskColor.bg, 
              borderColor: riskColor.border,
              color: riskColor.text 
            }}
          >
            <AlertTriangle size={20} />
            <span>{results.risk_level}</span>
          </div>
        </div>
      </div>

      <div className="forensic-output-dir">
        <FolderOpen size={18} />
        <span className="output-label">Artifacts saved to:</span>
        <code className="output-path">{results.output_dir}</code>
      </div>

      <div className="forensic-summary card">
        <h3>Summary</h3>
        <p>{results.summary}</p>
      </div>

      <div className="forensic-stats-grid">
        <div className="forensic-stat-card critical">
          <span className="stat-value">{criticalCount}</span>
          <span className="stat-label">Critical</span>
        </div>
        <div className="forensic-stat-card high">
          <span className="stat-value">{highCount}</span>
          <span className="stat-label">High</span>
        </div>
        <div className="forensic-stat-card medium">
          <span className="stat-value">{mediumCount}</span>
          <span className="stat-label">Medium</span>
        </div>
        <div className="forensic-stat-card low">
          <span className="stat-value">{lowCount}</span>
          <span className="stat-label">Low</span>
        </div>
      </div>

      <div className="forensic-findings-section">
        <h3>Findings ({results.findings.length} total)</h3>
        
        {results.findings.length === 0 ? (
          <div className="no-findings">
            <Shield size={48} />
            <h4>No Anti-Forensic Activity Detected</h4>
            <p>The analysis did not find evidence of anti-forensic techniques in this image.</p>
          </div>
        ) : (
          <div className="findings-list">
            {results.findings.map((finding, index) => {
              const sevColor = SEVERITY_COLORS[finding.severity] || SEVERITY_COLORS.UNKNOWN;
              return (
                <div 
                  key={index} 
                  className="finding-card"
                  style={{ borderLeftColor: sevColor.border }}
                >
                  <div className="finding-header">
                    <span className="finding-icon">
                      {TECHNIQUE_ICONS[finding.technique] || '🔍'}
                    </span>
                    <span className="finding-technique">
                      {TECHNIQUE_LABELS[finding.technique] || finding.technique}
                    </span>
                    <span 
                      className="finding-severity"
                      style={{ background: sevColor.bg, color: sevColor.text }}
                    >
                      {finding.severity}
                    </span>
                    <span className="finding-confidence">
                      {(finding.confidence * 100).toFixed(0)}% confidence
                    </span>
                  </div>
                  
                  <div className="finding-content">
                    <div className="finding-field">
                      <strong>Evidence:</strong>
                      <p>{finding.evidence}</p>
                    </div>
                    <div className="finding-field">
                      <strong>Explanation:</strong>
                      <p>{finding.explanation}</p>
                    </div>
                    <div className="finding-field">
                      <strong>Recommendation:</strong>
                      <p>{finding.recommendation}</p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {results.recommendations && results.recommendations.length > 0 && (
        <div className="forensic-recommendations card">
          <h3>Investigator Recommendations</h3>
          <ul>
            {results.recommendations.map((rec, index) => (
              <li key={index}>{rec}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
