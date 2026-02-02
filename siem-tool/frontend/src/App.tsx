import { useState, useCallback } from 'react';
import { 
   Upload, Shield, AlertTriangle, Activity, FileText, 
   Download, RefreshCw, ChevronDown, X, Search, Terminal,
   Layers, Clock, Target, Zap, TrendingUp
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar } from 'recharts';
import { parseLogsFromFile, parseLogsFromText, correlateMultipleFiles } from './api';
import type { ParseResponse, ParsedLogEntry, CorrelateResponse, AttackChain, TimelineEvent } from './types';
import { DynamicTable } from './DynamicTable';
import './App.css';

const SEVERITY_COLORS = {
  debug: '#64748b',
  info: '#3b82f6',
  warning: '#eab308',
  error: '#ef4444',
  critical: '#a855f7',
  unknown: '#94a3b8',
  low: '#22c55e',
  medium: '#f59e0b',
  high: '#ef4444',
};

const ATTACK_TYPE_ICONS: Record<string, string> = {
  bruteforce: '🔓',
  password_spray: '💨',
  credential_stuffing: '🔑',
  mfa_bypass: '🛡️',
  mfa_fatigue: '😴',
  session_hijacking: '🎭',
  privilege_escalation: '⬆️',
  lateral_movement: '↔️',
  data_exfiltration: '📤',
  sql_injection: '💉',
  xss_attack: '🌐',
  path_traversal: '📁',
  command_injection: '⌨️',
  port_scan: '🔍',
  ddos: '🌊',
  reconnaissance: '👁️',
  malware_activity: '🦠',
  c2_communication: '📡',
  insider_threat: '👤',
  account_takeover: '🔐',
  anomaly: '📊',
  unknown: '❓',
};

const STAGE_COLORS: Record<string, string> = {
  reconnaissance: '#64748b',
  initial_access: '#3b82f6',
  execution: '#8b5cf6',
  persistence: '#f59e0b',
  privilege_escalation: '#ef4444',
  lateral_movement: '#ec4899',
  exfiltration: '#dc2626',
  complete: '#7c3aed',
};

function App() {
  const [mode, setMode] = useState<'single' | 'multi'>('single');
  const [data, setData] = useState<ParseResponse | null>(null);
  const [correlationData, setCorrelationData] = useState<CorrelateResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'logs' | 'alerts' | 'attacks' | 'timeline' | 'stats'>('logs');
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [selectedEntry, setSelectedEntry] = useState<ParsedLogEntry | null>(null);
  const [selectedChain, setSelectedChain] = useState<AttackChain | null>(null);
  const [uploadedFiles, setUploadedFiles] = useState<File[]>([]);

  const handleFileUpload = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || []);
    if (files.length === 0) return;

    if (mode === 'multi' || files.length > 1) {
      setUploadedFiles(prev => [...prev, ...files]);
      return;
    }

    // Single file mode
    setLoading(true);
    setError(null);

    try {
      const result = await parseLogsFromFile(files[0]);
      setData(result);
      setCorrelationData(null);
      setActiveTab('logs');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to parse logs');
    } finally {
      setLoading(false);
    }
  }, [mode]);

  const handleRunCorrelation = useCallback(async () => {
    if (uploadedFiles.length === 0) return;

    setLoading(true);
    setError(null);

    try {
      const result = await correlateMultipleFiles(uploadedFiles);
      setCorrelationData(result);
      setData(null);
      setActiveTab('attacks');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to correlate logs');
    } finally {
      setLoading(false);
    }
  }, [uploadedFiles]);

  const handleDrop = useCallback(async (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    const files = Array.from(e.dataTransfer.files || []);
    if (files.length === 0) return;

    if (mode === 'multi' || files.length > 1) {
      setUploadedFiles(prev => [...prev, ...files]);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const result = await parseLogsFromFile(files[0]);
      setData(result);
      setCorrelationData(null);
      setActiveTab('logs');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to parse logs');
    } finally {
      setLoading(false);
    }
  }, [mode]);

  const handlePaste = useCallback(async (e: React.ClipboardEvent) => {
    const text = e.clipboardData.getData('text');
    if (!text || text.length < 10) return;

    setLoading(true);
    setError(null);

    try {
      const result = await parseLogsFromText(text);
      setData(result);
      setCorrelationData(null);
      setActiveTab('logs');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to parse logs');
    } finally {
      setLoading(false);
    }
  }, []);

  const removeFile = (index: number) => {
    setUploadedFiles(prev => prev.filter((_, i) => i !== index));
  };

  const resetAll = () => {
    setData(null);
    setCorrelationData(null);
    setUploadedFiles([]);
    setSelectedEntry(null);
    setSelectedChain(null);
    setError(null);
  };

  const filteredEntries = (data?.entries || []).filter(entry => {
    const matchesSearch = searchQuery === '' || 
      entry.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
      entry.source.ip?.includes(searchQuery) ||
      entry.user?.name?.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesSeverity = severityFilter === 'all' || entry.severity === severityFilter;
    
    return matchesSearch && matchesSeverity;
  });

  const exportToCSV = useCallback(() => {
    if (!data && !correlationData) return;
    
    const entries = data?.entries || [];
    const headers = ['timestamp', 'logType', 'severity', 'source_ip', 'user', 'action', 'outcome', 'message'];
    const rows = entries.map(e => [
      e.timestamp || '',
      e.logType,
      e.severity,
      e.source.ip || '',
      e.user?.name || '',
      e.action || '',
      e.outcome || '',
      `"${e.message.replace(/"/g, '""')}"`,
    ]);
    
    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `siem-logs-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
  }, [data, correlationData]);

  const exportToJSON = useCallback(() => {
    const exportData = correlationData || data;
    if (!exportData) return;
    
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `siem-analysis-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
  }, [data, correlationData]);

  const hasData = data || correlationData;
  const attackChains = correlationData?.correlation?.attackChains || [];
  const timeline = correlationData?.correlation?.timeline || [];
  const summary = correlationData?.correlation?.summary;

  return (
    <div className="app" onPaste={handlePaste}>
      {/* Header */}
      <header className="header">
        <div className="header-content container">
          <div className="logo">
            <Shield size={28} />
            <span>FreeKhana SIEM</span>
          </div>
          <div className="header-stats">
            {hasData && (
              <>
                {summary && (
                  <>
                    <div className="stat risk-stat" style={{ 
                      borderColor: summary.riskScore > 70 ? '#ef4444' : summary.riskScore > 40 ? '#f59e0b' : '#22c55e' 
                    }}>
                      <span className="stat-value">{summary.riskScore}</span>
                      <span className="stat-label">Risk Score</span>
                    </div>
                    <div className="stat">
                      <span className="stat-value" style={{ color: attackChains.length > 0 ? '#ef4444' : 'inherit' }}>
                        {attackChains.length}
                      </span>
                      <span className="stat-label">Attack Chains</span>
                    </div>
                  </>
                )}
                {data && (
                  <>
                    <div className="stat">
                      <span className="stat-value">{data.totalLines}</span>
                      <span className="stat-label">Total Lines</span>
                    </div>
                    <div className="stat">
                      <span className="stat-value">{data.parsedLines}</span>
                      <span className="stat-label">Parsed</span>
                    </div>
                  </>
                )}
              </>
            )}
          </div>
        </div>
      </header>

      <main className="main container">
        {/* Upload Section */}
        {!hasData && (
          <div className="upload-wrapper fade-in">
            {/* Mode Toggle */}
            <div className="mode-toggle">
              <button 
                className={`mode-btn ${mode === 'single' ? 'active' : ''}`}
                onClick={() => setMode('single')}
              >
                <FileText size={18} />
                Single Log
              </button>
              <button 
                className={`mode-btn ${mode === 'multi' ? 'active' : ''}`}
                onClick={() => setMode('multi')}
              >
                <Layers size={18} />
                Multi-Log Correlation
              </button>
            </div>

            <div 
              className="upload-section card"
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
            >
              <div className="upload-icon">
                {mode === 'single' ? <Upload size={48} /> : <Layers size={48} />}
              </div>
              <h2>{mode === 'single' ? 'Upload Log File' : 'Upload Multiple Log Files'}</h2>
              <p>
                {mode === 'single' 
                  ? 'Drag & drop your log file here, paste log content, or click to browse'
                  : 'Upload auth, web, database, firewall, and system logs for cross-correlation analysis'
                }
              </p>
              <p className="supported-types">
                Supports: Database, Webserver, System, SSH, Firewall, Network, Mail logs (56+ formats)
              </p>
              
              <input
                type="file"
                id="file-upload"
                onChange={handleFileUpload}
                accept=".log,.txt,.json"
                multiple={mode === 'multi'}
                hidden
              />
              <label htmlFor="file-upload" className="btn btn-primary">
                <FileText size={18} />
                {mode === 'single' ? 'Choose File' : 'Add Files'}
              </label>

              {/* Multi-file list */}
              {mode === 'multi' && uploadedFiles.length > 0 && (
                <div className="uploaded-files">
                  <h4>Uploaded Files ({uploadedFiles.length})</h4>
                  <div className="file-list">
                    {uploadedFiles.map((file, index) => (
                      <div key={index} className="file-item">
                        <FileText size={16} />
                        <span>{file.name}</span>
                        <span className="file-size">{(file.size / 1024).toFixed(1)} KB</span>
                        <button onClick={() => removeFile(index)} className="remove-btn">
                          <X size={14} />
                        </button>
                      </div>
                    ))}
                  </div>
                  <button 
                    className="btn btn-primary run-correlation-btn"
                    onClick={handleRunCorrelation}
                    disabled={loading}
                  >
                    <Zap size={18} />
                    Run ML Correlation Analysis
                  </button>
                </div>
              )}

              {loading && (
                <div className="loading">
                  <RefreshCw size={24} className="spin" />
                  <span>{mode === 'multi' ? 'Running ML correlation analysis...' : 'Parsing logs...'}</span>
                </div>
              )}
              {error && (
                <div className="error-message">
                  <AlertTriangle size={18} />
                  {error}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Dashboard */}
        {hasData && (
          <div className="dashboard fade-in">
            {/* Toolbar */}
            <div className="toolbar">
              <div className="tabs">
                {correlationData && (
                  <>
                    <button 
                      className={`tab ${activeTab === 'attacks' ? 'active' : ''}`}
                      onClick={() => setActiveTab('attacks')}
                    >
                      <Target size={16} />
                      Attack Chains ({attackChains.length})
                    </button>
                    <button 
                      className={`tab ${activeTab === 'timeline' ? 'active' : ''}`}
                      onClick={() => setActiveTab('timeline')}
                    >
                      <Clock size={16} />
                      Timeline
                    </button>
                  </>
                )}
                {data && (
                  <>
                    <button 
                      className={`tab ${activeTab === 'logs' ? 'active' : ''}`}
                      onClick={() => setActiveTab('logs')}
                    >
                      <Terminal size={16} />
                      Logs ({data.entries.length})
                    </button>
                    <button 
                      className={`tab ${activeTab === 'alerts' ? 'active' : ''}`}
                      onClick={() => setActiveTab('alerts')}
                    >
                      <AlertTriangle size={16} />
                      Alerts ({data.alerts.length})
                    </button>
                  </>
                )}
                <button 
                  className={`tab ${activeTab === 'stats' ? 'active' : ''}`}
                  onClick={() => setActiveTab('stats')}
                >
                  <Activity size={16} />
                  Analytics
                </button>
              </div>
              <div className="toolbar-actions">
                <button className="btn btn-secondary" onClick={resetAll}>
                  <Upload size={16} />
                  New Analysis
                </button>
                <div className="dropdown">
                  <button className="btn btn-secondary">
                    <Download size={16} />
                    Export
                    <ChevronDown size={14} />
                  </button>
                  <div className="dropdown-menu">
                    <button onClick={exportToCSV}>Export as CSV</button>
                    <button onClick={exportToJSON}>Export as JSON</button>
                  </div>
                </div>
              </div>
            </div>

            {/* Summary KPIs for Correlation */}
            {summary && (
              <div className="kpi-grid correlation-kpis">
                <div className="kpi-card risk-card" style={{ 
                  borderLeft: `4px solid ${summary.riskScore > 70 ? '#ef4444' : summary.riskScore > 40 ? '#f59e0b' : '#22c55e'}` 
                }}>
                  <div className="kpi-icon" style={{ 
                    background: summary.riskScore > 70 ? 'rgba(239, 68, 68, 0.2)' : summary.riskScore > 40 ? 'rgba(245, 158, 11, 0.2)' : 'rgba(34, 197, 94, 0.2)' 
                  }}>
                    <TrendingUp size={24} color={summary.riskScore > 70 ? '#ef4444' : summary.riskScore > 40 ? '#f59e0b' : '#22c55e'} />
                  </div>
                  <div className="kpi-content">
                    <div className="kpi-value">{summary.riskScore}/100</div>
                    <div className="kpi-label">Risk Score</div>
                  </div>
                </div>
                <div className="kpi-card">
                  <div className="kpi-icon" style={{ background: 'rgba(239, 68, 68, 0.2)' }}>
                    <Target size={24} color="#ef4444" />
                  </div>
                  <div className="kpi-content">
                    <div className="kpi-value">{summary.criticalAlerts}</div>
                    <div className="kpi-label">Critical Alerts</div>
                  </div>
                </div>
                <div className="kpi-card">
                  <div className="kpi-icon" style={{ background: 'rgba(34, 197, 94, 0.2)' }}>
                    <Shield size={24} color="#22c55e" />
                  </div>
                  <div className="kpi-content">
                    <div className="kpi-value">{summary.falsePositivesFiltered}</div>
                    <div className="kpi-label">False Positives Filtered</div>
                  </div>
                </div>
                <div className="kpi-card">
                  <div className="kpi-icon" style={{ background: 'rgba(59, 130, 246, 0.2)' }}>
                    <Activity size={24} color="#3b82f6" />
                  </div>
                  <div className="kpi-content">
                    <div className="kpi-value">{correlationData?.correlation?.totalEvents || 0}</div>
                    <div className="kpi-label">Total Events</div>
                  </div>
                </div>
              </div>
            )}

            {/* KPI Cards for single file */}
            {data && !correlationData && (
              <div className="kpi-grid">
                <div className="kpi-card">
                  <div className="kpi-icon" style={{ background: 'rgba(59, 130, 246, 0.2)' }}>
                    <FileText size={24} color="#3b82f6" />
                  </div>
                  <div className="kpi-content">
                    <div className="kpi-value">{data.detectedType}</div>
                    <div className="kpi-label">Detected Log Type</div>
                  </div>
                </div>
                <div className="kpi-card">
                  <div className="kpi-icon" style={{ background: 'rgba(34, 197, 94, 0.2)' }}>
                    <Activity size={24} color="#22c55e" />
                  </div>
                  <div className="kpi-content">
                    <div className="kpi-value">{Math.round((data.parsedLines / data.totalLines) * 100)}%</div>
                    <div className="kpi-label">Parse Success Rate</div>
                  </div>
                </div>
                <div className="kpi-card">
                  <div className="kpi-icon" style={{ background: 'rgba(239, 68, 68, 0.2)' }}>
                    <AlertTriangle size={24} color="#ef4444" />
                  </div>
                  <div className="kpi-content">
                    <div className="kpi-value">{data.stats.bySeverity.error || 0}</div>
                    <div className="kpi-label">Errors</div>
                  </div>
                </div>
                <div className="kpi-card">
                  <div className="kpi-icon" style={{ background: 'rgba(234, 179, 8, 0.2)' }}>
                    <Shield size={24} color="#eab308" />
                  </div>
                  <div className="kpi-content">
                    <div className="kpi-value">{data.alerts.filter(a => a.severity === 'high' || a.severity === 'critical').length}</div>
                    <div className="kpi-label">Critical Alerts</div>
                  </div>
                </div>
              </div>
            )}

            {/* Attack Chains Tab */}
            {activeTab === 'attacks' && correlationData && (
              <div className="attacks-section">
                {attackChains.length === 0 ? (
                  <div className="empty-state">
                    <Shield size={48} />
                    <h3>No Attack Chains Detected</h3>
                    <p>The ML analysis did not identify any coordinated attack patterns across your logs.</p>
                  </div>
                ) : (
                  <>
                    {/* Recommendations */}
                    {correlationData.correlation?.recommendations?.length > 0 && (
                      <div className="recommendations-panel">
                        <h3>Recommendations</h3>
                        <ul>
                          {correlationData.correlation.recommendations.slice(0, 5).map((rec, i) => (
                            <li key={i}>{rec}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    <div className="attack-chains-list">
                      {attackChains.map((chain) => (
                        <div 
                          key={chain.id} 
                          className={`attack-chain-card severity-${chain.prediction.confidence >= 0.8 ? 'critical' : chain.prediction.confidence >= 0.6 ? 'high' : 'medium'}`}
                          onClick={() => setSelectedChain(chain)}
                        >
                          <div className="chain-header">
                            <span className="attack-icon">{ATTACK_TYPE_ICONS[chain.attackType] || '?'}</span>
                            <div className="chain-title">
                              <h4>{chain.attackType.replace(/_/g, ' ').toUpperCase()}</h4>
                              <span className="chain-stage" style={{ background: STAGE_COLORS[chain.stage] }}>
                                {chain.stage.replace(/_/g, ' ')}
                              </span>
                            </div>
                            <div className="chain-confidence">
                              <div className="confidence-bar">
                                <div 
                                  className="confidence-fill" 
                                  style={{ 
                                    width: `${chain.prediction.confidence * 100}%`,
                                    background: chain.prediction.confidence >= 0.8 ? '#ef4444' : chain.prediction.confidence >= 0.6 ? '#f59e0b' : '#3b82f6'
                                  }}
                                ></div>
                              </div>
                              <span>{(chain.prediction.confidence * 100).toFixed(0)}% confidence</span>
                            </div>
                          </div>
                          
                          <div className="chain-details">
                            <div className="chain-meta">
                              <div className="meta-item">
                                <span className="meta-label">Events</span>
                                <span className="meta-value">{chain.events.length}</span>
                              </div>
                              <div className="meta-item">
                                <span className="meta-label">Source IPs</span>
                                <span className="meta-value">{chain.sourceIps.length}</span>
                              </div>
                              <div className="meta-item">
                                <span className="meta-label">Target Users</span>
                                <span className="meta-value">{chain.targetUsers.length}</span>
                              </div>
                              <div className="meta-item">
                                <span className="meta-label">Duration</span>
                                <span className="meta-value">
                                  {formatDuration(new Date(chain.endTime).getTime() - new Date(chain.startTime).getTime())}
                                </span>
                              </div>
                            </div>

                            <div className="chain-explanation">
                              {chain.prediction.explanation.slice(0, 2).map((exp, i) => (
                                <p key={i}>{exp}</p>
                              ))}
                            </div>

                            <div className="chain-mitre">
                              <span className="mitre-label">MITRE ATT&CK:</span>
                              {chain.mitreTactics.slice(0, 2).map((tactic, i) => (
                                <span key={i} className="mitre-tag">{tactic}</span>
                              ))}
                            </div>
                          </div>

                          <div className="chain-recommendation">
                            <AlertTriangle size={14} />
                            {chain.recommendation.substring(0, 150)}...
                          </div>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </div>
            )}

            {/* Timeline Tab */}
            {activeTab === 'timeline' && correlationData && (
              <div className="timeline-section">
                <div className="timeline-chart">
                  <h3>Event Timeline</h3>
                  <ResponsiveContainer width="100%" height={200}>
                    <BarChart data={aggregateTimelineData(timeline)}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis dataKey="time" stroke="#94a3b8" tick={{ fontSize: 10 }} />
                      <YAxis stroke="#94a3b8" />
                      <Tooltip 
                        contentStyle={{ background: '#1e293b', border: '1px solid #334155' }}
                        labelStyle={{ color: '#f1f5f9' }}
                      />
                      <Bar dataKey="normal" fill="#3b82f6" stackId="a" name="Normal" />
                      <Bar dataKey="anomaly" fill="#ef4444" stackId="a" name="Anomaly" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <div className="timeline-list">
                  {timeline.slice(0, 100).map((event) => (
                    <div 
                      key={event.id} 
                      className={`timeline-item ${event.isAnomaly ? 'anomaly' : ''}`}
                    >
                      <div className="timeline-time">
                        {new Date(event.timestamp).toLocaleTimeString()}
                      </div>
                      <div className={`timeline-dot severity-${event.severity}`}></div>
                      <div className="timeline-content">
                        <div className="timeline-header">
                          <span className={`timeline-source badge-${event.logSource}`}>{event.logSource}</span>
                          <span className="timeline-title">{event.title}</span>
                          {event.isAnomaly && (
                            <span className="anomaly-badge">
                              Anomaly ({(event.anomalyScore * 100).toFixed(0)}%)
                            </span>
                          )}
                        </div>
                        <p className="timeline-desc">{event.description.substring(0, 100)}</p>
                        {event.sourceIp && <span className="timeline-ip">{event.sourceIp}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Logs Tab */}
            {activeTab === 'logs' && data && (
              <div className="logs-section">
                {/* Filters */}
                <div className="filters">
                  <div className="search-box">
                    <Search size={18} />
                    <input
                      type="text"
                      placeholder="Search logs..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                    />
                    {searchQuery && (
                      <button onClick={() => setSearchQuery('')}>
                        <X size={16} />
                      </button>
                    )}
                  </div>
                  <select 
                    value={severityFilter} 
                    onChange={(e) => setSeverityFilter(e.target.value)}
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="error">Error</option>
                    <option value="warning">Warning</option>
                    <option value="info">Info</option>
                    <option value="debug">Debug</option>
                  </select>
                </div>

                {/* Dynamic Logs Table */}
                <DynamicTable
                  entries={filteredEntries.slice(0, 500)}
                  detectedType={data?.detectedType || 'unknown'}
                  onEntryClick={setSelectedEntry}
                />
                {filteredEntries.length > 500 && (
                  <div className="table-info">Showing 500 of {filteredEntries.length} entries</div>
                )}
              </div>
            )}

            {/* Alerts Tab */}
            {activeTab === 'alerts' && data && (
              <div className="alerts-section">
                {data.alerts.length === 0 ? (
                  <div className="empty-state">
                    <Shield size={48} />
                    <h3>No Alerts Detected</h3>
                    <p>The analysis did not find any security concerns in the provided logs.</p>
                  </div>
                ) : (
                  <div className="alerts-list">
                    {data.alerts.map((alert) => (
                      <div key={alert.id} className={`alert-card severity-${alert.severity}`}>
                        <div className="alert-header">
                          <span className="alert-icon">{ATTACK_TYPE_ICONS[alert.type] || '?'}</span>
                          <span className="alert-title">{alert.title}</span>
                          <span className={`badge badge-${alert.severity === 'high' || alert.severity === 'critical' ? 'error' : 'warning'}`}>
                            {alert.severity}
                          </span>
                        </div>
                        <p className="alert-description">{alert.description}</p>
                        <div className="alert-meta">
                          <span>Confidence: {alert.confidence}</span>
                          {alert.sourceIps.length > 0 && (
                            <span>Sources: {alert.sourceIps.join(', ')}</span>
                          )}
                          {alert.targetUsers.length > 0 && (
                            <span>Users: {alert.targetUsers.join(', ')}</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Stats Tab */}
            {activeTab === 'stats' && (
              <div className="stats-section">
                {/* Attack Types Detected (for correlation) */}
                {summary && summary.attackTypesDetected.length > 0 && (
                  <div className="chart-card full-width">
                    <h3>Attack Types Detected</h3>
                    <div className="attack-types-grid">
                      {summary.attackTypesDetected.map((type) => (
                        <div key={type} className="attack-type-chip">
                          <span className="attack-type-icon">{ATTACK_TYPE_ICONS[type]}</span>
                          <span>{type.replace(/_/g, ' ')}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Timeline Chart */}
                {(data?.stats.timeline || []).length > 0 && (
                  <div className="chart-card">
                    <h3>Event Timeline</h3>
                    <ResponsiveContainer width="100%" height={250}>
                      <LineChart data={data?.stats.timeline}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                        <XAxis dataKey="time" stroke="#94a3b8" tick={{ fontSize: 11 }} />
                        <YAxis stroke="#94a3b8" />
                        <Tooltip 
                          contentStyle={{ background: '#1e293b', border: '1px solid #334155' }}
                          labelStyle={{ color: '#f1f5f9' }}
                        />
                        <Line type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                )}

                <div className="stats-grid">
                  {/* Severity Distribution */}
                  <div className="chart-card">
                    <h3>Severity Distribution</h3>
                    <ResponsiveContainer width="100%" height={200}>
                      <PieChart>
                        <Pie
                          data={Object.entries(data?.stats.bySeverity || correlationData?.stats.bySeverity || {}).map(([name, value]) => ({ name, value }))}
                          cx="50%"
                          cy="50%"
                          innerRadius={50}
                          outerRadius={80}
                          paddingAngle={2}
                          dataKey="value"
                        >
                          {Object.entries(data?.stats.bySeverity || correlationData?.stats.bySeverity || {}).map(([severity]) => (
                            <Cell key={severity} fill={SEVERITY_COLORS[severity as keyof typeof SEVERITY_COLORS] || '#94a3b8'} />
                          ))}
                        </Pie>
                        <Tooltip />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="legend">
                      {Object.entries(data?.stats.bySeverity || correlationData?.stats.bySeverity || {}).map(([severity, count]) => (
                        <div key={severity} className="legend-item">
                          <span className="legend-color" style={{ background: SEVERITY_COLORS[severity as keyof typeof SEVERITY_COLORS] }}></span>
                          <span>{severity}: {count}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Top Sources */}
                  <div className="chart-card">
                    <h3>Top Source IPs</h3>
                    <div className="top-list">
                      {(summary?.mostActiveSourceIps || data?.stats.topSources || []).slice(0, 10).map((item, i) => {
                        const ip = 'ip' in item ? item.ip : '';
                        const threatScore = 'threatScore' in item ? (item.threatScore as number) : 0;
                        return (
                          <div key={ip || i} className="top-item">
                            <span className="rank">{i + 1}</span>
                            <span className="mono">{ip}</span>
                            <span className="count">{item.count}</span>
                            {threatScore > 0 && (
                              <span className="threat-score" style={{ 
                                color: threatScore > 0.7 ? '#ef4444' : threatScore > 0.4 ? '#f59e0b' : '#22c55e' 
                              }}>
                                {(threatScore * 100).toFixed(0)}% threat
                              </span>
                            )}
                          </div>
                        );
                      })}
                      {(summary?.mostActiveSourceIps || data?.stats.topSources || []).length === 0 && (
                        <div className="empty-list">No IP addresses found</div>
                      )}
                    </div>
                  </div>

                  {/* Top Users */}
                  <div className="chart-card">
                    <h3>Top Users</h3>
                    <div className="top-list">
                      {(summary?.mostTargetedUsers || data?.stats.topUsers || []).slice(0, 10).map((item, i) => (
                        <div key={item.user} className="top-item">
                          <span className="rank">{i + 1}</span>
                          <span>{item.user}</span>
                          <span className="count">{item.count}</span>
                        </div>
                      ))}
                      {(summary?.mostTargetedUsers || data?.stats.topUsers || []).length === 0 && (
                        <div className="empty-list">No users found</div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </main>

      {/* Detail Modal for Log Entry */}
      {selectedEntry && (
        <div className="modal-overlay" onClick={() => setSelectedEntry(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Log Entry Details</h3>
              <button onClick={() => setSelectedEntry(null)}>
                <X size={20} />
              </button>
            </div>
            <div className="modal-body">
              <div className="detail-grid">
                <div className="detail-item">
                  <label>Timestamp</label>
                  <span className="mono">{selectedEntry.timestamp || 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Log Type</label>
                  <span className="badge badge-info">{selectedEntry.logType}</span>
                </div>
                <div className="detail-item">
                  <label>Severity</label>
                  <span className={`badge badge-${selectedEntry.severity === 'error' || selectedEntry.severity === 'critical' ? 'error' : selectedEntry.severity === 'warning' ? 'warning' : 'info'}`}>
                    {selectedEntry.severity}
                  </span>
                </div>
                <div className="detail-item">
                  <label>Outcome</label>
                  <span className={`badge ${selectedEntry.outcome === 'success' ? 'badge-success' : selectedEntry.outcome === 'failure' ? 'badge-error' : 'badge-info'}`}>
                    {selectedEntry.outcome || 'unknown'}
                  </span>
                </div>
                <div className="detail-item">
                  <label>Source IP</label>
                  <span className="mono">{selectedEntry.source.ip || 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Source Host</label>
                  <span>{selectedEntry.source.hostname || 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Service</label>
                  <span>{selectedEntry.source.service || 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>User</label>
                  <span>{selectedEntry.user?.name || 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Action</label>
                  <span>{selectedEntry.action || 'N/A'}</span>
                </div>
                <div className="detail-item full-width">
                  <label>Tags</label>
                  <div className="tags">
                    {selectedEntry.tags.map(tag => (
                      <span key={tag} className="tag">{tag}</span>
                    ))}
                  </div>
                </div>
                <div className="detail-item full-width">
                  <label>Message</label>
                  <pre className="mono">{selectedEntry.message}</pre>
                </div>
                <div className="detail-item full-width">
                  <label>Raw Log</label>
                  <pre className="mono raw-log">{selectedEntry.rawLine}</pre>
                </div>
                {Object.keys(selectedEntry.fields).length > 0 && (
                  <div className="detail-item full-width">
                    <label>Parsed Fields</label>
                    <pre className="mono">{JSON.stringify(selectedEntry.fields, null, 2)}</pre>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Attack Chain Detail Modal */}
      {selectedChain && (
        <div className="modal-overlay" onClick={() => setSelectedChain(null)}>
          <div className="modal modal-large" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>
                <span className="attack-icon">{ATTACK_TYPE_ICONS[selectedChain.attackType]}</span>
                Attack Chain Details
              </h3>
              <button onClick={() => setSelectedChain(null)}>
                <X size={20} />
              </button>
            </div>
            <div className="modal-body">
              <div className="chain-detail-header">
                <div className="chain-type">
                  <h4>{selectedChain.attackType.replace(/_/g, ' ').toUpperCase()}</h4>
                  <span className="chain-stage" style={{ background: STAGE_COLORS[selectedChain.stage] }}>
                    {selectedChain.stage.replace(/_/g, ' ')}
                  </span>
                </div>
                <div className="chain-confidence-large">
                  <span className="confidence-value">{(selectedChain.prediction.confidence * 100).toFixed(0)}%</span>
                  <span className="confidence-label">Confidence</span>
                </div>
              </div>

              <div className="chain-info-grid">
                <div className="info-section">
                  <h5>Time Range</h5>
                  <p>{new Date(selectedChain.startTime).toLocaleString()} - {new Date(selectedChain.endTime).toLocaleString()}</p>
                </div>
                <div className="info-section">
                  <h5>Source IPs ({selectedChain.sourceIps.length})</h5>
                  <div className="ip-list">
                    {selectedChain.sourceIps.map(ip => (
                      <span key={ip} className="ip-tag">{ip}</span>
                    ))}
                  </div>
                </div>
                <div className="info-section">
                  <h5>Target Users ({selectedChain.targetUsers.length})</h5>
                  <div className="user-list">
                    {selectedChain.targetUsers.map(user => (
                      <span key={user} className="user-tag">{user}</span>
                    ))}
                  </div>
                </div>
              </div>

              <div className="chain-explanation-section">
                <h5>ML Analysis</h5>
                <ul>
                  {selectedChain.prediction.explanation.map((exp, i) => (
                    <li key={i}>{exp}</li>
                  ))}
                </ul>
              </div>

              <div className="chain-mitre-section">
                <h5>MITRE ATT&CK Mapping</h5>
                <div className="mitre-tags">
                  {selectedChain.mitreTactics.map((tactic, i) => (
                    <span key={i} className="mitre-tactic">{tactic}</span>
                  ))}
                </div>
                <div className="mitre-tags">
                  {selectedChain.mitreTechniques.map((tech, i) => (
                    <span key={i} className="mitre-technique">{tech}</span>
                  ))}
                </div>
              </div>

              <div className="chain-recommendation-section">
                <h5>Recommendation</h5>
                <p>{selectedChain.recommendation}</p>
              </div>

              <div className="chain-events-section">
                <h5>Related Events ({selectedChain.events.length})</h5>
                <div className="events-list">
                  {selectedChain.events.slice(0, 20).map(event => (
                    <div key={event.id} className="event-item">
                      <span className="event-time">{new Date(event.timestamp).toLocaleTimeString()}</span>
                      <span className={`event-source badge-${event.logSource}`}>{event.logSource}</span>
                      <span className="event-message">{event.message.substring(0, 80)}</span>
                      <span className="event-score">{(event.correlationScore * 100).toFixed(0)}%</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Helper functions
function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(0)}s`;
  if (ms < 3600000) return `${(ms / 60000).toFixed(0)}m`;
  return `${(ms / 3600000).toFixed(1)}h`;
}

function aggregateTimelineData(timeline: TimelineEvent[]): Array<{ time: string; normal: number; anomaly: number }> {
  const grouped = new Map<string, { normal: number; anomaly: number }>();
  
  for (const event of timeline) {
    const minute = event.timestamp.substring(0, 16);
    if (!grouped.has(minute)) {
      grouped.set(minute, { normal: 0, anomaly: 0 });
    }
    const data = grouped.get(minute)!;
    if (event.isAnomaly) {
      data.anomaly++;
    } else {
      data.normal++;
    }
  }
  
  return Array.from(grouped.entries())
    .map(([time, data]) => ({ time: time.substring(11), ...data }))
    .sort((a, b) => a.time.localeCompare(b.time));
}

export default App;
