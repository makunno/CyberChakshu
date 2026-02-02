import React, { useRef, useEffect, useState } from 'react';
import type { ParsedLogEntry } from '../types';

interface Column {
  key: string;
  label: string;
  width: number;
  visible: boolean;
  getValue: (entry: ParsedLogEntry) => string | JSX.Element;
  sortable: boolean;
}

const MIN_COLUMN_WIDTH = 100;

const getColumnsForLogType = (logType: string, sampleEntries: ParsedLogEntry[]): Column[] => {
  const columns: Column[] = [
    { key: 'timestamp', label: 'Timestamp', width: 180, visible: true, sortable: true, getValue: (e) => e.timestamp || '-' },
    { key: 'severity', label: 'Severity', width: 100, visible: true, sortable: true, getValue: (e) => e.severity },
    { key: 'message', label: 'Message', width: MIN_COLUMN_WIDTH, visible: true, sortable: false, getValue: (e) => e.message },
  ];

  const lowerType = logType.toLowerCase();

  // Check first entry to see what fields are available
  const hasIp = sampleEntries.some(e => e.source?.ip);
  const hasPath = sampleEntries.some(e => e.fields?.path || e.fields?.url);
  const hasStatus = sampleEntries.some(e => e.fields?.status !== undefined);
  const hasSize = sampleEntries.some(e => e.fields?.size !== undefined || e.fields?.bytes !== undefined);
  const hasMethod = sampleEntries.some(e => e.action || e.fields?.method);
  const hasUser = sampleEntries.some(e => e.user?.name);
  const hasPid = sampleEntries.some(e => e.source?.pid);
  const hasHostname = sampleEntries.some(e => e.source?.hostname);

  if (lowerType.includes('ssh') || lowerType.includes('auth') || lowerType.includes('sshd')) {
    if (hasIp) columns.push({ key: 'source_ip', label: 'Source IP', width: 140, visible: true, sortable: true, getValue: (e) => e.source.ip || '-' });
    if (hasUser) columns.push({ key: 'user', label: 'User', width: 140, visible: true, sortable: true, getValue: (e) => e.user?.name || '-' });
    columns.push({ key: 'outcome', label: 'Outcome', width: 100, visible: true, sortable: true, getValue: (e) => e.outcome || '-' });
    columns.push({ key: 'action', label: 'Action', width: 120, visible: true, sortable: true, getValue: (e) => e.action || '-' });
  } else if (lowerType.includes('mysql') || lowerType.includes('postgres') || lowerType.includes('oracle') || lowerType.includes('mongodb') || lowerType.includes('sqlserver') || lowerType.includes('database')) {
    if (hasHostname) columns.push({ key: 'source_hostname', label: 'Host', width: 140, visible: true, sortable: true, getValue: (e) => e.source.hostname || '-' });
    columns.push({ key: 'source_service', label: 'Service', width: 120, visible: true, sortable: true, getValue: (e) => e.source.service || '-' });
    if (hasPid) columns.push({ key: 'source_pid', label: 'PID', width: 80, visible: true, sortable: true, getValue: (e) => e.source.pid?.toString() || '-' });
  } else if (lowerType.includes('apache') || lowerType.includes('nginx') || lowerType.includes('iis') || lowerType.includes('django') || lowerType.includes('flask') || lowerType.includes('express') || lowerType.includes('laravel') || lowerType.includes('rails') || lowerType.includes('gunicorn') || lowerType.includes('uvicorn') || lowerType.includes('web')) {
    if (hasIp) columns.push({ key: 'source_ip', label: 'IP', width: 130, visible: true, sortable: true, getValue: (e) => e.source.ip || '-' });
    if (hasMethod) columns.push({ key: 'action', label: 'Method', width: 90, visible: true, sortable: true, getValue: (e) => e.action || e.fields.method || '-' });
    if (hasPath) columns.push({ key: 'fields_path', label: 'Endpoint', width: 200, visible: true, sortable: true, getValue: (e) => e.fields.path || e.fields.url || e.fields.endpoint || '-' });
    if (hasStatus) columns.push({ key: 'fields_status', label: 'Status', width: 80, visible: true, sortable: true, getValue: (e) => e.fields.status?.toString() || '-' });
    if (hasSize) columns.push({ key: 'fields_size', label: 'Size', width: 90, visible: true, sortable: true, getValue: (e) => {
      const size = e.fields.size !== undefined ? e.fields.size : e.fields.bytes;
      return size !== undefined ? size.toString() : '-';
    }});
  } else if (lowerType.includes('postfix') || lowerType.includes('sendmail') || lowerType.includes('exim') || lowerType.includes('dovecot') || lowerType.includes('exchange') || lowerType.includes('mail') || lowerType.includes('smtp')) {
    if (hasHostname) columns.push({ key: 'source_hostname', label: 'Host', width: 140, visible: true, sortable: true, getValue: (e) => e.source.hostname || '-' });
    columns.push({ key: 'source_service', label: 'Service', width: 120, visible: true, sortable: true, getValue: (e) => e.source.service || '-' });
    columns.push({ key: 'fields_sender', label: 'From', width: 160, visible: false, sortable: true, getValue: (e) => e.fields.sender || e.fields.from || e.fields.from_address || '-' });
    columns.push({ key: 'fields_recipient', label: 'Recipient', width: 160, visible: true, sortable: true, getValue: (e) => e.fields.recipient || e.fields.to || e.fields.to_address || '-' });
    columns.push({ key: 'action', label: 'Action', width: 100, visible: true, sortable: true, getValue: (e) => e.action || e.fields.action || '-' });
  } else if (lowerType.includes('iptables') || lowerType.includes('ufw') || lowerType.includes('nftables') || lowerType.includes('firewalld') || lowerType.includes('firewall') || lowerType.includes('palo') || lowerType.includes('fortigate') || lowerType.includes('cisco') || lowerType.includes('checkpoint') || lowerType.includes('aws') || lowerType.includes('azure') || lowerType.includes('gcp')) {
    if (hasIp) columns.push({ key: 'source_ip', label: 'Source IP', width: 130, visible: true, sortable: true, getValue: (e) => e.source.ip || '-' });
    columns.push({ key: 'destination_ip', label: 'Dest IP', width: 130, visible: true, sortable: true, getValue: (e) => e.destination?.ip || e.fields.dst_ip || e.fields.destination_ip || '-' });
    columns.push({ key: 'fields_protocol', label: 'Protocol', width: 100, visible: true, sortable: true, getValue: (e) => e.fields.protocol || e.fields.proto || '-' });
    columns.push({ key: 'fields_action', label: 'Action', width: 100, visible: true, sortable: true, getValue: (e) => e.fields.action || e.outcome || '-' });
  } else if (lowerType.includes('windows') || lowerType.includes('security') || lowerType.includes('system') || lowerType.includes('application') || lowerType.includes('event')) {
    if (hasHostname) columns.push({ key: 'source_hostname', label: 'Host', width: 140, visible: true, sortable: true, getValue: (e) => e.source.hostname || '-' });
    columns.push({ key: 'fields_event_id', label: 'Event ID', width: 90, visible: true, sortable: true, getValue: (e) => e.fields.event_id?.toString() || e.fields.eventid?.toString() || e.fields.EventID?.toString() || '-' });
    if (hasUser) columns.push({ key: 'user', label: 'User', width: 120, visible: true, sortable: true, getValue: (e) => e.user?.name || e.fields.accountname || e.fields.AccountName || '-' });
    columns.push({ key: 'fields_logon_type', label: 'Logon Type', width: 100, visible: false, sortable: true, getValue: (e) => e.fields.logontype?.toString() || e.fields.LogonType?.toString() || '-' });
    columns.push({ key: 'fields_ip_address', label: 'IP Address', width: 130, visible: false, sortable: true, getValue: (e) => e.fields.ipaddress?.toString() || e.fields.IpAddress?.toString() || '-' });
  } else if (lowerType.includes('vsftpd') || lowerType.includes('proftpd') || lowerType.includes('ftp') || lowerType.includes('filezilla') || lowerType.includes('xferlog')) {
    if (hasIp) columns.push({ key: 'source_ip', label: 'Client IP', width: 130, visible: true, sortable: true, getValue: (e) => e.source.ip || '-' });
    if (hasUser) columns.push({ key: 'user', label: 'User', width: 120, visible: true, sortable: true, getValue: (e) => e.user?.name || e.fields.user || '-' });
    columns.push({ key: 'action', label: 'Action', width: 100, visible: true, sortable: true, getValue: (e) => e.action || e.fields.action || '-' });
    if (hasPid) columns.push({ key: 'source_pid', label: 'PID', width: 80, visible: false, sortable: true, getValue: (e) => e.source.pid?.toString() || '-' });
  } else if (lowerType.includes('dhcp') || lowerType.includes('dns') || lowerType.includes('proxy') || lowerType.includes('network')) {
    if (hasHostname) columns.push({ key: 'source_hostname', label: 'Host', width: 140, visible: true, sortable: true, getValue: (e) => e.source.hostname || '-' });
    columns.push({ key: 'source_service', label: 'Service', width: 120, visible: true, sortable: true, getValue: (e) => e.source.service || '-' });
    columns.push({ key: 'fields_mac', label: 'MAC Address', width: 140, visible: false, sortable: true, getValue: (e) => e.fields.mac || e.fields.client_mac || '-' });
    columns.push({ key: 'action', label: 'Action', width: 100, visible: true, sortable: true, getValue: (e) => e.action || e.fields.action || '-' });
    if (hasIp) columns.push({ key: 'source_ip', label: 'Client IP', width: 130, visible: true, sortable: true, getValue: (e) => e.source.ip || '-' });
  } else if (lowerType.includes('syslog') || lowerType.includes('systemd') || lowerType.includes('kernel') || lowerType.includes('audit') || lowerType.includes('cron') || lowerType.includes('daemon') || lowerType.includes('auth') || lowerType.includes('system')) {
    if (hasHostname) columns.push({ key: 'source_hostname', label: 'Host', width: 140, visible: true, sortable: true, getValue: (e) => e.source.hostname || '-' });
    if (hasPid) columns.push({ key: 'source_pid', label: 'PID', width: 80, visible: true, sortable: true, getValue: (e) => e.source.pid?.toString() || '-' });
    columns.push({ key: 'source_service', label: 'Service', width: 120, visible: true, sortable: true, getValue: (e) => e.source.service || e.fields.program || '-' });
    columns.push({ key: 'command', label: 'Command', width: 180, visible: false, sortable: true, getValue: (e) => e.fields.command || e.fields.comm || e.fields.exe || '-' });
  } else if (lowerType.includes('fastapi') || lowerType.includes('aiohttp') || lowerType.includes('starlette') || lowerType.includes('python') || lowerType.includes('uvicorn') || lowerType.includes('gunicorn')) {
    if (hasIp) columns.push({ key: 'source_ip', label: 'Client IP', width: 130, visible: true, sortable: true, getValue: (e) => e.source.ip || e.fields.client_ip || e.fields.clientip || '-' });
    if (hasMethod) columns.push({ key: 'action', label: 'Method', width: 100, visible: true, sortable: true, getValue: (e) => e.action || e.fields.method || '-' });
    if (hasPath) columns.push({ key: 'fields_path', label: 'Endpoint', width: 200, visible: true, sortable: true, getValue: (e) => e.fields.path || e.fields.url || e.fields.endpoint || '-' });
    if (hasStatus) columns.push({ key: 'fields_status', label: 'Status', width: 80, visible: true, sortable: true, getValue: (e) => e.fields.status?.toString() || '-' });
    columns.push({ key: 'fields_latency', label: 'Latency (ms)', width: 100, visible: false, sortable: true, getValue: (e) => e.fields.latency_ms?.toString() || e.fields.latency || '-' });
  } else if (lowerType.includes('php-fpm') || lowerType.includes('php') || lowerType.includes('fpm')) {
    columns.push({ key: 'fields_level', label: 'Level', width: 100, visible: true, sortable: true, getValue: (e) => e.fields.level || e.severity || '-' });
  } else if (lowerType.includes('haproxy')) {
    if (hasIp) columns.push({ key: 'source_ip', label: 'Client IP', width: 130, visible: true, sortable: true, getValue: (e) => e.source.ip || '-' });
    if (hasMethod) columns.push({ key: 'action', label: 'Method', width: 100, visible: true, sortable: true, getValue: (e) => e.action || e.fields.method || '-' });
    if (hasPath) columns.push({ key: 'fields_path', label: 'Endpoint', width: 200, visible: true, sortable: true, getValue: (e) => e.fields.path || e.fields.url || '-' });
    if (hasStatus) columns.push({ key: 'fields_status', label: 'Status', width: 80, visible: true, sortable: true, getValue: (e) => e.fields.status?.toString() || '-' });
  } else if (lowerType.includes('spring') || lowerType.includes('java') || lowerType.includes('boot')) {
    columns.push({ key: 'fields_level', label: 'Level', width: 100, visible: true, sortable: true, getValue: (e) => e.fields.level || e.severity || '-' });
    columns.push({ key: 'fields_logger', label: 'Logger', width: 150, visible: false, sortable: true, getValue: (e) => e.fields.logger || e.fields.logger_name || '-' });
    if (hasMethod) columns.push({ key: 'action', label: 'Method', width: 100, visible: true, sortable: true, getValue: (e) => e.action || e.fields.method || '-' });
    if (hasPath) columns.push({ key: 'fields_path', label: 'Endpoint', width: 200, visible: true, sortable: true, getValue: (e) => e.fields.path || '-' });
    if (hasStatus) columns.push({ key: 'fields_status', label: 'Status', width: 80, visible: true, sortable: true, getValue: (e) => e.fields.status?.toString() || '-' });
  } else if (lowerType.includes('aspnet') || lowerType.includes('dotnet') || lowerType.includes('core')) {
    columns.push({ key: 'fields_level', label: 'Level', width: 100, visible: true, sortable: true, getValue: (e) => e.fields.level || e.severity || '-' });
    if (hasMethod) columns.push({ key: 'action', label: 'Method', width: 100, visible: true, sortable: true, getValue: (e) => e.action || e.fields.method || '-' });
    if (hasPath) columns.push({ key: 'fields_path', label: 'Endpoint', width: 200, visible: true, sortable: true, getValue: (e) => e.fields.path || '-' });
    if (hasStatus) columns.push({ key: 'fields_status', label: 'Status', width: 80, visible: true, sortable: true, getValue: (e) => e.fields.status?.toString() || '-' });
  } else if (lowerType.includes('courier')) {
    if (hasHostname) columns.push({ key: 'source_hostname', label: 'Host', width: 140, visible: true, sortable: true, getValue: (e) => e.source.hostname || '-' });
    columns.push({ key: 'source_service', label: 'Service', width: 120, visible: true, sortable: true, getValue: (e) => e.source.service || 'courier' });
    columns.push({ key: 'action', label: 'Action', width: 100, visible: true, sortable: true, getValue: (e) => e.action || e.fields.action || '-' });
    if (hasUser) columns.push({ key: 'user', label: 'User', width: 120, visible: true, sortable: true, getValue: (e) => e.user?.name || e.fields.user || '-' });
  } else if (lowerType.includes('amavis') || lowerType.includes('spamassassin') || lowerType.includes('mailscanner')) {
    if (hasHostname) columns.push({ key: 'source_hostname', label: 'Host', width: 140, visible: true, sortable: true, getValue: (e) => e.source.hostname || '-' });
    columns.push({ key: 'source_service', label: 'Service', width: 120, visible: true, sortable: true, getValue: (e) => e.source.service || '-' });
  } else if (lowerType.includes('macos') && (lowerType.includes('pf') || lowerType.includes('firewall'))) {
    columns.push({ key: 'fields_rule', label: 'Rule', width: 100, visible: true, sortable: true, getValue: (e) => e.fields.rule || '-' });
    columns.push({ key: 'fields_action', label: 'Action', width: 100, visible: true, sortable: true, getValue: (e) => e.fields.action || e.outcome || '-' });
    columns.push({ key: 'fields_direction', label: 'Direction', width: 100, visible: false, sortable: true, getValue: (e) => e.fields.direction || '-' });
    columns.push({ key: 'fields_interface', label: 'Interface', width: 100, visible: false, sortable: true, getValue: (e) => e.fields.iface || e.fields.interface || '-' });
  } else if (lowerType.includes('oracle')) {
    if (hasHostname) columns.push({ key: 'source_hostname', label: 'Host', width: 140, visible: true, sortable: true, getValue: (e) => e.source.hostname || '-' });
    columns.push({ key: 'source_service', label: 'Service', width: 120, visible: true, sortable: true, getValue: (e) => e.fields.service_name || e.source.service || '-' });
    columns.push({ key: 'fields_protocol', label: 'Protocol', width: 100, visible: false, sortable: true, getValue: (e) => e.fields.protocol || '-' });
    columns.push({ key: 'fields_port', label: 'Port', width: 80, visible: false, sortable: true, getValue: (e) => e.fields.port?.toString() || '-' });
  } else if (lowerType.includes('package') || lowerType.includes('linux_package')) {
    columns.push({ key: 'command', label: 'Package Action', width: 200, visible: true, sortable: true, getValue: (e) => e.fields.message || e.message || '-' });
  } else if (lowerType.includes('macos') && lowerType.includes('app')) {
    columns.push({ key: 'fields_action', label: 'Action', width: 100, visible: true, sortable: true, getValue: (e) => e.fields.action || '-' });
    columns.push({ key: 'fields_direction', label: 'Direction', width: 100, visible: true, sortable: true, getValue: (e) => e.fields.direction || '-' });
    columns.push({ key: 'source_ip', label: 'Source IP', width: 130, visible: true, sortable: true, getValue: (e) => e.source.ip || e.fields.ip || '-' });
    columns.push({ key: 'fields_app', label: 'Application', width: 150, visible: true, sortable: true, getValue: (e) => e.fields.app || '-' });
  } else {
    // Fallback: inspect sample entries to determine columns
    if (hasIp) columns.push({ key: 'source_ip', label: 'IP', width: 130, visible: true, sortable: true, getValue: (e) => e.source.ip || '-' });
    if (hasMethod) columns.push({ key: 'action', label: 'Method', width: 90, visible: true, sortable: true, getValue: (e) => e.action || e.fields.method || '-' });
    if (hasPath) columns.push({ key: 'fields_path', label: 'Endpoint', width: 200, visible: true, sortable: true, getValue: (e) => e.fields.path || e.fields.url || '-' });
    if (hasStatus) columns.push({ key: 'fields_status', label: 'Status', width: 80, visible: true, sortable: true, getValue: (e) => e.fields.status?.toString() || '-' });
    if (hasUser) columns.push({ key: 'user', label: 'User', width: 120, visible: true, sortable: true, getValue: (e) => e.user?.name || '-' });
    if (hasPid) columns.push({ key: 'source_pid', label: 'PID', width: 80, visible: false, sortable: true, getValue: (e) => e.source.pid?.toString() || '-' });
  }

  columns.push({ key: 'fields', label: 'Fields', width: MIN_COLUMN_WIDTH, visible: false, sortable: false, getValue: (e) => '...' });

  return columns;
};

interface DynamicTableProps {
  entries: ParsedLogEntry[];
  detectedType: string;
  onEntryClick?: (entry: ParsedLogEntry) => void;
}

export function DynamicTable({ entries, detectedType, onEntryClick }: DynamicTableProps) {
  const [columns, setColumns] = useState<Column[]>([]);
  const [sortColumn, setSortColumn] = useState<string | null>(null);
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');
  const [visibleColumns, setVisibleColumns] = useState<Set<string>>(new Set());

  const tableContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const newColumns = getColumnsForLogType(detectedType, entries.slice(0, 10));
    setColumns(newColumns);
    setVisibleColumns(new Set(newColumns.filter(c => c.visible).map(c => c.key)));
  }, [detectedType, entries]);

  const handleSort = (columnKey: string) => {
    if (sortColumn === columnKey) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortColumn(columnKey);
      setSortDirection('asc');
    }
  };

  const handleResizeStart = (columnKey: string, startX: number) => {
    const handleMouseMove = (e: MouseEvent) => {
      const column = columns.find(c => c.key === columnKey);
      if (!column) return;

      const delta = startX - e.clientX;
      const newWidth = Math.max(MIN_COLUMN_WIDTH, column.width - delta);
      
      setColumns(prev => prev.map(c => 
        c.key === columnKey ? { ...c, width: newWidth } : c
      ));

      if (newWidth === MIN_COLUMN_WIDTH) {
        const newVisible = new Set(visibleColumns);
        newVisible.delete(columnKey);
        setVisibleColumns(newVisible);
      }
    };

    const handleMouseUp = () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  };

  const getSortedEntries = (): ParsedLogEntry[] => {
    if (!sortColumn) return entries;

    const column = columns.find(c => c.key === sortColumn);
    if (!column || !column.sortable) return entries;

    const sorted = [...entries].sort((a, b) => {
      const valueA = String(column.getValue(a) || '');
      const valueB = String(column.getValue(b) || '');
      
      const comparison = valueA.localeCompare(valueB);
      return sortDirection === 'asc' ? comparison : -comparison;
    });

    return sorted;
  };

  const visibleColumnList = columns.filter(c => visibleColumns.has(c.key));
  const totalWidth = visibleColumnList.reduce((sum, col) => sum + col.width, 0);
  const sortedEntries = getSortedEntries();

  return (
    <div className="dynamic-table-container">
      <div className="table-scroll-wrapper" ref={tableContainerRef}>
        <table className="dynamic-table">
          <thead>
            <tr>
              {visibleColumnList.map(column => (
                <th
                  key={column.key}
                  style={{ width: `${column.width}px`, minWidth: `${MIN_COLUMN_WIDTH}px` }}
                  className={`sortable ${sortColumn === column.key ? 'sorted' : ''}`}
                  onClick={() => column.sortable && handleSort(column.key)}
                >
                  <div className="th-content">
                    <span className="th-label">{column.label}</span>
                    {sortColumn === column.key && (
                      <span className={`sort-indicator ${sortDirection}`}>
                        {sortDirection === 'asc' ? '▲' : '▼'}
                      </span>
                    )}
                  </div>
                  <div 
                    className="resize-handle"
                    onMouseDown={(e) => handleResizeStart(column.key, e.clientX)}
                  />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sortedEntries.map((entry) => (
              <tr key={entry.id} onClick={() => onEntryClick?.(entry)}>
                {visibleColumnList.map(column => (
                  <td 
                    key={column.key}
                    style={{ width: `${column.width}px` }}
                    className="data-cell"
                  >
                    {column.getValue(entry)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="column-toggles">
        <button 
          className="toggle-columns-btn"
          onClick={() => {
            if (visibleColumns.size === columns.filter(c => c.visible).length) {
              const allVisible = new Set(columns.filter(c => c.visible).map(c => c.key));
              setVisibleColumns(allVisible);
            } else {
              const minimalVisible = new Set(['timestamp', 'severity', 'message']);
              setVisibleColumns(minimalVisible);
            }
          }}
        >
          {visibleColumns.size > 3 ? 'Fewer Columns' : 'More Columns'}
        </button>
      </div>
      {visibleColumns.size < columns.filter(c => c.visible).length && (
        <div className="hidden-columns-indicator">
          {columns.filter(c => c.visible).length - visibleColumns.size} hidden columns
        </div>
      )}
    </div>
  );
}
