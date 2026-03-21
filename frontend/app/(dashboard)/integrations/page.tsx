'use client';

import { useState, useCallback } from 'react';
import {
  Zap,
  Plus,
  Activity,
  Server,
  Shield,
  Webhook,
  Send,
  ChevronDown,
  ChevronUp,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  Info,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { IntegrationCard, IntegrationConfig } from '@/components/integrations/IntegrationCard';
import { WebhookBuilder, WebhookFormData } from '@/components/integrations/WebhookBuilder';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type SIEMFormat = 'json' | 'cef' | 'leef';
type Tab = 'webhooks' | 'siem' | 'syslog';

interface SIEMExportResult {
  format: string;
  count: number;
  records: string[];
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

// ---------------------------------------------------------------------------
// Demo webhook configs
// ---------------------------------------------------------------------------
const DEMO_CONFIGS: IntegrationConfig[] = [
  {
    id: 'demo-slack',
    name: 'Team Slack',
    provider: 'slack',
    url: 'https://hooks.slack.com/services/T00/B00/DEMO',
    enabled: true,
    events: ['finding_critical', 'scan_completed'],
    lastDelivery: { success: true, timestamp: new Date(Date.now() - 60000).toISOString(), duration_ms: 120 },
  },
  {
    id: 'demo-pagerduty',
    name: 'Critical Alerts',
    provider: 'pagerduty',
    url: 'https://events.pagerduty.com/v2/enqueue',
    enabled: true,
    events: ['finding_critical'],
    lastDelivery: { success: false, timestamp: new Date(Date.now() - 300000).toISOString(), duration_ms: 0 },
  },
  {
    id: 'demo-jira',
    name: 'Security Tickets',
    provider: 'jira',
    url: 'https://company.atlassian.net/rest/api/3/issue',
    enabled: false,
    events: ['finding_critical', 'finding_high'],
  },
];

// ---------------------------------------------------------------------------
// SIEMPanel
// ---------------------------------------------------------------------------

function SIEMPanel() {
  const [format, setFormat] = useState<SIEMFormat>('json');
  const [result, setResult] = useState<SIEMExportResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const SAMPLE_FINDINGS = [
    { id: 'F001', title: 'SQL Injection', severity: 'critical', category: 'injection', description: 'Unsanitised SQL query on /api/users', target_host: 'api.target.local', target_port: 443, cve_id: 'CVE-2023-0001', cvss_score: 9.8 },
    { id: 'F002', title: 'XSS Reflected', severity: 'high', category: 'xss', description: 'Reflected XSS on search parameter', target_host: 'www.target.local', target_port: 80 },
    { id: 'F003', title: 'Insecure Direct Object Reference', severity: 'medium', category: 'idor', description: 'IDOR allows access to other users data', target_host: 'api.target.local' },
  ];

  const exportFindings = async () => {
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const resp = await fetch(`${API_BASE}/api/integrations/export/siem`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format, findings: SAMPLE_FINDINGS }),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message ?? 'Export failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Format selector */}
      <div>
        <p className="text-sm font-medium text-gray-300 mb-3">Export Format</p>
        <div className="flex gap-3">
          {(['json', 'cef', 'leef'] as SIEMFormat[]).map((f) => (
            <button
              key={f}
              onClick={() => setFormat(f)}
              className={`px-4 py-2 rounded-lg border text-sm font-medium uppercase tracking-wide transition-all ${
                format === f
                  ? 'border-cyan-500 bg-cyan-500/10 text-cyan-300'
                  : 'border-gray-700 bg-gray-800/40 text-gray-400 hover:border-gray-600'
              }`}
            >
              {f.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Info badges */}
      <div className="grid grid-cols-3 gap-3 text-xs">
        <div className="bg-gray-800/50 rounded-lg p-3 border border-gray-700">
          <p className="font-semibold text-white mb-1">JSON</p>
          <p className="text-gray-500">Generic structured log — compatible with any SIEM</p>
        </div>
        <div className="bg-gray-800/50 rounded-lg p-3 border border-gray-700">
          <p className="font-semibold text-white mb-1">CEF</p>
          <p className="text-gray-500">ArcSight Common Event Format — Splunk, QRadar, ArcSight</p>
        </div>
        <div className="bg-gray-800/50 rounded-lg p-3 border border-gray-700">
          <p className="font-semibold text-white mb-1">LEEF</p>
          <p className="text-gray-500">IBM QRadar Log Event Extended Format</p>
        </div>
      </div>

      <Button
        onClick={exportFindings}
        disabled={loading}
        className="bg-cyan-600 hover:bg-cyan-500 text-white gap-2"
      >
        {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
        Export {SAMPLE_FINDINGS.length} Sample Findings
      </Button>

      {error && (
        <div className="text-sm text-red-400 bg-red-500/10 border border-red-800 rounded-lg px-4 py-3">
          {error}
        </div>
      )}

      {result && (
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm text-green-400">
            <CheckCircle2 className="w-4 h-4" />
            Exported {result.count} records in {result.format.toUpperCase()} format
          </div>
          <pre className="bg-gray-950 border border-gray-800 rounded-xl p-4 text-xs text-gray-300 overflow-auto max-h-72 font-mono">
            {result.records.join('\n')}
          </pre>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// SyslogPanel
// ---------------------------------------------------------------------------

function SyslogPanel() {
  const [form, setForm] = useState({
    host: '127.0.0.1',
    port: '514',
    protocol: 'udp',
    message: 'UniVex test syslog message',
    severity: 'info',
    app_name: 'univex',
    msg_id: 'TEST',
  });
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ success: boolean; message: string } | null>(null);

  const send = async () => {
    setLoading(true);
    setResult(null);
    try {
      const resp = await fetch(`${API_BASE}/api/integrations/syslog/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...form, port: form.port ? parseInt(form.port) : undefined }),
      });
      const data = await resp.json();
      setResult({ success: data.success, message: data.success ? 'Message sent successfully' : 'Send failed' });
    } catch {
      setResult({ success: false, message: 'Connection error' });
    } finally {
      setLoading(false);
    }
  };

  const field = (key: keyof typeof form, label: string, placeholder: string, type = 'text') => (
    <div className="space-y-1.5">
      <label className="text-sm text-gray-300">{label}</label>
      <input
        type={type}
        value={form[key]}
        onChange={(e) => setForm((f) => ({ ...f, [key]: e.target.value }))}
        placeholder={placeholder}
        className="w-full bg-gray-800 border border-gray-700 text-white rounded-md px-3 py-2 text-sm placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-600"
      />
    </div>
  );

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {field('host', 'Syslog Server Host', 'siem.corp.internal')}
        {field('port', 'Port', '514', 'number')}
        <div className="space-y-1.5">
          <label className="text-sm text-gray-300">Protocol</label>
          <select
            value={form.protocol}
            onChange={(e) => setForm((f) => ({ ...f, protocol: e.target.value }))}
            className="w-full bg-gray-800 border border-gray-700 text-white rounded-md px-3 py-2 text-sm"
          >
            <option value="udp">UDP (RFC 5424)</option>
            <option value="tcp">TCP (RFC 6587)</option>
            <option value="tls">TLS (RFC 5425)</option>
          </select>
        </div>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {field('app_name', 'App Name', 'univex')}
        {field('msg_id', 'Message ID', 'FINDING')}
      </div>
      <div className="space-y-1.5">
        <label className="text-sm text-gray-300">Severity</label>
        <select
          value={form.severity}
          onChange={(e) => setForm((f) => ({ ...f, severity: e.target.value }))}
          className="w-full bg-gray-800 border border-gray-700 text-white rounded-md px-3 py-2 text-sm"
        >
          {['emerg','alert','crit','err','warning','notice','info','debug'].map((s) => (
            <option key={s} value={s}>{s.toUpperCase()}</option>
          ))}
        </select>
      </div>
      <div className="space-y-1.5">
        <label className="text-sm text-gray-300">Message</label>
        <textarea
          value={form.message}
          onChange={(e) => setForm((f) => ({ ...f, message: e.target.value }))}
          rows={3}
          className="w-full bg-gray-800 border border-gray-700 text-white rounded-md px-3 py-2 text-sm placeholder-gray-500 resize-none focus:outline-none focus:ring-2 focus:ring-cyan-600"
        />
      </div>

      <Button onClick={send} disabled={loading} className="bg-cyan-600 hover:bg-cyan-500 text-white gap-2">
        {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
        Send Syslog Message
      </Button>

      {result && (
        <div className={`flex items-center gap-2 text-sm p-3 rounded-lg border ${result.success ? 'bg-green-500/10 border-green-700 text-green-400' : 'bg-red-500/10 border-red-700 text-red-400'}`}>
          {result.success ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
          {result.message}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function IntegrationsPage() {
  const [activeTab, setActiveTab] = useState<Tab>('webhooks');
  const [configs, setConfigs] = useState<IntegrationConfig[]>(DEMO_CONFIGS);
  const [showBuilder, setShowBuilder] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [builderLoading, setBuilderLoading] = useState(false);

  const handleTest = useCallback(async (id: string) => {
    setTestingId(id);
    try {
      const resp = await fetch(`${API_BASE}/api/integrations/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config_id: id, event: 'scan_completed' }),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    } finally {
      setTestingId(null);
    }
  }, []);

  const handleDelete = useCallback(async (id: string) => {
    setDeletingId(id);
    try {
      await fetch(`${API_BASE}/api/integrations/configure/${id}`, { method: 'DELETE' });
      setConfigs((prev) => prev.filter((c) => c.id !== id));
    } finally {
      setDeletingId(null);
    }
  }, []);

  const handleToggle = useCallback((id: string, enabled: boolean) => {
    setConfigs((prev) =>
      prev.map((c) => (c.id === id ? { ...c, enabled } : c))
    );
  }, []);

  const handleWebhookSubmit = useCallback(async (data: WebhookFormData) => {
    setBuilderLoading(true);
    try {
      await fetch(`${API_BASE}/api/integrations/configure`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      const newConfig: IntegrationConfig = {
        id: data.id,
        name: data.name,
        provider: data.provider,
        url: data.url,
        enabled: data.enabled,
        events: data.events,
      };
      setConfigs((prev) => [...prev, newConfig]);
      setShowBuilder(false);
    } finally {
      setBuilderLoading(false);
    }
  }, []);

  const TABS: { key: Tab; label: string; icon: React.ReactNode; count?: number }[] = [
    { key: 'webhooks', label: 'Webhooks', icon: <Webhook className="w-4 h-4" />, count: configs.length },
    { key: 'siem', label: 'SIEM Export', icon: <Shield className="w-4 h-4" /> },
    { key: 'syslog', label: 'Syslog', icon: <Server className="w-4 h-4" /> },
  ];

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      <div className="max-w-6xl mx-auto px-6 py-8 space-y-8">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-700 flex items-center justify-center">
                <Zap className="w-5 h-5 text-cyan-400" />
              </div>
              <h1 className="text-2xl font-bold text-white">Integrations</h1>
            </div>
            <p className="text-gray-400 text-sm">
              Connect UniVex to your SIEM, ticketing, and alerting systems.
            </p>
          </div>

          {activeTab === 'webhooks' && (
            <Button
              onClick={() => setShowBuilder(!showBuilder)}
              className="bg-cyan-600 hover:bg-cyan-500 text-white gap-2"
            >
              <Plus className="w-4 h-4" />
              Add Webhook
            </Button>
          )}
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-gray-900/70 rounded-xl border border-gray-800 p-4 text-center">
            <p className="text-2xl font-bold text-white">{configs.length}</p>
            <p className="text-xs text-gray-400 mt-1">Webhooks</p>
          </div>
          <div className="bg-gray-900/70 rounded-xl border border-gray-800 p-4 text-center">
            <p className="text-2xl font-bold text-green-400">
              {configs.filter((c) => c.enabled).length}
            </p>
            <p className="text-xs text-gray-400 mt-1">Active</p>
          </div>
          <div className="bg-gray-900/70 rounded-xl border border-gray-800 p-4 text-center">
            <p className="text-2xl font-bold text-cyan-400">5</p>
            <p className="text-xs text-gray-400 mt-1">Providers</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 bg-gray-900/50 rounded-xl p-1 border border-gray-800">
          {TABS.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`flex-1 flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg text-sm font-medium transition-all ${
                activeTab === tab.key
                  ? 'bg-gray-800 text-white shadow-sm'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              {tab.icon}
              {tab.label}
              {tab.count !== undefined && tab.count > 0 && (
                <span className="text-xs bg-cyan-500/20 text-cyan-400 px-1.5 py-0.5 rounded-full">
                  {tab.count}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Tab content */}
        {activeTab === 'webhooks' && (
          <div className="space-y-4">
            {/* Webhook builder */}
            {showBuilder && (
              <div className="bg-gray-900/70 rounded-xl border border-cyan-800 p-6">
                <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
                  <Plus className="w-4 h-4 text-cyan-400" />
                  New Webhook
                </h2>
                <WebhookBuilder onSubmit={handleWebhookSubmit} isLoading={builderLoading} />
              </div>
            )}

            {/* Config cards */}
            {configs.length === 0 ? (
              <div className="text-center py-16 text-gray-500">
                <Webhook className="w-10 h-10 mx-auto mb-3 opacity-30" />
                <p>No webhook integrations yet.</p>
                <p className="text-sm mt-1">Click "Add Webhook" to get started.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {configs.map((cfg) => (
                  <IntegrationCard
                    key={cfg.id}
                    config={cfg}
                    onTest={handleTest}
                    onDelete={handleDelete}
                    onToggle={handleToggle}
                    isTestLoading={testingId === cfg.id}
                    isDeleteLoading={deletingId === cfg.id}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'siem' && (
          <div className="bg-gray-900/70 rounded-xl border border-gray-800 p-6">
            <h2 className="text-base font-semibold text-white mb-5 flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              SIEM Export
            </h2>
            <SIEMPanel />
          </div>
        )}

        {activeTab === 'syslog' && (
          <div className="bg-gray-900/70 rounded-xl border border-gray-800 p-6">
            <h2 className="text-base font-semibold text-white mb-5 flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              Syslog Forwarder
            </h2>
            <SyslogPanel />
          </div>
        )}
      </div>
    </div>
  );
}
