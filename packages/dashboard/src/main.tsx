import React, { useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import './styles.css';

type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

type Finding = {
  id: string;
  severity: Severity;
  ruleId: string;
  file: string;
  line: number;
  message: string;
  cwe: string;
  suggestion: string;
  snippet: string;
};

type ScanStatus = 'queued' | 'running' | 'done';

const severityRank: Record<Severity, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Info: 1,
};

const findings: Finding[] = [
  {
    id: 'f-001',
    severity: 'Critical',
    ruleId: 'secret.aws.access_key',
    file: 'src/config/payments.ts',
    line: 14,
    message: 'Hardcoded AWS access key detected',
    cwe: 'CWE-798',
    suggestion:
      'Move the credential into a managed secret store and inject it through environment variables. Rotate the exposed key, remove it from git history, and load it with a typed config helper before AWS clients are created.',
    snippet:
      'const client = new S3Client({\n  region: process.env.AWS_REGION,\n  credentials: loadAwsCredentials()\n});',
  },
  {
    id: 'f-002',
    severity: 'High',
    ruleId: 'unsafe.eval',
    file: 'src/routes/webhook.ts',
    line: 42,
    message: 'Dynamic evaluation of request-controlled data',
    cwe: 'CWE-95',
    suggestion:
      'Replace dynamic evaluation with a fixed command registry. Parse the incoming action as a string enum, reject unknown values, and execute only mapped handlers.',
    snippet:
      'const handlers = { refund, capture, voidPayment };\nconst handler = handlers[action];\nif (!handler) throw new Error("Unsupported action");',
  },
  {
    id: 'f-003',
    severity: 'High',
    ruleId: 'sqli.template_interpolation',
    file: 'src/db/orders.ts',
    line: 67,
    message: 'SQL template contains interpolated user input',
    cwe: 'CWE-89',
    suggestion:
      'Use parameterized queries and pass user input as values instead of interpolating it into SQL. Keep the SQL text static so the database driver can bind parameters safely.',
    snippet:
      'await db.query("select * from orders where email = $1", [email]);',
  },
  {
    id: 'f-004',
    severity: 'Medium',
    ruleId: 'path.traversal.join',
    file: 'src/files/download.ts',
    line: 31,
    message: 'File path is built from request input',
    cwe: 'CWE-22',
    suggestion:
      'Normalize the requested path, reject parent directory segments, and verify that the resolved path remains inside the expected storage directory.',
    snippet:
      'const resolved = path.resolve(storageRoot, requestedName);\nif (!resolved.startsWith(storageRoot)) throw new Error("Invalid path");',
  },
  {
    id: 'f-005',
    severity: 'Medium',
    ruleId: 'secret.high_entropy_string',
    file: 'scripts/seed.ts',
    line: 9,
    message: 'High-entropy string literal may contain a secret',
    cwe: 'CWE-798',
    suggestion:
      'Replace seeded credentials with generated local-only values and keep production secrets outside source control. If this value was ever real, rotate it immediately.',
    snippet: 'const demoPassword = createLocalOnlyCredential();',
  },
  {
    id: 'f-006',
    severity: 'Low',
    ruleId: 'header.missing_csp',
    file: 'src/server/security.ts',
    line: 22,
    message: 'Content Security Policy is not configured',
    cwe: 'CWE-693',
    suggestion:
      'Add a restrictive Content Security Policy for production responses and keep exceptions scoped to known asset origins.',
    snippet: 'reply.header("Content-Security-Policy", "default-src \'self\'; frame-ancestors \'none\'");',
  },
];

const fileHeatmap = [
  { file: 'payments.ts', lines: 220, severity: 'Critical' as Severity },
  { file: 'webhook.ts', lines: 164, severity: 'High' as Severity },
  { file: 'orders.ts', lines: 145, severity: 'High' as Severity },
  { file: 'download.ts', lines: 98, severity: 'Medium' as Severity },
  { file: 'seed.ts', lines: 58, severity: 'Medium' as Severity },
  { file: 'security.ts', lines: 74, severity: 'Low' as Severity },
  { file: 'billing.ts', lines: 186, severity: 'Info' as Severity },
  { file: 'auth.ts', lines: 128, severity: 'Info' as Severity },
];

const history = [
  { date: 'Apr 10', score: 61 },
  { date: 'Apr 11', score: 66 },
  { date: 'Apr 13', score: 70 },
  { date: 'Apr 15', score: 72 },
  { date: 'Apr 17', score: 74 },
];

const scanMeta = {
  repo: 'octo-store/payments',
  branch: 'feature/secure-checkout',
  commit: '8f31c2a',
  scannedAt: 'Apr 17, 2026, 09:51',
  duration: '312 ms',
  files: 142,
  lines: 18430,
  score: 74,
};

function App() {
  const [status, setStatus] = useState<ScanStatus>('done');
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | 'All'>('All');
  const [expandedFindingId, setExpandedFindingId] = useState<string>('f-001');

  const severitySummary = useMemo(() => getSeveritySummary(findings), []);
  const filteredFindings = useMemo(() => {
    if (selectedSeverity === 'All') {
      return findings;
    }

    return findings.filter((finding) => finding.severity === selectedSeverity);
  }, [selectedSeverity]);

  const runDemoScan = () => {
    setStatus('queued');
    window.setTimeout(() => setStatus('running'), 700);
    window.setTimeout(() => setStatus('done'), 1900);
  };

  return (
    <main className="app-shell">
      <section className="hero-band" aria-label="AegisHub scan demo">
        <div className="hero-copy">
          <div className="eyebrow">
            <ShieldIcon />
            AegisHub Security Report
          </div>
          <h1>{scanMeta.repo}</h1>
          <p>
            Pull request scan for <strong>{scanMeta.branch}</strong> at commit{' '}
            <code>{scanMeta.commit}</code>
          </p>
        </div>

        <div className="hero-actions">
          <StatusPill status={status} />
          <button className="primary-button" type="button" onClick={runDemoScan}>
            <PlayIcon />
            Run demo scan
          </button>
        </div>
      </section>

      <section className="dashboard-grid" aria-label="Scan dashboard">
        <div className="score-panel">
          <ScoreRing score={status === 'done' ? scanMeta.score : 0} />
          <div className="score-copy">
            <span>Security score</span>
            <strong>{status === 'done' ? `${scanMeta.score}/100` : 'Scanning'}</strong>
            <p>Threshold: 70. Current PR status: {scanMeta.score >= 70 ? 'passing' : 'blocked'}.</p>
          </div>
        </div>

        <MetricCard label="Files scanned" value={scanMeta.files.toLocaleString('en-US')} />
        <MetricCard label="Lines scanned" value={scanMeta.lines.toLocaleString('en-US')} />
        <MetricCard label="Findings" value={findings.length.toString()} />
        <MetricCard label="Duration" value={scanMeta.duration} />

        <section className="panel chart-panel" aria-label="Findings breakdown">
          <PanelHeader title="Findings by severity" label="Current scan" />
          <div className="chart-frame">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severitySummary} margin={{ top: 8, right: 10, left: -24, bottom: 0 }}>
                <CartesianGrid stroke="#e5e7eb" vertical={false} />
                <XAxis dataKey="severity" tickLine={false} axisLine={false} />
                <YAxis allowDecimals={false} tickLine={false} axisLine={false} />
                <Tooltip cursor={{ fill: '#f8fafc' }} />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {severitySummary.map((item) => (
                    <Cell key={item.severity} fill={getSeverityColor(item.severity)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="panel heatmap-panel" aria-label="File heatmap">
          <PanelHeader title="File heatmap" label="Highest severity per file" />
          <div className="heatmap-grid">
            {fileHeatmap.map((item) => (
              <div
                className="heatmap-tile"
                key={item.file}
                style={{
                  borderColor: getSeverityColor(item.severity),
                  gridColumn: `span ${Math.max(1, Math.min(3, Math.ceil(item.lines / 90)))}`,
                }}
              >
                <span>{item.file}</span>
                <strong style={{ color: getSeverityColor(item.severity) }}>{item.severity}</strong>
                <small>{item.lines} lines</small>
              </div>
            ))}
          </div>
        </section>

        <section className="panel findings-panel" aria-label="Findings table">
          <div className="findings-header">
            <PanelHeader title="Findings" label={`${filteredFindings.length} visible`} />
            <div className="segmented-control" aria-label="Filter findings">
              {(['All', 'Critical', 'High', 'Medium', 'Low'] as const).map((severity) => (
                <button
                  className={selectedSeverity === severity ? 'active' : ''}
                  key={severity}
                  type="button"
                  onClick={() => setSelectedSeverity(severity)}
                >
                  {severity}
                </button>
              ))}
            </div>
          </div>

          <div className="findings-table" role="table">
            <div className="table-row table-heading" role="row">
              <span>Severity</span>
              <span>Rule</span>
              <span>File</span>
              <span>Message</span>
              <span>CWE</span>
              <span>Fix</span>
            </div>
            {filteredFindings.map((finding) => (
              <FindingRow
                expanded={expandedFindingId === finding.id}
                finding={finding}
                key={finding.id}
                onToggle={() =>
                  setExpandedFindingId(expandedFindingId === finding.id ? '' : finding.id)
                }
              />
            ))}
          </div>
        </section>

        <section className="panel history-panel" aria-label="Security score history">
          <PanelHeader title="Score history" label="Last five scans" />
          <div className="chart-frame small">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={history} margin={{ top: 8, right: 12, left: -24, bottom: 0 }}>
                <CartesianGrid stroke="#e5e7eb" vertical={false} />
                <XAxis dataKey="date" tickLine={false} axisLine={false} />
                <YAxis domain={[40, 100]} tickLine={false} axisLine={false} />
                <Tooltip />
                <Line
                  type="monotone"
                  dataKey="score"
                  stroke="#0f766e"
                  strokeWidth={3}
                  dot={{ r: 4, fill: '#0f766e' }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="panel pr-panel" aria-label="GitHub pull request comment preview">
          <PanelHeader title="Pull request comment" label="GitHub App preview" />
          <PrComment summary={severitySummary} />
        </section>
      </section>
    </main>
  );
}

function getSeveritySummary(items: Finding[]) {
  const severities: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info'];

  return severities.map((severity) => ({
    severity,
    count: items.filter((finding) => finding.severity === severity).length,
  }));
}

function MetricCard({ label, value }: { label: string; value: string }) {
  return (
    <section className="metric-card" aria-label={label}>
      <span>{label}</span>
      <strong>{value}</strong>
    </section>
  );
}

function PanelHeader({ title, label }: { title: string; label: string }) {
  return (
    <header className="panel-header">
      <h2>{title}</h2>
      <span>{label}</span>
    </header>
  );
}

function ScoreRing({ score }: { score: number }) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="score-ring" aria-label={`Security score ${score} out of 100`}>
      <svg viewBox="0 0 140 140" role="img">
        <circle className="score-track" cx="70" cy="70" r={radius} />
        <circle
          className="score-value"
          cx="70"
          cy="70"
          r={radius}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
      </svg>
      <span>{score}</span>
    </div>
  );
}

function StatusPill({ status }: { status: ScanStatus }) {
  return (
    <span className={`status-pill ${status}`}>
      <span className="status-dot" />
      {getStatusLabel(status)}
    </span>
  );
}

function FindingRow({
  expanded,
  finding,
  onToggle,
}: {
  expanded: boolean;
  finding: Finding;
  onToggle: () => void;
}) {
  return (
    <div className="finding-group">
      <div className="table-row" role="row">
        <span>
          <SeverityBadge severity={finding.severity} />
        </span>
        <code>{finding.ruleId}</code>
        <span>
          {finding.file}:{finding.line}
        </span>
        <span>{finding.message}</span>
        <span>{finding.cwe}</span>
        <button className="icon-button" type="button" onClick={onToggle} aria-expanded={expanded}>
          <SparkIcon />
          AI fix
        </button>
      </div>
      {expanded ? (
        <div className="fix-panel">
          <p>{finding.suggestion}</p>
          <pre>
            <code>{finding.snippet}</code>
          </pre>
        </div>
      ) : null}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: Severity }) {
  const color = getSeverityColor(severity);

  return (
    <strong className="severity-badge" style={{ color }}>
      <span style={{ backgroundColor: color }} />
      {severity}
    </strong>
  );
}

function PrComment({ summary }: { summary: Array<{ severity: Severity; count: number }> }) {
  const visibleSummary = summary.filter((item) => item.severity !== 'Info');
  const topFindings = [...findings]
    .sort((left, right) => severityRank[right.severity] - severityRank[left.severity])
    .slice(0, 3);

  return (
    <div className="pr-comment">
      <h3>AegisHub Security Report - Score: {scanMeta.score}/100</h3>
      <div className="markdown-table">
        <div className="markdown-row heading">
          <span>Severity</span>
          <span>Count</span>
        </div>
        {visibleSummary.map((item) => (
          <div className="markdown-row" key={item.severity}>
            <span>{item.severity}</span>
            <strong>{item.count}</strong>
          </div>
        ))}
      </div>
      <h4>Findings</h4>
      {topFindings.map((finding) => (
        <article className="comment-finding" key={finding.id}>
          <strong style={{ color: getSeverityColor(finding.severity) }}>
            [{finding.severity}] {finding.message}
          </strong>
          <span>
            {finding.file}, line {finding.line}
          </span>
          <p>{finding.suggestion}</p>
        </article>
      ))}
    </div>
  );
}

function getSeverityColor(severity: Severity) {
  switch (severity) {
    case 'Critical':
      return '#dc2626';
    case 'High':
      return '#d97706';
    case 'Medium':
      return '#0891b2';
    case 'Low':
      return '#6b7280';
    case 'Info':
      return '#475569';
  }
}

function getStatusLabel(status: ScanStatus) {
  switch (status) {
    case 'queued':
      return 'Queued';
    case 'running':
      return 'Scanning';
    case 'done':
      return 'Completed';
  }
}

function ShieldIcon() {
  return (
    <svg className="inline-icon" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 3 5 6v5c0 4.2 2.8 8 7 10 4.2-2 7-5.8 7-10V6l-7-3Z" />
      <path d="m9 12 2 2 4-5" />
    </svg>
  );
}

function PlayIcon() {
  return (
    <svg className="inline-icon" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M8 5v14l11-7L8 5Z" />
    </svg>
  );
}

function SparkIcon() {
  return (
    <svg className="inline-icon" viewBox="0 0 24 24" aria-hidden="true">
      <path d="m12 3 1.6 5.1L19 10l-5.4 1.9L12 17l-1.6-5.1L5 10l5.4-1.9L12 3Z" />
      <path d="m18 15 .8 2.2L21 18l-2.2.8L18 21l-.8-2.2L15 18l2.2-.8L18 15Z" />
    </svg>
  );
}

const root = document.getElementById('root');

if (root) {
  createRoot(root).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
}
