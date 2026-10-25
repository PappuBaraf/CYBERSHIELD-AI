import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

const pages = ['Overview', 'Live Protection', 'Log Analyzer', 'Incidents', 'Investigation', 'Threat Intelligence', 'AI Assistant', 'Reports', 'Settings'];
const icons = ['◈', '●', '▤', '▣', '⌕', '◉', '✳', '⇩', '⚙'];
const analyzerDemoRecords = [
  { eventType: 'authentication', status: 'failed', message: 'Repeated login failures', username: 'demo-user-01', sourceIp: '192.0.2.41', count: 12 },
  { eventType: 'authentication', status: 'success', message: 'Login from a new country; unusual context', username: 'demo-user-02', sourceIp: '198.51.100.22' },
  { eventType: 'network', message: 'Port scan pattern; many destination ports', sourceIp: '203.0.113.17', count: 24 },
  { eventType: 'network', message: 'Unusual outbound traffic; potential data exfiltration', sourceIp: '192.0.2.63', bytes: 85000000 },
  { eventType: 'dns', message: 'Suspicious DNS query with encoded domain and long DNS label', sourceIp: '198.51.100.45' },
  { eventType: 'web', message: 'HTTP 500 repeated server error spike', service: 'demo-web' },
  { eventType: 'identity', message: 'Administrator privilege change outside approved window', username: 'demo-user-07' },
  { eventType: 'file', message: 'Unexpected access to sensitive file', path: 'DEMO/finance-sample.csv', username: 'demo-user-08' },
  { eventType: 'api', message: 'Rate limit exceeded repeatedly', service: 'demo-api', count: 30 },
  { eventType: 'admin', message: 'Unusual administrative action outside approved window', username: 'demo-admin-10', indicatorId: 'CSAI-DEMO-IOC-0001', cve: 'CVE-2021-44228' },
];

async function api(path, options = {}) {
  const response = await fetch(`/api${path}`, {
    ...options,
    headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function App() {
  const [collapsed, setCollapsed] = useState(false);
  const [active, setActive] = useState('Overview');
  const [health, setHealth] = useState(null);
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [logText, setLogText] = useState('');
  const [analysis, setAnalysis] = useState(null);
  const [question, setQuestion] = useState('');
  const [answer, setAnswer] = useState(null);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [note, setNote] = useState('');
  const [investigation, setInvestigation] = useState(null);
  const [onboarding, setOnboarding] = useState(true);
  const [assistantConfig, setAssistantConfig] = useState({ provider: 'offline', model: null, connected: false });

  async function loadPage(page = active) {
    setError('');
    setData(null);
    try {
      if (page === 'Overview') setData(await api('/dashboard'));
      else if (page === 'Incidents') {
        const [incidents, alerts] = await Promise.all([api('/incidents'), api('/alerts')]);
        setData({ ...incidents, ...alerts });
      }
      else if (page === 'Investigation') setData(await api('/investigations'));
      else if (page === 'Threat Intelligence') setData(await api('/knowledge'));
      else if (page === 'Reports') {
        const audit = await api('/audit');
        setData(audit);
      }
      else if (page === 'Settings') setData(await api('/settings'));
    } catch (e) { setError(e.message); }
  }

  useEffect(() => {
    Promise.all([api('/health'), api('/settings')]).then(([healthState, settings]) => {
      setHealth(healthState);
      setAssistantConfig(settings);
      setOnboarding(!settings.configured);
    }).catch((e) => setError(e.message));
  }, []);
  useEffect(() => { loadPage(active); }, [active]);

  async function runAnalysis(records) {
    setBusy(true); setError(''); setAnalysis(null);
    try {
      const result = await api('/analyze', { method: 'POST', body: JSON.stringify({ records }) });
      setAnalysis(result.analysis);
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  function parseText() {
    const lines = logText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    if (!lines.length) { setError('Paste JSON records or JSONL content first.'); return; }
    try {
      const value = JSON.parse(logText);
      runAnalysis(Array.isArray(value) ? value : [value]);
    } catch {
      const records = lines.map((line) => {
        try { return JSON.parse(line); } catch { return null; }
      });
      runAnalysis(records);
    }
  }

  async function readFile(file) {
    if (!file) return;
    if (file.size > 1024 * 1024) { setError('Select a file smaller than 1 MB.'); return; }
    try {
      const content = await file.text();
      if (file.name.toLowerCase().endsWith('.csv')) {
        const [headerLine, ...rows] = content.split(/\r?\n/).filter(Boolean);
        const headers = headerLine.split(',').map((part) => part.trim());
        const records = rows.slice(0, 5000).map((row) => Object.fromEntries(row.split(',').map((value, index) => [headers[index] || `field${index}`, value.trim()])));
        await runAnalysis(records);
      } else {
        const previous = logText;
        setLogText(content);
        const lines = content.split(/\r?\n/).filter(Boolean);
        try {
          const parsed = JSON.parse(content);
          await runAnalysis(Array.isArray(parsed) ? parsed : [parsed]);
        } catch {
          await runAnalysis(lines.map((line) => { try { return JSON.parse(line); } catch { return null; } }));
        }
        setLogText(previous);
      }
    } catch (e) { setError(`Could not read selected file: ${e.message}`); }
  }

  async function updateIncident(id, fields) {
    setBusy(true); setError('');
    try {
      const result = await api(`/incidents/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(fields) });
      setSelectedIncident(result.incident);
      await loadPage('Incidents');
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  async function openIncident(id) {
    if (!id) return;
    setBusy(true); setError('');
    try {
      const result = await api(`/incidents/${encodeURIComponent(id)}`);
      setSelectedIncident(result.incident);
      setActive('Incidents');
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  async function addNote() {
    if (!selectedIncident || !note.trim()) return;
    setBusy(true); setError('');
    try {
      const result = await api(`/incidents/${encodeURIComponent(selectedIncident.id)}/notes`, { method: 'POST', body: JSON.stringify({ text: note }) });
      setSelectedIncident(result.incident); setNote('');
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  async function askAssistant(event) {
    event.preventDefault(); setBusy(true); setError(''); setAnswer(null);
    try { setAnswer(await api('/assistant/chat', { method: 'POST', body: JSON.stringify({ question }) })); }
    catch (e) { setError(e.message); } finally { setBusy(false); }
  }

  async function explainFindingsWithAssistant(detections) {
    const safeFindings = (detections || []).slice(0, 12).map((finding) => ({
      ruleId: String(finding.ruleId || '').slice(0, 32),
      ruleName: String(finding.ruleName || '').slice(0, 100),
      severity: String(finding.severity || '').slice(0, 16),
      methodology: String(finding.methodology || '').slice(0, 32),
    }));
    if (!safeFindings.length) return;
    const prompt = `Explain these local detection rule summaries and give safe, defensive triage steps. Treat every result as unconfirmed. Do not assume compromise.\n${JSON.stringify(safeFindings)}`;
    setQuestion(prompt); setActive('AI Assistant'); setAnswer(null); setBusy(true); setError('');
    try { setAnswer(await api('/assistant/chat', { method: 'POST', body: JSON.stringify({ question: prompt }) })); }
    catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  async function chooseOffline() {
    setBusy(true); setError('');
    try {
      const settings = await api('/settings', { method: 'POST', body: JSON.stringify({ provider: 'offline' }) });
      setAssistantConfig(settings); setOnboarding(false); setActive('Overview');
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  async function connectGroq(apiKey, model) {
    setBusy(true); setError('');
    try {
      const settings = await api('/settings', { method: 'POST', body: JSON.stringify({ provider: 'groq', apiKey, model }) });
      setAssistantConfig(settings); setOnboarding(false); setActive('Overview');
    } catch (e) { setError(e.message); throw e; }
    finally { setBusy(false); }
  }

  if (onboarding) return <SetupPage busy={busy} error={error} onOffline={chooseOffline} onConnect={connectGroq} />;

  async function startInvestigation(id) {
    setBusy(true); setError('');
    try {
      const result = await api('/investigations', { method: 'POST', body: JSON.stringify({ incidentId: id }) });
      setInvestigation(result.investigation);
      setActive('Investigation');
    } catch (e) { setError(e.message); } finally { setBusy(false); }
  }

  async function openInvestigation(id) {
    setBusy(true); setError('');
    try { setInvestigation((await api(`/investigations/${encodeURIComponent(id)}`)).investigation); }
    catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  function closeInvestigation() { setInvestigation(null); }

  const title = active;
  return <div className="shell">
    <aside className={collapsed ? 'sidebar collapsed' : 'sidebar'}>
      <div className="brand"><span className="brand-mark">C</span>{!collapsed && <span>CYBERSHIELD <b>AI</b></span>}</div>
      <div className="nav-label">WORKSPACE</div>
      <nav>{pages.map((page, i) => <button key={page} className={active === page ? 'nav-item active' : 'nav-item'} title={page} onClick={() => { setActive(page); setSelectedIncident(null); }}><span className="nav-icon">{icons[i]}</span>{!collapsed && <span>{page}</span>}</button>)}</nav>
      <div className="sidebar-bottom"><span className="status-dot" />{!collapsed && <span>LOCAL · SYNTHETIC DEMO</span>}</div>
    </aside>
    <main className="main"><header><button className="toggle" onClick={() => setCollapsed(!collapsed)} aria-label="Toggle sidebar">☰</button><div className="crumb">Workspace <span>/</span> {active}</div><div className="header-right"><span className={health?.ok ? 'online' : 'offline'}><i /> {health?.ok ? 'API ONLINE' : 'API CHECKING'}</span><span className="provider-badge">AI · {assistantConfig.provider?.toUpperCase() || 'OFFLINE'}</span><span className="avatar">CS</span></div></header>
      <section className="content">
        <div className="eyebrow">SECURITY OPERATIONS CENTER · LOCAL EDUCATIONAL PROTOTYPE</div><h1>{title}</h1>
        <p className="intro">{active === 'Overview' ? 'Review local security activity and defensive investigation signals.' : 'Local rule-based analysis; heuristic results are not confirmed attacks.'}</p>
        {error && <div className="notice error" role="alert">{error}<button onClick={() => setError('')} aria-label="Dismiss error">×</button></div>}
        {active === 'Overview' && <Overview data={data} onNavigate={setActive} />}
        {active === 'Live Protection' && <LiveProtection onExplain={explainFindingsWithAssistant} assistantProvider={assistantConfig.provider} />}
        {active === 'Log Analyzer' && <Analyzer logText={logText} setLogText={setLogText} onAnalyze={parseText} onFile={readFile} busy={busy} analysis={analysis} onExplain={explainFindingsWithAssistant} assistantProvider={assistantConfig.provider} />}
        {active === 'Threat Intelligence' && <ThreatIntel documents={data?.documents} />}
        {active === 'Incidents' && <IncidentList data={data} selected={selectedIncident} onSelect={setSelectedIncident} onUpdate={updateIncident} onNoteChange={setNote} note={note} onAddNote={addNote} onInvestigate={startInvestigation} onOpenIncident={openIncident} busy={busy} />}
        {active === 'AI Assistant' && <section className="panel"><h2>{assistantConfig.provider === 'groq' ? 'Groq security assistant' : 'Offline security assistant'}</h2><p className="muted">{assistantConfig.provider === 'groq' ? `Connected to Groq (${assistantConfig.model}). Questions and matched local knowledge excerpts are sent to Groq.` : 'General defensive guidance uses local keyword matching. Connect Groq in Settings for API-backed answers.'} Finding explanations pass rule IDs, names, severity, and method only—never raw log events or evidence.</p><form className="inline-form" onSubmit={askAssistant}><textarea required maxLength={2000} value={question} onChange={(e) => setQuestion(e.target.value)} placeholder="Ask a defensive security question…" /><button className="primary" disabled={busy}>{busy ? 'Thinking…' : assistantConfig.provider === 'groq' ? 'Ask Groq' : 'Ask offline assistant'}</button></form>{answer && <div className="answer"><strong>{answer.provider === 'groq' ? `Groq · ${answer.model}` : 'Offline guidance'}</strong><p>{answer.answer}</p><small>{answer.evidenceVersusInference}</small>{answer.sources?.map((source) => <p className="source" key={source.title}>Source: {source.title} · {source.source}</p>)}</div>}</section>}
        {active === 'Settings' && <section className="panel"><h2>Provider and local settings</h2><div className="setting-card"><strong>Active assistant: {assistantConfig.provider === 'groq' ? `Groq · ${assistantConfig.model}` : 'Offline'}</strong><p>{assistantConfig.provider === 'groq' ? 'Groq is connected. The API key is held in server memory only and is cleared when the local API server stops.' : 'Offline keyword guidance runs locally without credentials.'}</p><button className="primary" onClick={() => setOnboarding(true)}>Change connection</button></div><div className="setting-card"><strong>Backend</strong><p>{health?.ok ? `Healthy · ${health.storage} · 127.0.0.1:3001` : 'Health status unavailable'}</p><p>Frontend: http://127.0.0.1:5173</p></div></section>}
        {active === 'Reports' && <><section className="panel"><h2>Reports & exports</h2><p className="muted">Exports contain local application data only. Check files before sharing.</p><div className="export-actions"><a className="primary link-button" href="/api/exports/incidents">Export incidents (JSON)</a><a className="primary link-button" href="/api/exports/audit">Export audit log (JSON)</a></div></section><section className="panel"><h2>Recent application activity</h2><p className="muted">Local JSON log; not tamper-proof forensic evidence.</p>{data?.entries?.length ? data.entries.slice(0, 20).map((entry) => <div className="audit-row" key={entry.id}><strong>{entry.action}</strong><span>{entry.target}</span><time>{new Date(entry.timestamp).toLocaleString()}</time><small>{entry.result}</small></div>) : <Empty>No audit events recorded.</Empty>}</section></>}
        {active === 'Investigation' && <section className="panel"><h2>Investigation history</h2><p className="muted">Local, read-only investigation records. Start another from an incident. The AI summary step is marked unavailable.</p>{investigation ? <><button className="text-button" onClick={closeInvestigation}>← All investigations</button><InvestigationResult item={investigation} /></> : <InvestigationList items={data?.investigations} onOpen={openInvestigation} busy={busy} />}</section>}
      </section>
    </main>
  </div>;
}

function SetupPage({ busy, error, onOffline, onConnect }) {
  const [apiKey, setApiKey] = useState('');
  const [model, setModel] = useState('openai/gpt-oss-20b');
  return <main className="setup-shell"><section className="setup-card">
    <div className="setup-brand"><span className="brand-mark">C</span><span>CYBERSHIELD <b>AI</b></span></div>
    <div className="eyebrow">LOCAL SECURITY OPERATIONS CENTER</div>
    <h1>Welcome to CyberShield AI</h1>
    <p className="muted">Choose how you want to start. This local app does not create a user account.</p>
    {error && <div className="notice error" role="alert">{error}</div>}
    <div className="setup-options">
      <article className="setup-option"><span className="pill neutral">PRIVATE · LOCAL</span><h2>Continue offline</h2><p className="muted">Use local rules and the built-in defensive knowledge base. No key, account, or external AI request is needed.</p><button className="primary" disabled={busy} onClick={onOffline}>{busy ? 'Opening…' : 'Continue offline'}</button></article>
      <article className="setup-option"><span className="pill neutral">OPTIONAL · GROQ</span><h2>Connect LLM</h2><p className="muted">Paste a Groq API key to test the connection and enable AI answers. The key stays in local server memory and is cleared when the server stops.</p><form onSubmit={(event) => { event.preventDefault(); onConnect(apiKey, model).then(() => setApiKey('')).catch(() => {}); }}>
        <label className="setup-label">Groq API key<input type="password" autoComplete="off" required maxLength={4096} value={apiKey} onChange={(event) => setApiKey(event.target.value)} placeholder="Paste your Groq API key" /></label>
        <label className="setup-label">Model ID<input type="text" required maxLength={120} value={model} onChange={(event) => setModel(event.target.value)} /></label>
        <p className="setup-disclosure">Connect sends the key and a short test prompt to Groq. Assistant questions and matched local knowledge excerpts are also sent to Groq. Provider usage may be billed.</p>
        <button className="primary" disabled={busy || !apiKey.trim()}>{busy ? 'Connecting…' : 'Connect and test Groq'}</button>
      </form></article>
    </div>
  </section></main>;
}

function Overview({ data, onNavigate }) {
  if (!data) return <Loading />;
  return <><div className="demo-banner">DEMO MODE · No live security telemetry is connected; records originate from local synthetic scenarios or your submitted logs.</div><div className="stat-grid"><Stat label="Open incidents" value={data.openIncidents} /><Stat label="Total incidents" value={data.incidents} /><Stat label="Alerts" value={data.alerts} /><Stat label="Analyses" value={data.analyses} /></div><div className="panel"><div className="panel-heading"><h2>Open severity counts</h2><button className="text-button" onClick={() => onNavigate('Incidents')}>View incidents →</button></div><div className="severity-grid">{Object.entries(data.severity || {}).map(([label, value]) => <div className={`severity ${label}`} key={label}><span>{label}</span><strong>{value}</strong></div>)}</div></div><div className="panel"><h2>Recent incidents</h2>{data.recentIncidents?.length ? data.recentIncidents.map((item) => <div className="audit-row" key={item.id}><strong>{item.title}</strong><span className={`pill ${item.severity}`}>{item.severity}</span><span>{item.status}</span><time>{new Date(item.createdAt).toLocaleString()}</time></div>) : <Empty>No incidents. Analyze records or run a scenario to create a local finding.</Empty>}</div></>;
}

function DetectionMethodologies({ onExplain, assistantProvider }) {
  const [checking, setChecking] = useState(false);
  const [selfTest, setSelfTest] = useState(null);
  const [error, setError] = useState('');
  const methods = [
    ['Signature-based', 'Exact-match against one clearly synthetic local training indicator. Not an antivirus engine or production IOC feed.'],
    ['Behavior-based', 'Deterministic rules inspect record text for suspicious authentication, network, DNS, privilege, file, web, API, and admin patterns.'],
    ['Anomaly-based', 'Fixed educational thresholds flag selected counts and byte volumes. They are not learned from your environment; compare with an approved baseline.'],
    ['Intelligence-driven', 'Maps selected rule IDs to MITRE ATT&CK and checks CVEs against the saved CISA KEV snapshot. Events are checked as they arrive; the reference catalog itself is not a real-time feed.'],
  ];
  async function runSelfTest() {
    setChecking(true); setError(''); setSelfTest(null);
    try { setSelfTest((await api('/analyze/preview', { method: 'POST', body: JSON.stringify({ records: analyzerDemoRecords }) })).analysis); }
    catch (reason) { setError(reason.message); }
    finally { setChecking(false); }
  }
  return <><section className="panel"><h2>Detection methodologies</h2><p className="muted">Run a local self-test to exercise every method. Test events are not saved or sent to the AI provider.</p><div className="method-grid">{methods.map(([title, description]) => <article className="method-card" key={title}><strong>{title}</strong><p>{description}</p></article>)}</div><div className="form-actions"><button className="primary" disabled={checking} onClick={runSelfTest}>{checking ? 'Testing local rules…' : 'Run 10-event protection self-test'}</button></div>{error && <div className="notice error" role="alert">{error}</div>}</section>{selfTest && <section className="panel"><div className="panel-heading"><h2>Self-test result · {selfTest.classification}</h2><span>{selfTest.processed} processed · {selfTest.valid} valid · {selfTest.rejected} rejected</span></div>{selfTest.detections.map((finding) => <article className="finding" key={finding.ruleId}><div className="panel-heading"><strong>{finding.ruleId} · {finding.ruleName}</strong><span className="pill neutral">{finding.methodology}</span></div>{finding.intelligenceMatches?.map((match) => <p key={match}>Local CISA KEV match: {match}</p>)}</article>)}<p className="muted">Self-test uses a preview API; it creates no incidents or history.</p><button className="primary" disabled={!selfTest.detections.length || checking} onClick={() => onExplain(selfTest.detections)}>{assistantProvider === 'groq' ? 'Explain findings with Groq' : 'Explain findings offline'}</button><p className="muted">Only rule IDs, names, severity, and method are sent as the assistant question. Raw events and evidence are excluded.</p></section>}</>;
}

function LiveMonitor({ onExplain, assistantProvider }) {
  const [events, setEvents] = useState([]);
  const [streamStatus, setStreamStatus] = useState('connecting');
  const [recordText, setRecordText] = useState('{"eventType":"authentication","status":"failed","message":"Repeated login failures","username":"local-demo-user","count":12}');
  const [busy, setBusy] = useState(false);
  const [running, setRunning] = useState(false);
  const [message, setMessage] = useState('');
  const [problem, setProblem] = useState('');
  const [autoExplain, setAutoExplain] = useState(false);
  const stopDemo = useRef(false);
  const autoExplainRef = useRef(false);
  const autoExplainTimer = useRef(null);
  const pendingFindings = useRef([]);

  useEffect(() => {
    autoExplainRef.current = autoExplain;
    if (!autoExplain && autoExplainTimer.current) {
      clearTimeout(autoExplainTimer.current);
      autoExplainTimer.current = null;
      pendingFindings.current = [];
    }
  }, [autoExplain]);

  useEffect(() => {
    let source;
    let cancelled = false;
    api('/live/events').then((result) => { if (!cancelled) setEvents(result.events || []); }).catch((error) => { if (!cancelled) setProblem(error.message); });
    source = new EventSource('/api/live/stream');
    source.addEventListener('ready', () => setStreamStatus('connected'));
    source.addEventListener('detection', (event) => {
      try {
        const item = JSON.parse(event.data);
        setEvents((current) => [item, ...current.filter((existing) => existing.id !== item.id)].slice(0, 100));
        if (autoExplainRef.current && item.detections?.length) {
          const combined = [...pendingFindings.current, ...item.detections];
          pendingFindings.current = [...new Map(combined.map((finding) => [finding.ruleId, finding])).values()].slice(0, 20);
          if (autoExplainTimer.current) clearTimeout(autoExplainTimer.current);
          autoExplainTimer.current = setTimeout(() => {
            const batch = pendingFindings.current;
            pendingFindings.current = [];
            autoExplainTimer.current = null;
            if (batch.length && autoExplainRef.current) onExplain(batch);
          }, 1500);
        }
      } catch { setProblem('Received an unreadable live event.'); }
    });
    source.onerror = () => setStreamStatus('reconnecting');
    return () => { cancelled = true; source?.close(); stopDemo.current = true; if (autoExplainTimer.current) clearTimeout(autoExplainTimer.current); };
  }, []);

  async function submitEvent(record, synthetic = false) {
    const result = await api('/live/events', { method: 'POST', body: JSON.stringify({ source: synthetic ? 'CyberShield synthetic demo generator' : 'local-forwarder', synthetic, event: record }) });
    return result;
  }

  async function sendManualEvent(event) {
    event.preventDefault(); setBusy(true); setProblem(''); setMessage('');
    try {
      const record = JSON.parse(recordText);
      if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error('Enter one JSON event object.');
      const result = await submitEvent(record);
      setMessage(`Received ${result.accepted} event. ${result.detections} event(s) matched local rules.`);
    } catch (error) { setProblem(error.message); }
    finally { setBusy(false); }
  }

  async function runDemoStream() {
    stopDemo.current = false; setRunning(true); setProblem(''); setMessage('Sending ten synthetic events through the live receiver…');
    try {
      for (let index = 0; index < analyzerDemoRecords.length && !stopDemo.current; index++) {
        const result = await submitEvent(analyzerDemoRecords[index], true);
        setMessage(`Demo stream: ${index + 1}/10 events received · ${result.detections} detections in this event.`);
        if (index < analyzerDemoRecords.length - 1) await new Promise((resolve) => setTimeout(resolve, 900));
      }
    } catch (error) { setProblem(error.message); }
    finally { setRunning(false); stopDemo.current = false; }
  }

  const latestFindings = [...new Map(events.flatMap((item) => item.detections || []).map((finding) => [finding.ruleId, finding])).values()].slice(0, 20);
  return <><div className="demo-banner"><strong>Local real-time event receiver</strong><p>Incoming JSON events are analyzed immediately and pushed to this page over Server-Sent Events. This is live processing of events you submit; it does not automatically read Windows event logs, endpoint telemetry, or a SIEM.</p></div><section className="panel"><div className="panel-heading"><h2>Stream status</h2><span className={`pill ${streamStatus === 'connected' ? 'low' : 'medium'}`}>{streamStatus}</span></div><p className="muted">Listening on the local API stream. Submit a single event or run the synthetic ten-event demo.</p><div className="form-actions"><button className="primary" disabled={running} onClick={runDemoStream}>{running ? 'Demo stream running…' : 'Start 10-event demo stream'}</button><button className="text-button" disabled={!running} onClick={() => { stopDemo.current = true; setMessage('Stopping demo stream…'); }}>Stop demo</button></div><label className="feed-consent"><input type="checkbox" checked={autoExplain} disabled={assistantProvider !== 'groq'} onChange={(event) => setAutoExplain(event.target.checked)} /> Automatically explain new live findings with Groq</label><p className="muted">When enabled, new findings are batched for 1.5 seconds and sent as rule summaries only. Each batch uses Groq API usage. Raw events and evidence stay local. {assistantProvider !== 'groq' ? 'Connect Groq in Settings to enable.' : 'This is off until you enable it.'}</p>{message && <p className="muted" role="status">{message}</p>}{problem && <div className="notice error" role="alert">{problem}</div>}</section><section className="panel"><h2>Submit a local log event</h2><p className="muted">Your event stays on this computer and is stored in the local live-event history. Do not submit secrets or data you are not authorized to process.</p><form onSubmit={sendManualEvent}><textarea className="log-input" aria-label="Single JSON event" value={recordText} onChange={(event) => setRecordText(event.target.value)} /><div className="form-actions"><button className="primary" disabled={busy}>{busy ? 'Submitting…' : 'Submit and detect now'}</button></div></form><details className="live-api-help"><summary>Connect a local log forwarder</summary><p>POST one JSON object as <code>{'{ "source": "my-local-forwarder", "event": { "eventType": "...", "message": "..." } }'}</code> to <code>http://127.0.0.1:3001/api/live/events</code>. Use the application's local API only; no listener is exposed beyond loopback.</p></details></section><section className="panel"><div className="panel-heading"><h2>Live events and detections</h2><span className="pill neutral">{events.length} shown · newest first</span></div>{events.length ? <><div className="form-actions"><button className="primary" disabled={!latestFindings.length || busy} onClick={() => onExplain(latestFindings)}>Explain latest findings {assistantProvider === 'groq' ? 'with Groq' : 'offline'}</button><span className="muted">Only rule summaries are sent to the assistant; event records and evidence stay local.</span></div><div className="live-list">{events.map((item) => <article className="live-event" key={item.id}><div className="panel-heading"><strong>{item.classification === 'Suspicious' ? 'Detection' : 'Event'} · {item.source}</strong><span className={`pill ${item.classification === 'Suspicious' ? 'high' : 'low'}`}>{item.classification}{item.synthetic ? ' · SYNTHETIC' : ''}</span></div><small>{new Date(item.receivedAt).toLocaleString()}</small><pre className="record">{JSON.stringify(item.record, null, 2)}</pre>{item.detections?.length ? item.detections.map((finding) => <div className="finding" key={finding.ruleId}><strong>{finding.ruleId} · {finding.ruleName}</strong><span className="pill neutral">{finding.methodology}</span><p>{finding.explanation}</p></div>) : <p className="muted">No local rule matched this event.</p>}</article>)}</div></> : <div className="empty">Waiting for events. Submit one above or start the synthetic stream.</div>}</section></>;
}

function LiveProtection({ onExplain, assistantProvider }) {
  const [section, setSection] = useState('Monitor');
  const tabs = ['Monitor', 'Malicious links & extension', 'Detection methods'];
  return <><nav className="section-tabs" aria-label="Live protection sections">{tabs.map((item) => <button key={item} className={section === item ? 'section-tab active' : 'section-tab'} onClick={() => setSection(item)}>{item}</button>)}</nav>{section === 'Monitor' && <LiveMonitor onExplain={onExplain} assistantProvider={assistantProvider} />}{section === 'Malicious links & extension' && <BrowserProtection />}{section === 'Detection methods' && <DetectionMethodologies onExplain={onExplain} assistantProvider={assistantProvider} />}</>;
}

function BrowserProtection() {
  const [url, setUrl] = useState('https://paypal-login-security.example/login');
  const [result, setResult] = useState(null);
  const [feed, setFeed] = useState(null);
  const [acceptedTerms, setAcceptedTerms] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => { api('/url/status').then(setFeed).catch((reason) => setError(reason.message)); }, []);
  async function check(event) {
    event.preventDefault(); setBusy(true); setError(''); setResult(null);
    try { setResult(await api('/url/check', { method: 'POST', body: JSON.stringify({ url }) })); }
    catch (reason) { setError(reason.message); }
    finally { setBusy(false); }
  }
  async function refreshFeed() {
    setBusy(true); setError('');
    try { const updated = await api('/url/refresh', { method: 'POST', body: JSON.stringify({ acceptedTerms }) }); setFeed((current) => ({ ...current, ...updated })); }
    catch (reason) { setError(reason.message); }
    finally { setBusy(false); }
  }
  return <><section className="panel"><h2>Check a URL locally</h2><p className="muted">The URL is parsed and checked on this computer against local heuristics and the downloaded feed. The app does not visit the submitted URL. Unlisted does not mean safe.</p><form className="search-row" onSubmit={check}><input aria-label="URL to check" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com/path" /><button className="primary" disabled={busy}>{busy ? 'Checking…' : 'Check URL'}</button></form>{error && <div className="notice error" role="alert">{error}</div>}{result && <div className={`url-verdict ${result.risk}`}><div className="panel-heading"><strong>{result.verdict.replaceAll('-', ' ').toUpperCase()}</strong><span className={`pill ${result.risk}`}>{result.risk} · {result.score}/100</span></div><p>Host: <code>{result.host}</code> · Source: {result.source}</p>{result.reasons.map((reason) => <p key={reason}>{reason}</p>)}</div>}</section><section className="panel"><h2>Phishing feed</h2><p className="muted">{feed?.provider || 'OpenPhish community feed'} refreshes approximately every 12 hours. {feed?.automaticRefresh ? 'Automatic refresh is enabled while the local server runs.' : 'No feed is fetched until you accept its terms and refresh it.'} Browsing URLs are never sent to the feed provider.</p><p>Local snapshot: {feed?.urlCount ?? 0} URLs · {feed?.domainCount ?? 0} blockable domains · {feed?.fetchedAt ? `last refreshed ${new Date(feed.fetchedAt).toLocaleString()}` : 'not downloaded'}</p><label className="feed-consent"><input type="checkbox" checked={acceptedTerms} onChange={(event) => setAcceptedTerms(event.target.checked)} /> I have reviewed and accept the <a href="https://www.openphish.com/terms.html" target="_blank" rel="noreferrer">OpenPhish community feed terms</a>.</label><div className="form-actions"><button className="primary" disabled={busy || !acceptedTerms} onClick={refreshFeed}>Refresh phishing feed</button></div><p className="muted">After a refresh, open the extension popup and sync its blocklist. Feed-listed domains are blocked before browser requests; checks run on link clicks.</p></section><section className="panel"><h2>Install the Chrome / Edge extension</h2><ol className="muted"><li>Open <code>edge://extensions</code> or <code>chrome://extensions</code>.</li><li>Turn on Developer mode, choose <b>Load unpacked</b>, and select this project's <code>extension</code> folder.</li><li>Keep CyberShield running. The extension checks clicked links locally and syncs feed domains for pre-request blocking.</li></ol><div className="notice">Heuristic checks cover ordinary same-tab link clicks. Feed-listed domains are blocked before the request. Typed URLs and redirects may only get a warning after the initial request; modifier/new-tab clicks and non-browser apps can bypass heuristic pre-checks. This is not a replacement for browser Safe Browsing or endpoint protection.</div></section></>;
}

function Analyzer({ logText, setLogText, onAnalyze, onFile, busy, analysis, onExplain, assistantProvider }) {
  const [copyStatus, setCopyStatus] = useState('');
  async function copyDemo() {
    try {
      await navigator.clipboard.writeText(JSON.stringify(analyzerDemoRecords, null, 2));
      setCopyStatus('Copied 10 synthetic records. Paste them into the box below.');
    } catch {
      setLogText(JSON.stringify(analyzerDemoRecords, null, 2));
      setCopyStatus('Clipboard access is unavailable; the 10 synthetic records are loaded below and ready to analyze.');
    }
  }
  return <section className="panel"><h2>Analyze supported log records</h2><p className="muted">Paste JSON/JSONL or upload JSON, JSONL, or CSV (maximum 1 MB, 5,000 records). Analysis stays local. Heuristics are not confirmed attacks.</p><div className="demo-banner"><strong>Local demo lab · 10 synthetic records</strong><p>Fictional users and documentation-only IP ranges. No live telemetry; analysis runs locally with deterministic rules.</p><div className="form-actions"><button className="primary" onClick={() => { setLogText(JSON.stringify(analyzerDemoRecords, null, 2)); setCopyStatus('10 synthetic records loaded. Run defensive analysis to see the findings.'); }}>Load 10 demo records</button><button className="primary" onClick={copyDemo}>Copy demo JSON</button></div>{copyStatus && <p className="muted" role="status">{copyStatus}</p>}</div><textarea aria-label="JSON or JSONL log records" className="log-input" value={logText} onChange={(e) => setLogText(e.target.value)} placeholder={'{"eventType":"authentication","status":"failed","message":"login failed"}'} /><div className="form-actions"><button className="primary" onClick={onAnalyze} disabled={busy}>Run defensive analysis</button><label className="upload-button">Choose log file<input type="file" accept=".json,.jsonl,.csv,application/json,text/csv" onChange={(e) => onFile(e.target.files?.[0])} /></label></div>{busy && <p className="muted">Analyzing…</p>}{analysis && <div className="analysis-result"><div className="result-top"><h3>{analysis.classification}</h3><span>{analysis.processed} processed · {analysis.valid} valid · {analysis.rejected} rejected</span></div>{analysis.detections.length ? <>{analysis.detections.map((d) => <div className="finding" key={d.ruleId}><div className="panel-heading"><strong>{d.ruleId} · {d.ruleName}</strong><span className={`pill ${d.severity}`}>{d.severity}</span></div><p className="method-label">{d.methodology || 'Behavior-based'}</p>{d.explanation && <p>{d.explanation}</p>}{d.techniques?.map((technique) => <p className="source" key={technique.id}>ATT&amp;CK candidate mapping: {technique.id} · {technique.name}</p>)}{d.intelligenceMatches?.map((match) => <p className="source" key={match}>Matched local CISA KEV snapshot: {match}</p>)}<p><b>Recommended:</b> {d.recommendation}</p><small>Evidence: {d.evidence.join(' | ')}</small></div>)}<div className="form-actions"><button className="primary" disabled={busy} onClick={() => onExplain(analysis.detections)}>Explain findings {assistantProvider === 'groq' ? 'with Groq' : 'offline'}</button><span className="muted">Only rule IDs, names, severity, and method go to the assistant; raw records and evidence remain local.</span></div></> : <Empty>No rules matched these valid records.</Empty>}</div>}</section>;
}

function IncidentList({ data, selected, onSelect, onUpdate, onNoteChange, note, onAddNote, onInvestigate, onOpenIncident, busy }) {
  if (!selected) return <><section className="panel"><h2>Incident queue</h2>{data?.incidents?.length ? <div className="table-wrap"><table><thead><tr><th>Title</th><th>Severity</th><th>Status</th><th>Owner</th><th>Created</th></tr></thead><tbody>{data.incidents.map((item) => <tr key={item.id} onClick={() => onSelect(item)}><td>{item.title}</td><td><span className={`pill ${item.severity}`}>{item.severity}</span></td><td>{item.status}</td><td>{item.owner || 'Unassigned'}</td><td>{new Date(item.createdAt).toLocaleString()}</td></tr>)}</tbody></table></div> : <Empty>No incidents yet. Analyze records to create a local finding.</Empty>}</section><section className="panel"><h2>Recent alerts</h2>{data?.alerts?.length ? data.alerts.slice(-10).reverse().map((item, i) => <article className="setting-card alert-card" key={item.id || i}><div className="panel-heading"><strong>{item.title || 'Alert'}</strong><span className={`pill ${item.severity || 'low'}`}>{item.severity || 'info'}</span></div><p>{item.description || 'No additional details.'}</p><small>{item.source || 'Local'} · {new Date(item.createdAt || Date.now()).toLocaleString()}{item.synthetic ? ' · SYNTHETIC' : ''}</small>{item.incidentId && <button className="primary" disabled={busy} onClick={() => onOpenIncident(item.incidentId)}>View incident</button>}</article>) : <Empty>No alerts have been recorded.</Empty>}</section></>;
  return <section className="panel"><button className="text-button" onClick={() => onSelect(null)}>← All incidents</button><h2>{selected.title}</h2><div className="incident-meta"><span className={`pill ${selected.severity}`}>{selected.severity}</span><span>Created {new Date(selected.createdAt).toLocaleString()}</span></div><div className="form-actions"><label>Status <select value={selected.status} onChange={(e) => onUpdate(selected.id, { status: e.target.value })} disabled={busy}>{['New', 'Investigating', 'Contained', 'Resolved', 'False Positive'].map((v) => <option key={v}>{v}</option>)}</select></label><label>Owner <input value={selected.owner} maxLength={100} onChange={(e) => onUpdate(selected.id, { owner: e.target.value })} /></label><button className="primary" onClick={() => onInvestigate(selected.id)} disabled={busy}>Start investigation</button></div><h3>Evidence</h3>{selected.evidence?.map((item, i) => <pre className="record" key={i}>{item}</pre>)}<h3>Triggered rules</h3>{selected.detections?.map((d) => <div className="finding" key={d.ruleId}><strong>{d.ruleId} · {d.ruleName}</strong><p>{d.explanation}</p><small>{d.recommendation}</small></div>)}<h3>Investigation notes</h3>{selected.notes?.map((item) => <div className="note" key={item.id}><p>{item.text}</p><small>{new Date(item.createdAt).toLocaleString()}</small></div>)}<form className="inline-form" onSubmit={(e) => { e.preventDefault(); onAddNote(); }}><textarea value={note} maxLength={2000} onChange={(e) => onNoteChange(e.target.value)} placeholder="Add an investigation note…" /><button className="primary" disabled={busy}>Add note</button></form></section>;
}

function ThreatIntel({ documents }) {
  const [query, setQuery] = useState('');
  const records = (documents || []).filter((doc) => doc.category === 'CISA KEV' && `${doc.title} ${doc.content}`.toLowerCase().includes(query.toLowerCase()));
  return <section className="panel"><h2>Threat intelligence snapshot</h2><p className="muted">Curated CISA Known Exploited Vulnerabilities data for local CVE matching. It is a dated snapshot, not a live feed; confirm current affected versions and vendor guidance before action.</p><div className="search-row"><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter CVE, vendor, or product…" aria-label="Filter threat references" /></div><div className="threat-grid">{records.length ? records.map((doc) => <article className="document threat-card" key={doc.id}><span className="pill high">CISA KEV · {doc.snapshotDate}</span><h3>{doc.title}</h3><p>{doc.content}</p><small>{doc.source}</small></article>) : <Empty>No matching CISA KEV references.</Empty>}</div></section>;
}
function InvestigationResult({ item }) {
  return <><p>Investigation {item.id} · {new Date(item.createdAt).toLocaleString()}</p>{item.steps.map((step) => <div className="audit-row" key={step.name}><strong>{step.name}</strong><span>{step.status}</span><small>{Array.isArray(step.result) ? step.result.join(', ') || 'No matching sources' : step.result}</small></div>)}<h3>Report</h3>{item.report.findings.map((finding) => <p key={finding.ruleId}>{finding.ruleName}: {finding.explanation}</p>)}<h3>Defensive next steps</h3>{item.report.nextSteps.map((step, i) => <p key={i}>{step}</p>)}<p className="muted">{item.report.caveat}</p></>;
}
function InvestigationList({ items, onOpen, busy }) {
  return items?.length ? <div className="table-wrap"><table><thead><tr><th>Incident</th><th>Created</th><th>Provider</th><th>Action</th></tr></thead><tbody>{items.map((item) => <tr key={item.id}><td>{item.report?.title || item.incidentId}</td><td>{new Date(item.createdAt).toLocaleString()}</td><td>{item.provider || 'offline'}</td><td><button className="primary" disabled={busy} onClick={() => onOpen(item.id)}>Open report</button></td></tr>)}</tbody></table></div> : <Empty>No investigations yet. Open an incident and choose “Start investigation”.</Empty>;
}
function Stat({ label, value }) { return <div className="stat-card"><span>{label}</span><strong>{value ?? 0}</strong></div>; }
function Empty({ children }) { return <div className="empty">{children}</div>; }
function Loading() { return <div className="panel muted">Loading local dashboard data…</div>; }

createRoot(document.getElementById('root')).render(<App />);
