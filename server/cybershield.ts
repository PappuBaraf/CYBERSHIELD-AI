import express from "express";
import cors from "cors";
import { randomUUID } from "node:crypto";
import { checkUrl, isSharedHostingHost, type UrlFeed } from "./urlProtection.js";
import {
  analyzeRecords, emptyAlerts, emptyAnalyses, emptyAudit, emptyIncidents,
  readJson, scenarios, searchKnowledge, seededKnowledge, writeJson,
  type AuditEntry, type Incident, type IncidentStatus, type KnowledgeDocument, type Scenario, type Severity,
} from "./soc.js";

const app = express();
const port = Number(process.env.PORT) || 3001;
const statuses: IncidentStatus[] = ["New", "Investigating", "Contained", "Resolved", "False Positive"];
const severities: Severity[] = ["critical", "high", "medium", "low"];
const validProviders = ["offline", "groq"];
const openPhishFeedUrl = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt";
const feedTermsUrl = "https://www.openphish.com/terms.html";
const linkExtensionOrigin = "chrome-extension://mmjljnoikflopbdbgjfddnfcledgfmoj";
type LiveEvent = { id: string; receivedAt: string; source: string; synthetic: boolean; record: Record<string, unknown>; classification: "Suspicious" | "Benign"; detections: ReturnType<typeof analyzeRecords>["detections"] };
const liveClients = new Set<express.Response>();
type GroqConfig = { model: string; apiKey: string };
let groqConfig: GroqConfig | null = null;
let setupChosen = false;
const transitions: Record<IncidentStatus, IncidentStatus[]> = {
  New: ["Investigating", "False Positive"],
  Investigating: ["New", "Contained", "Resolved", "False Positive"],
  Contained: ["Investigating", "Resolved"],
  Resolved: ["Investigating"],
  "False Positive": ["Investigating"],
};

function rateLimit(maximum: number, windowMs: number) {
  const requests = new Map<string, number[]>();
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const now = Date.now();
    const key = req.ip || req.socket.remoteAddress || "local";
    const recent = (requests.get(key) ?? []).filter((timestamp) => now - timestamp < windowMs);
    if (recent.length >= maximum) return res.status(429).json({ error: "Rate limit exceeded; retry later." });
    recent.push(now);
    requests.set(key, recent);
    return next();
  };
}

app.disable("x-powered-by");
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  next();
});
app.use(cors((req, callback) => {
  const origin = req.header("Origin");
  const isClient = origin === (process.env.CLIENT_ORIGIN || "http://127.0.0.1:5173");
  const isAllowedExtensionRequest = origin === linkExtensionOrigin && ["/api/url/check", "/api/url/blocklist"].includes(req.path);
  callback(null, { origin: isClient || isAllowedExtensionRequest ? origin : false, methods: ["GET", "POST", "PATCH", "OPTIONS"], allowedHeaders: ["Content-Type"] });
}));
app.use(express.json({ limit: "1mb" }));

async function audit(action: string, target: string, result: string, metadata?: Record<string, unknown>) {
  const entries = await readJson<AuditEntry[]>("audit-log.json", emptyAudit);
  entries.push({ id: randomUUID(), timestamp: new Date().toISOString(), action, target, result, metadata });
  await writeJson("audit-log.json", entries.slice(-5000));
}

async function loadIncidents() { return readJson<Incident[]>("incidents.json", emptyIncidents); }
async function loadKnowledge() { return readJson<KnowledgeDocument[]>("knowledge-base.json", seededKnowledge); }
function validId(id: string) { return /^[\w-]{1,80}$/.test(id); }

async function refreshOpenPhish(acceptedTermsAt: string): Promise<UrlFeed> {
  const response = await fetch(openPhishFeedUrl, { signal: AbortSignal.timeout(12000), headers: { "User-Agent": "CyberShield-AI-Educational-Local/1.0" } });
  if (!response.ok) throw new Error(`OpenPhish feed returned HTTP ${response.status}.`);
  const text = await response.text();
  if (text.length > 8_000_000) throw new Error("Feed is larger than the 8 MB safety limit.");
  const urls = [...new Set(text.split(/\r?\n/).map((line) => line.trim()).filter((line) => {
    if (!line || line.length > 4096) return false;
    try { return ["http:", "https:"].includes(new URL(line).protocol); } catch { return false; }
  }))].slice(0, 20000);
  if (!urls.length) throw new Error("Feed contained no usable HTTP(S) URLs.");
  const feed: UrlFeed = { provider: "OpenPhish community feed", fetchedAt: new Date().toISOString(), acceptedTermsAt, updateIntervalHours: 12, urls };
  await writeJson("url-threats.json", feed);
  await audit("url_threat_feed_refreshed", "OpenPhish community feed", "completed", { urlCount: urls.length });
  return feed;
}

app.get("/api/health", (_req, res) => res.json({
  ok: true, queue: false, time: new Date().toISOString(), storage: "local-json",
  ai: { provider: "offline", connected: false, liveProvidersImplemented: false },
}));

app.get("/api/dashboard", async (_req, res, next) => {
  try {
    const incidents = await loadIncidents();
    const alerts = await readJson<Array<Record<string, unknown>>>("alerts.json", emptyAlerts);
    const analyses = await readJson<Array<Record<string, unknown>>>("analyses.json", emptyAnalyses);
    const counts = Object.fromEntries(severities.map((severity) => [severity, incidents.filter((item) => item.severity === severity && !["Resolved", "False Positive"].includes(item.status)).length]));
    res.json({ syntheticData: true, incidents: incidents.length, openIncidents: incidents.filter((item) => !["Resolved", "False Positive"].includes(item.status)).length, alerts: alerts.length, analyses: analyses.length, severity: counts, recentIncidents: incidents.slice(-5).reverse() });
  } catch (error) { next(error); }
});

app.get("/api/scenarios", async (_req, res, next) => {
  try { res.json({ synthetic: true, scenarios: await readJson<Scenario[]>("scenarios.json", scenarios) }); }
  catch (error) { next(error); }
});
app.post("/api/scenarios/:id/run", async (req, res, next) => {
  try {
    const scenario = (await readJson<Scenario[]>("scenarios.json", scenarios)).find((item) => item.id === req.params.id);
    if (!scenario) return res.status(404).json({ error: "Scenario not found" });
    const result = analyzeRecords(scenario.records);
    await audit("scenario_run", scenario.id, "completed", { classification: result.classification, detections: result.detections.length });
    return res.json({ scenario: scenario.id, synthetic: true, expectedClassification: scenario.expectedClassification, ...result, matchesExpected: result.classification === scenario.expectedClassification });
  } catch (error) { return next(error); }
});

app.get("/api/incidents", async (req, res, next) => {
  try {
    let incidents = await loadIncidents();
    if (typeof req.query.status === "string") incidents = incidents.filter((item) => item.status === req.query.status);
    if (typeof req.query.search === "string") {
      const query = req.query.search.toLowerCase();
      incidents = incidents.filter((item) => `${item.title} ${item.owner} ${item.status}`.toLowerCase().includes(query));
    }
    res.json({ incidents: incidents.reverse() });
  } catch (error) { next(error); }
});

app.get("/api/incidents/:id", async (req, res, next) => {
  try {
    if (!validId(req.params.id)) return res.status(400).json({ error: "Invalid incident ID" });
    const incident = (await loadIncidents()).find((item) => item.id === req.params.id);
    if (!incident) return res.status(404).json({ error: "Incident not found" });
    return res.json({ incident });
  } catch (error) { return next(error); }
});

app.post("/api/incidents", async (req, res, next) => {
  try {
    const { title, severity, evidence = [], detections = [] } = req.body ?? {};
    if (typeof title !== "string" || !title.trim() || title.length > 200 || !severities.includes(severity) || !Array.isArray(evidence) || evidence.length > 100 || !Array.isArray(detections)) {
      return res.status(400).json({ error: "Invalid incident input" });
    }
    const now = new Date().toISOString();
    const incident: Incident = { id: randomUUID(), title: title.trim(), severity, status: "New", createdAt: now, updatedAt: now, evidence: evidence.filter((item: unknown) => typeof item === "string").slice(0, 100), detections, owner: "", notes: [], history: [{ status: "New", changedAt: now }] };
    const incidents = await loadIncidents();
    incidents.push(incident);
    await writeJson("incidents.json", incidents);
    await audit("incident_created", incident.id, "completed", { severity });
    return res.status(201).json({ incident });
  } catch (error) { return next(error); }
});

app.patch("/api/incidents/:id", async (req, res, next) => {
  try {
    if (!validId(req.params.id)) return res.status(400).json({ error: "Invalid incident ID" });
    const incidents = await loadIncidents();
    const incident = incidents.find((item) => item.id === req.params.id);
    if (!incident) return res.status(404).json({ error: "Incident not found" });
    const { status, owner } = req.body ?? {};
    if (status !== undefined && !statuses.includes(status)) return res.status(400).json({ error: "Invalid incident status" });
    if (owner !== undefined && (typeof owner !== "string" || owner.length > 100)) return res.status(400).json({ error: "Invalid owner" });
    if (status && status !== incident.status && !transitions[incident.status].includes(status)) {
      return res.status(409).json({ error: `Status transition from ${incident.status} to ${status} is not allowed` });
    }
    if (status && status !== incident.status) {
      incident.status = status;
      incident.history.push({ status, changedAt: new Date().toISOString() });
    }
    if (owner !== undefined) incident.owner = owner.trim();
    incident.updatedAt = new Date().toISOString();
    await writeJson("incidents.json", incidents);
    await audit("incident_updated", incident.id, "completed", { status: incident.status, owner: incident.owner });
    return res.json({ incident });
  } catch (error) { return next(error); }
});

app.post("/api/incidents/:id/notes", async (req, res, next) => {
  try {
    if (!validId(req.params.id)) return res.status(400).json({ error: "Invalid incident ID" });
    const text = req.body?.text;
    if (typeof text !== "string" || !text.trim() || text.length > 2000) return res.status(400).json({ error: "Note must contain 1-2000 characters" });
    const incidents = await loadIncidents();
    const incident = incidents.find((item) => item.id === req.params.id);
    if (!incident) return res.status(404).json({ error: "Incident not found" });
    incident.notes.push({ id: randomUUID(), text: text.trim(), createdAt: new Date().toISOString() });
    incident.updatedAt = new Date().toISOString();
    await writeJson("incidents.json", incidents);
    await audit("incident_note_added", incident.id, "completed");
    return res.status(201).json({ incident });
  } catch (error) { return next(error); }
});

app.post("/api/analyze/preview", rateLimit(30, 60_000), async (req, res, next) => {
  try {
    const records = Array.isArray(req.body?.records) ? req.body.records : null;
    if (!records || records.length > 5000) return res.status(400).json({ error: "Provide an array of up to 5000 JSON records." });
    return res.json({ analysis: analyzeRecords(records, await loadKnowledge()), persisted: false });
  } catch (error) { return next(error); }
});

app.post("/api/analyze", rateLimit(30, 60_000), async (req, res, next) => {
  try {
    const records = Array.isArray(req.body?.records) ? req.body.records : typeof req.body?.text === "string" ? req.body.text.split(/\r?\n/).filter(Boolean).map((line: string) => {
      try { return JSON.parse(line); } catch { return null; }
    }) : null;
    if (!records || records.length > 5000) return res.status(400).json({ error: "Provide records (maximum 5000) or newline-delimited JSON text" });
    const result = analyzeRecords(records, await loadKnowledge());
    const stored = await readJson<Array<Record<string, unknown>>>("analyses.json", emptyAnalyses);
    const analysis = { id: randomUUID(), timestamp: new Date().toISOString(), ...result };
    stored.push(analysis);
    await writeJson("analyses.json", stored.slice(-1000));
    if (result.detections.length) {
      const severity = result.detections.reduce((best, item) => severities.indexOf(item.severity) < severities.indexOf(best) ? item.severity : best, "low" as Severity);
      const incidents = await loadIncidents();
      const now = new Date().toISOString();
      const incident: Incident = { id: randomUUID(), title: result.detections[0].ruleName, severity, status: "New", createdAt: now, updatedAt: now, evidence: result.detections.flatMap((item) => item.evidence), detections: result.detections, owner: "", notes: [], history: [{ status: "New", changedAt: now }] };
      incidents.push(incident);
      await writeJson("incidents.json", incidents);
    }
    await audit("analysis_run", analysis.id, "completed", { records: result.processed, detections: result.detections.length });
    return res.json({ analysis });
  } catch (error) { return next(error); }
});

function publishLiveEvent(event: LiveEvent) {
  const frame = `event: detection\ndata: ${JSON.stringify(event)}\n\n`;
  for (const client of liveClients) {
    try { client.write(frame); } catch { liveClients.delete(client); }
  }
}

app.get("/api/live/events", async (_req, res, next) => {
  try {
    const events = await readJson<LiveEvent[]>("live-events.json", []);
    res.json({ events: events.slice(-100).reverse(), maxStored: 1000, delivery: "server-sent events" });
  } catch (error) { next(error); }
});

app.get("/api/live/stream", (req, res) => {
  if (liveClients.size >= 20) return res.status(503).end("Too many live dashboard connections");
  res.status(200);
  res.set({ "Content-Type": "text/event-stream", "Cache-Control": "no-cache, no-transform", Connection: "keep-alive", "X-Accel-Buffering": "no" });
  res.flushHeaders();
  liveClients.add(res);
  res.write(`event: ready\ndata: ${JSON.stringify({ connectedAt: new Date().toISOString() })}\n\n`);
  const heartbeat = setInterval(() => { if (!res.destroyed) res.write(": keep-alive\n\n"); }, 15000);
  req.on("close", () => { clearInterval(heartbeat); liveClients.delete(res); });
});

app.post("/api/live/events", rateLimit(120, 60_000), async (req, res, next) => {
  try {
    const records = Array.isArray(req.body?.events) ? req.body.events : req.body?.event ? [req.body.event] : null;
    if (!records || !records.length || records.length > 100 || records.some((record: unknown) => !record || typeof record !== "object" || Array.isArray(record))) {
      return res.status(400).json({ error: "Provide 1–100 JSON event objects using event or events." });
    }
    const source = typeof req.body?.source === "string" ? req.body.source.slice(0, 80) : "local-forwarder";
    const synthetic = req.body?.synthetic === true;
    const knowledge = await loadKnowledge();
    const history = await readJson<LiveEvent[]>("live-events.json", []);
    const alerts = await readJson<Array<Record<string, unknown>>>("alerts.json", emptyAlerts);
    const accepted: LiveEvent[] = records.map((record: Record<string, unknown>) => {
      const result = analyzeRecords([record], knowledge);
      return { id: randomUUID(), receivedAt: new Date().toISOString(), source, synthetic, record, classification: result.classification, detections: result.detections };
    });
    history.push(...accepted);
    await writeJson("live-events.json", history.slice(-1000));
    for (const event of accepted) {
      if (event.detections.length) {
        for (const finding of event.detections) alerts.push({ id: randomUUID(), title: `LIVE · ${finding.ruleName}`, severity: finding.severity, status: "Open", source: event.source, description: finding.explanation, incidentId: null, liveEventId: event.id, createdAt: event.receivedAt, synthetic: event.synthetic, methodology: finding.methodology });
      }
      publishLiveEvent(event);
    }
    await writeJson("alerts.json", alerts.slice(-2000));
    await audit("live_events_received", source, "completed", { records: accepted.length, detections: accepted.filter((event) => event.detections.length).length, synthetic });
    return res.status(202).json({ accepted: accepted.length, detections: accepted.filter((event) => event.detections.length).length, events: accepted });
  } catch (error) { return next(error); }
});

app.get("/api/url/status", async (_req, res, next) => {
  try {
    const feed = await readJson<UrlFeed>("url-threats.json", { provider: "OpenPhish community feed", fetchedAt: null, updateIntervalHours: 12, urls: [] });
    const domains = [...new Set(feed.urls.flatMap((entry) => { try { return [new URL(entry).hostname]; } catch { return []; } }))];
    return res.json({ provider: feed.provider, fetchedAt: feed.fetchedAt, updateIntervalHours: feed.updateIntervalHours, automaticRefresh: !!feed.acceptedTermsAt, urlCount: feed.urls.length, domainCount: domains.length, termsUrl: feedTermsUrl, localOnlyChecks: true });
  } catch (error) { return next(error); }
});

app.get("/api/url/blocklist", async (_req, res, next) => {
  try {
    const feed = await readJson<UrlFeed>("url-threats.json", { provider: "OpenPhish community feed", fetchedAt: null, updateIntervalHours: 12, urls: [] });
    const domains = [...new Set(feed.urls.flatMap((entry) => { try { const host = new URL(entry).hostname; return isSharedHostingHost(host) ? [] : [host]; } catch { return []; } }))].slice(0, 20000);
    return res.json({ domains, fetchedAt: feed.fetchedAt, provider: feed.provider });
  } catch (error) { return next(error); }
});

app.post("/api/url/check", rateLimit(120, 60_000), async (req, res, next) => {
  try {
    if (typeof req.body?.url !== "string") return res.status(400).json({ error: "Provide a URL string." });
    const feed = await readJson<UrlFeed>("url-threats.json", { provider: "OpenPhish community feed", fetchedAt: null, updateIntervalHours: 12, urls: [] });
    try { return res.json(checkUrl(req.body.url, feed)); }
    catch (error) { return res.status(400).json({ error: error instanceof Error ? error.message : "Invalid URL." }); }
  } catch (error) { return next(error); }
});

app.post("/api/url/refresh", rateLimit(3, 60_000), async (req, res, next) => {
  try {
    if (req.body?.acceptedTerms !== true) return res.status(400).json({ error: "Review and accept the OpenPhish community feed terms before refreshing." });
    const oldFeed = await readJson<UrlFeed>("url-threats.json", { provider: "OpenPhish community feed", fetchedAt: null, updateIntervalHours: 12, urls: [] });
    const feed = await refreshOpenPhish(oldFeed.acceptedTermsAt || new Date().toISOString());
    return res.json({ ok: true, provider: feed.provider, urlCount: feed.urls.length, fetchedAt: feed.fetchedAt, updateIntervalHours: feed.updateIntervalHours, automaticRefresh: true });
  } catch (error) { return res.status(502).json({ error: `Unable to refresh the feed: ${error instanceof Error ? error.message : "network error"}. The previous local feed was kept.` }); }
});

const feedRefreshTimer = setInterval(async () => {
  try {
    const feed = await readJson<UrlFeed>("url-threats.json", { provider: "OpenPhish community feed", fetchedAt: null, updateIntervalHours: 12, urls: [] });
    if (feed.acceptedTermsAt) await refreshOpenPhish(feed.acceptedTermsAt);
  } catch (error) { console.warn("Automatic phishing-feed refresh failed; retaining the previous snapshot.", error instanceof Error ? error.message : "network error"); }
}, 12 * 60 * 60 * 1000);
feedRefreshTimer.unref();

app.get("/api/alerts", async (_req, res, next) => {
  try { res.json({ alerts: await readJson("alerts.json", emptyAlerts), synthetic: true }); } catch (error) { next(error); }
});
app.get("/api/audit", async (_req, res, next) => {
  try {
    const entries = await readJson<AuditEntry[]>("audit-log.json", emptyAudit);
    res.json({ entries: entries.slice(-500).reverse(), localJsonLog: true, tamperProof: false });
  } catch (error) { next(error); }
});
app.get("/api/knowledge", async (_req, res, next) => {
  try { res.json({ documents: await loadKnowledge(), retrieval: "keyword matching; not vector search" }); } catch (error) { next(error); }
});
app.get("/api/knowledge/search", async (req, res, next) => {
  try {
    const query = typeof req.query.q === "string" ? req.query.q.slice(0, 500) : "";
    res.json({ documents: searchKnowledge(await loadKnowledge(), query), retrieval: "keyword matching; not vector search" });
  } catch (error) { next(error); }
});

async function groqCompletion(config: GroqConfig, prompt: string): Promise<string> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 25_000);
  try {
    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${config.apiKey}` },
      body: JSON.stringify({ model: config.model, messages: [{ role: "user", content: prompt }], max_completion_tokens: 500 }),
      signal: controller.signal,
    });
    const data = await response.json().catch(() => ({})) as { choices?: Array<{ message?: { content?: string } }> };
    if (!response.ok) throw new Error(`Groq returned HTTP ${response.status}`);
    const answer = data.choices?.[0]?.message?.content;
    if (typeof answer !== "string" || !answer.trim()) throw new Error("Groq returned no text output");
    return answer.trim();
  } finally {
    clearTimeout(timeout);
  }
}

app.post("/api/assistant/chat", rateLimit(10, 60_000), async (req, res, next) => {
  try {
    const question = req.body?.question;
    if (typeof question !== "string" || !question.trim() || question.length > 2000) return res.status(400).json({ error: "Question must contain 1-2000 characters" });
    const sources = searchKnowledge(await loadKnowledge(), question);
    if (groqConfig) {
      const sourceContext = sources.map((source) => `${source.title}: ${source.content}`).join("\n");
      const answer = await groqCompletion(groqConfig, `You are CyberShield AI, an educational defensive security assistant. Give concise, safe, defensive guidance. Treat findings as unverified signals, never claim an attack is confirmed.\n\nMatched local reference material:\n${sourceContext || "No local reference matched."}\n\nUser question:\n${question.trim()}`);
      await audit("assistant_query", "groq-assistant", "completed", { sourceCount: sources.length, model: groqConfig.model });
      return res.json({ answer, provider: "groq", model: groqConfig.model, sources: sources.map(({ title, source }) => ({ title, source })), evidenceVersusInference: "LLM-generated guidance; verify claims against authorized evidence and procedures." });
    }
    const answer = sources.length
      ? `Offline guidance (not an AI-generated assessment): ${sources.map((doc) => doc.content).join(" ")}`
      : "No relevant built-in knowledge documents were found. This offline assistant has no external AI connection; verify findings using your approved procedures.";
    await audit("assistant_query", "offline-assistant", "completed", { sourceCount: sources.length });
    return res.json({ answer, provider: "offline", model: "local-keyword-guidance", sources: sources.map(({ title, source }) => ({ title, source })), evidenceVersusInference: "This is general defensive guidance, not incident-specific evidence or an AI-generated assessment." });
  } catch (error) { return next(error); }
});

app.post("/api/investigations", async (req, res, next) => {
  try {
    const incidentId = req.body?.incidentId;
    if (typeof incidentId !== "string" || !validId(incidentId)) return res.status(400).json({ error: "Valid incidentId is required" });
    const incident = (await loadIncidents()).find((item) => item.id === incidentId);
    if (!incident) return res.status(404).json({ error: "Incident not found" });
    const steps = [
      { name: "Load incident evidence", status: "completed", result: `${incident.evidence.length} evidence item(s) loaded` },
      { name: "Run deterministic rules", status: "completed", result: `${incident.detections.length} rule finding(s) associated` },
      { name: "Retrieve defensive knowledge", status: "completed", result: searchKnowledge(await loadKnowledge(), `${incident.title} ${incident.evidence.join(" ")}`).map((doc) => doc.title) },
      { name: "AI summary", status: "unavailable", result: "No live provider is configured or implemented; no AI response was generated." },
    ];
    const investigation = { id: randomUUID(), incidentId, createdAt: new Date().toISOString(), provider: "offline", steps, report: { title: `Investigation: ${incident.title}`, findings: incident.detections, evidence: incident.evidence, nextSteps: incident.detections.map((item) => item.recommendation), caveat: "Heuristic findings are not confirmation of malicious activity. Validate with authorized sources." } };
    const investigations = await readJson<Array<Record<string, unknown>>>("investigations.json", []);
    investigations.push(investigation);
    await writeJson("investigations.json", investigations.slice(-500));
    await audit("investigation_created", investigation.id, "completed", { incidentId });
    return res.status(201).json({ investigation });
  } catch (error) { return next(error); }
});
app.get("/api/investigations", async (_req, res, next) => {
  try {
    const investigations = await readJson<Array<Record<string, unknown>>>("investigations.json", []);
    return res.json({ investigations: investigations.slice(-500).reverse() });
  } catch (error) { return next(error); }
});
app.get("/api/investigations/:id", async (req, res, next) => {
  try {
    if (!validId(req.params.id)) return res.status(400).json({ error: "Invalid investigation ID" });
    const investigations = await readJson<Array<Record<string, unknown>>>("investigations.json", []);
    const investigation = investigations.find((item) => item.id === req.params.id);
    if (!investigation) return res.status(404).json({ error: "Investigation not found" });
    return res.json({ investigation });
  } catch (error) { return next(error); }
});
app.get("/api/settings", (_req, res) => res.json({
  configured: setupChosen,
  provider: groqConfig ? "groq" : (setupChosen ? "offline" : null),
  model: groqConfig?.model || null,
  connected: Boolean(groqConfig),
  providerOptions: validProviders,
  keyStorage: "memory-only; cleared when the local API server stops",
}));
app.post("/api/settings", async (req, res, next) => {
  const provider = req.body?.provider;
  try {
    if (provider === "offline") {
      groqConfig = null;
      setupChosen = true;
      await audit("provider_selected", "offline", "completed");
      return res.json({ configured: true, provider: "offline", connected: false });
    }
    if (provider !== "groq") return res.status(400).json({ error: "Choose offline mode or Groq." });
    const apiKey = typeof req.body?.apiKey === "string" ? req.body.apiKey.trim() : "";
    const model = typeof req.body?.model === "string" ? req.body.model.trim() : "";
    if (!apiKey || apiKey.length > 4096) return res.status(400).json({ error: "Enter a valid Groq API key (maximum 4096 characters)." });
    if (!model || model.length > 120 || /[\r\n]/.test(model)) return res.status(400).json({ error: "Enter a valid Groq model ID." });
    const candidate = { apiKey, model };
    await groqCompletion(candidate, "Reply with exactly: CyberShield connected");
    groqConfig = candidate;
    setupChosen = true;
    await audit("provider_connected", "groq", "completed", { model });
    return res.json({ configured: true, provider: "groq", model, connected: true, keyStorage: "memory-only" });
  } catch (error) {
    const reason = error instanceof Error ? error.message : "Connection failed";
    const status = reason.match(/HTTP (\d{3})/)?.[1];
    if (status) return res.status(502).json({ error: `Groq connection failed (HTTP ${status}). Check the API key, model ID, and Groq account.` });
    return res.status(502).json({ error: "Could not reach Groq or read its response. Check your network and try again." });
  }
});

app.get("/api/exports/incidents", async (_req, res, next) => {
  try {
    res.setHeader("Content-Disposition", `attachment; filename="cybershield-incidents-${new Date().toISOString().slice(0, 10)}.json"`);
    res.json(await loadIncidents());
    await audit("export", "incidents", "completed");
  } catch (error) { next(error); }
});
app.get("/api/exports/audit", async (_req, res, next) => {
  try {
    const entries = await readJson<AuditEntry[]>("audit-log.json", emptyAudit);
    res.setHeader("Content-Disposition", `attachment; filename="cybershield-audit-${new Date().toISOString().slice(0, 10)}.json"`);
    res.json(entries);
    await audit("export", "audit", "completed", { entries: entries.length });
  } catch (error) { next(error); }
});

app.use((_req, res) => res.status(404).json({ error: "Not found" }));
app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  if (error instanceof SyntaxError) return res.status(400).json({ error: "Invalid JSON request body" });
  console.error("CyberShield API request failed", error instanceof Error ? error.message : "unknown error");
  return res.status(500).json({ error: "Internal server error" });
});

app.listen(port, "127.0.0.1", () => {
  console.log(`CyberShield AI API listening on http://127.0.0.1:${port}`);
});
