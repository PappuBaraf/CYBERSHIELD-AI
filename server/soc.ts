import { copyFile, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";

export type Severity = "critical" | "high" | "medium" | "low";
export type IncidentStatus = "New" | "Investigating" | "Contained" | "Resolved" | "False Positive";

export interface Detection {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  explanation: string;
  evidence: string[];
  recommendation: string;
  methodology?: "Signature-based" | "Behavior-based" | "Anomaly-based" | "Intelligence-driven";
  techniques?: Array<{ id: string; name: string; url: string }>;
  intelligenceMatches?: string[];
}

const techniqueByRule: Record<string, Array<{ id: string; name: string; url: string }>> = {
  "AUTH-001": [{ id: "T1110", name: "Brute Force", url: "https://attack.mitre.org/techniques/T1110/" }],
  "AUTH-002": [{ id: "T1078", name: "Valid Accounts", url: "https://attack.mitre.org/techniques/T1078/" }],
  "NET-001": [{ id: "T1046", name: "Network Service Discovery", url: "https://attack.mitre.org/techniques/T1046/" }],
  "NET-002": [{ id: "T1041", name: "Exfiltration Over C2 Channel (candidate mapping)", url: "https://attack.mitre.org/techniques/T1041/" }],
  "DNS-001": [{ id: "T1071.004", name: "Application Layer Protocol: DNS (candidate mapping)", url: "https://attack.mitre.org/techniques/T1071/004/" }],
};

// Deliberately synthetic training marker; this is not a real malware or threat feed.
const demoSignatures = [{ field: "indicatorId", value: "CSAI-DEMO-IOC-0001", name: "CyberShield training marker" }];

export interface Scenario {
  id: string;
  title: string;
  description: string;
  expectedClassification: "Suspicious" | "Benign";
  records: Record<string, unknown>[];
  explanation: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  createdAt: string;
  updatedAt: string;
  evidence: string[];
  detections: Detection[];
  owner: string;
  notes: Array<{ id: string; text: string; createdAt: string }>;
  history: Array<{ status: IncidentStatus; changedAt: string }>;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  action: string;
  target: string;
  result: string;
  metadata?: Record<string, unknown>;
}

export interface KnowledgeDocument {
  id: string;
  title: string;
  category: string;
  content: string;
  keywords: string[];
  source: string;
}

export const scenarios: Scenario[] = [
  { id: "auth-failures", title: "Repeated authentication failures", description: "Synthetic authentication records with repeated failures.", expectedClassification: "Suspicious", records: [{ eventType: "authentication", status: "failed", username: "analyst-demo", sourceIp: "192.0.2.41", count: 12 }], explanation: "Repeated failures can indicate password guessing; confirm against the identity provider and expected user activity." },
  { id: "suspicious-login", title: "Suspicious login pattern", description: "Synthetic login from an unusual location and time.", expectedClassification: "Suspicious", records: [{ eventType: "login", status: "success", sourceIp: "198.51.100.26", message: "new country login at unusual hour" }], explanation: "An unusual successful login is a review signal, not proof of compromise." },
  { id: "port-scan", title: "Port-scan-like log pattern", description: "Synthetic host records show many destination ports.", expectedClassification: "Suspicious", records: [{ eventType: "network", message: "port scan pattern", sourceIp: "192.0.2.51", count: 24 }], explanation: "Repeated port probes warrant checking authorized scanner schedules and network telemetry." },
  { id: "outbound-traffic", title: "Unusual outbound traffic", description: "Synthetic record with anomalous outbound volume.", expectedClassification: "Suspicious", records: [{ eventType: "network", action: "outbound", message: "unusual outbound traffic volume", bytes: 900000000 }], explanation: "Review the destination, process, and baseline before treating this volume anomaly as malicious." },
  { id: "dns-activity", title: "Suspicious DNS activity", description: "Synthetic DNS record with a long, encoded-looking query label.", expectedClassification: "Suspicious", records: [{ eventType: "dns", message: "suspicious dns query with unusually long encoded domain label" }], explanation: "Long DNS labels may be benign; inspect resolver logs and domain context." },
  { id: "web-errors", title: "Web application error spike", description: "Synthetic web logs with elevated server errors.", expectedClassification: "Suspicious", records: [{ eventType: "http", status: 500, message: "server error spike", count: 35 }], explanation: "Correlate server errors with deployment and request logs; error spikes alone do not establish an attack." },
  { id: "privilege-change", title: "Unexpected privilege change", description: "Synthetic record for a privilege change outside the normal window.", expectedClassification: "Suspicious", records: [{ eventType: "privilege", action: "privilege escalation", message: "unexpected administrator privilege change" }], explanation: "Verify the change against approved access requests and audit records." },
  { id: "file-access", title: "Unexpected file access", description: "Synthetic record for unusual access to a sensitive file.", expectedClassification: "Suspicious", records: [{ eventType: "file", action: "access", message: "unexpected access to sensitive file outside normal pattern" }], explanation: "Confirm the actor, resource, and business context with file audit logs." },
  { id: "rate-limit", title: "Repeated rate-limit events", description: "Synthetic API gateway logs with repeated throttling.", expectedClassification: "Suspicious", records: [{ eventType: "api", message: "rate limit exceeded repeatedly", count: 19 }], explanation: "Check for client retries, load tests, and expected service behavior before escalation." },
  { id: "admin-actions", title: "Unusual administrative actions", description: "Synthetic audit record for an unexpected admin action.", expectedClassification: "Suspicious", records: [{ eventType: "admin", action: "configuration changed", message: "unusual administrative action outside approved window" }], explanation: "Validate the actor, change ticket, and administrative audit trail." },
  { id: "exfil-indicator", title: "Potential data-exfiltration indicator", description: "Synthetic outbound transfer record; no real traffic is generated.", expectedClassification: "Suspicious", records: [{ eventType: "network", action: "outbound", message: "potential data exfiltration indicator synthetic transfer", bytes: 1500000000 }], explanation: "Review destination and data handling records; this synthetic heuristic is not confirmation of exfiltration." },
  { id: "benign-activity", title: "Benign scheduled activity", description: "Synthetic expected maintenance activity.", expectedClassification: "Benign", records: [{ eventType: "maintenance", action: "scheduled backup", message: "approved routine backup completed", status: "success" }], explanation: "No included rule matched this routine maintenance record." },
];

const defaultKnowledge: KnowledgeDocument[] = [
  { id: "kb-account-review", title: "Account activity triage", category: "Identity", content: "For unusual logins, verify the account owner, source context, MFA events, device posture, and approved travel. Correlate with identity-provider audit logs. Do not disable accounts solely from a heuristic finding.", keywords: ["login", "authentication", "account", "mfa", "identity"], source: "Built-in defensive guidance" },
  { id: "kb-network-review", title: "Network anomaly triage", category: "Network", content: "Validate network anomalies against approved scanners, change windows, asset ownership, and established traffic baselines. Preserve relevant logs and escalate through the organization's incident process.", keywords: ["network", "port", "outbound", "dns", "traffic"], source: "Built-in defensive guidance" },
  { id: "kb-incident", title: "Incident investigation basics", category: "Response", content: "Record timestamps, evidence sources, scope, and uncertainty. Prefer read-only validation and approved procedures. Keep containment or destructive actions under explicit human authorization.", keywords: ["incident", "evidence", "investigation", "response", "containment"], source: "Built-in defensive guidance" },
];

const dataDirectory = path.resolve(process.cwd(), "data");
const writeQueues = new Map<string, Promise<void>>();

export async function readJson<T>(filename: string, fallback: T): Promise<T> {
  const target = path.join(dataDirectory, filename);
  await mkdir(dataDirectory, { recursive: true });
  let text: string;
  try {
    text = await readFile(target, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      await writeJson(filename, fallback);
      return fallback;
    }
    throw new Error(`Unable to read ${filename}`, { cause: error });
  }
  try {
    return JSON.parse(text) as T;
  } catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    const backup = `${target}.${new Date().toISOString().replace(/[:.]/g, "-")}.corrupt`;
    await copyFile(target, backup);
    await writeJson(filename, fallback);
    return fallback;
  }
}

export async function writeJson<T>(filename: string, value: T): Promise<void> {
  if (path.basename(filename) !== filename) throw new Error("Invalid data filename");
  const target = path.join(dataDirectory, filename);
  const previous = writeQueues.get(target) ?? Promise.resolve();
  const next = previous.catch(() => undefined).then(async () => {
    await mkdir(dataDirectory, { recursive: true });
    const temporary = `${target}.${randomUUID()}.tmp`;
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    await rename(temporary, target);
  });
  writeQueues.set(target, next);
  try { await next; } finally { if (writeQueues.get(target) === next) writeQueues.delete(target); }
}

const stringify = (record: Record<string, unknown>) => Object.entries(record)
  .map(([key, value]) => `${key}=${String(value)}`).join(" ").toLowerCase();

const ruleDefinitions: Array<{ id: string; name: string; severity: Severity; pattern: RegExp; explanation: string; recommendation: string }> = [
  { id: "AUTH-001", name: "Repeated authentication failures", severity: "high", pattern: /(authentication|login).{0,40}(fail|denied)|(?:fail|denied).{0,40}(authentication|login)/, explanation: "Repeated authentication failure indicators were present.", recommendation: "Validate account activity and identity-provider logs; check approved testing before escalation." },
  { id: "AUTH-002", name: "Unusual login context", severity: "medium", pattern: /(unusual|new country|impossible travel).{0,50}login|login.{0,50}(unusual|new country|impossible travel)/, explanation: "The record describes a login context that may be unusual.", recommendation: "Confirm the user, location, device, and MFA context with identity logs." },
  { id: "NET-001", name: "Port-scan-like pattern", severity: "medium", pattern: /port scan|port probe|many destination ports/, explanation: "The record contains a port-scan-like indicator.", recommendation: "Check whether the source is an authorized scanner and review network flow logs." },
  { id: "NET-002", name: "Unusual outbound traffic", severity: "medium", pattern: /unusual outbound|potential data exfiltration|exfiltration indicator/, explanation: "The record contains an unusual outbound transfer indicator.", recommendation: "Validate destination, process, and approved data-transfer context." },
  { id: "DNS-001", name: "Suspicious DNS pattern", severity: "medium", pattern: /suspicious dns|encoded domain|long dns label/, explanation: "The record contains a suspicious DNS pattern indicator.", recommendation: "Review the resolver query, domain context, and endpoint telemetry." },
  { id: "WEB-001", name: "Web server error spike", severity: "low", pattern: /server error spike|http.{0,10}5\d\d.{0,30}(spike|repeated)/, explanation: "The record indicates elevated web server errors.", recommendation: "Correlate with deployments, request rates, and application logs." },
  { id: "IAM-001", name: "Privilege change", severity: "high", pattern: /privilege escalation|administrator privilege change|privilege.{0,20}change/, explanation: "The record describes a privilege change requiring verification.", recommendation: "Verify the actor and approved change record; review access audit logs." },
  { id: "FILE-001", name: "Unexpected sensitive-file access", severity: "medium", pattern: /unexpected access to sensitive file|sensitive file.{0,30}unusual/, explanation: "The record describes potentially unusual access to a sensitive file.", recommendation: "Confirm user authorization and review file access audit records." },
  { id: "API-001", name: "Repeated rate limiting", severity: "low", pattern: /rate limit exceeded repeatedly|repeated rate.limit/, explanation: "Repeated API rate-limit indicators were found.", recommendation: "Check client retries, service health, and authorized load tests." },
  { id: "ADMIN-001", name: "Unusual administrative action", severity: "medium", pattern: /unusual administrative action|admin.{0,30}outside approved window/, explanation: "The record describes an administrative action outside an expected context.", recommendation: "Confirm the actor, change ticket, and administrative audit trail." },
];

export function analyzeRecords(records: unknown[], intelDocuments: KnowledgeDocument[] = []): { processed: number; valid: number; rejected: number; detections: Detection[]; classification: "Suspicious" | "Benign" } {
  const valid = records.filter((record): record is Record<string, unknown> => !!record && typeof record === "object" && !Array.isArray(record));
  const detections: Detection[] = [];
  for (const definition of ruleDefinitions) {
    const matches = valid.map(stringify).filter((text) => definition.pattern.test(text));
    if (matches.length) detections.push({
      ruleId: definition.id, ruleName: definition.name, severity: definition.severity,
      explanation: definition.explanation,
      evidence: matches.slice(0, 5).map((text) => text.slice(0, 300)),
      recommendation: definition.recommendation,
      methodology: "Behavior-based",
      techniques: techniqueByRule[definition.id] ?? [],
    });
  }
  const signatureMatches = valid.flatMap((record) => demoSignatures.filter((signature) => record[signature.field] === signature.value).map((signature) => `${signature.name} (${signature.field}=${signature.value})`));
  if (signatureMatches.length) detections.push({ ruleId: "SIG-IOC-001", ruleName: "Exact local training-indicator match", severity: "high", explanation: "An exact value matched CyberShield's built-in synthetic training marker. This is not a real-world threat indicator.", evidence: signatureMatches.slice(0, 5), recommendation: "Validate the indicator source and context; this educational marker is not evidence of compromise.", methodology: "Signature-based", techniques: [] });

  const anomalous = valid.filter((record) => {
    const count = Number(record.count);
    const bytes = Number(record.bytes);
    return (Number.isFinite(count) && count >= 10 && /auth|login|network|port|rate|api/i.test(String(record.eventType ?? "") + " " + String(record.message ?? ""))) || (Number.isFinite(bytes) && bytes >= 50_000_000);
  });
  if (anomalous.length) detections.push({ ruleId: "ANOM-001", ruleName: "Reference-threshold anomaly", severity: "medium", explanation: `Record values crossed the educational reference thresholds (count ≥ 10 or outbound bytes ≥ 50 MB). These are fixed demo thresholds, not a learned baseline for your environment.`, evidence: anomalous.slice(0, 5).map((record) => stringify(record).slice(0, 300)), recommendation: "Compare with an approved local baseline and expected workload before escalation.", methodology: "Anomaly-based", techniques: [] });

  const intel = new Set(intelDocuments.filter((item) => item.category === "CISA KEV").map((item) => `${item.title} ${item.content}`.toUpperCase()));
  const kevMatches = new Set<string>();
  for (const record of valid) {
    const text = stringify(record).toUpperCase();
    for (const cve of text.match(/CVE-\d{4}-\d{4,}/g) ?? []) if ([...intel].some((entry) => entry.includes(cve))) kevMatches.add(cve);
  }
  if (kevMatches.size) detections.push({ ruleId: "INTEL-KEV-001", ruleName: "CISA KEV snapshot match", severity: "high", explanation: "A CVE in submitted records matched the locally stored CISA Known Exploited Vulnerabilities snapshot. Verify the affected asset and patch status.", evidence: [...kevMatches].slice(0, 10), recommendation: "Confirm the vulnerable product/version and remediation status. The local catalog is a dated snapshot, not a live feed.", methodology: "Intelligence-driven", techniques: [], intelligenceMatches: [...kevMatches] });
  return { processed: records.length, valid: valid.length, rejected: records.length - valid.length, detections, classification: detections.length ? "Suspicious" : "Benign" };
}

export function searchKnowledge(documents: KnowledgeDocument[], query: string, limit = 3): KnowledgeDocument[] {
  const tokens = query.toLowerCase().match(/[a-z0-9]{3,}/g) ?? [];
  if (!tokens.length) return [];
  return documents.map((document) => {
    const searchable = `${document.title} ${document.category} ${document.content} ${document.keywords.join(" ")}`.toLowerCase();
    const score = Array.from(new Set(tokens)).reduce((count, token) => count + (searchable.includes(token) ? 1 : 0), 0);
    return { document, score };
  }).filter(({ score }) => score > 0)
    .sort((a, b) => b.score - a.score || a.document.title.localeCompare(b.document.title))
    .slice(0, Math.max(1, Math.min(limit, 5)))
    .map(({ document }) => document);
}

export const emptyAudit: AuditEntry[] = [];
export const emptyIncidents: Incident[] = [];
export const emptyAlerts: Array<Record<string, unknown>> = [];
export const emptyAnalyses: Array<Record<string, unknown>> = [];
export const seededKnowledge = defaultKnowledge;
