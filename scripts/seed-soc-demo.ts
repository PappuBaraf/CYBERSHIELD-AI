import { analyzeRecords, readJson, scenarios, searchKnowledge, seededKnowledge, writeJson, type Incident } from "../server/soc.js";

const snapshotDate = "2026-10-26";
const realThreats = [
  { cveId: "CVE-2021-44228", vendor: "Apache", product: "Log4j2", title: "Log4Shell remote code execution", summary: "A JNDI lookup handling flaw can allow remote code execution in affected Log4j2 deployments.", action: "Inventory affected applications and libraries; apply fixed versions and follow CISA and vendor guidance.", sourceUrl: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2021-44228" },
  { cveId: "CVE-2021-26855", vendor: "Microsoft", product: "Exchange Server", title: "ProxyLogon server-side request forgery", summary: "A server-side request forgery vulnerability in Exchange Server was exploited as part of the ProxyLogon attack chain.", action: "Apply Microsoft security updates and review Exchange systems for signs of compromise.", sourceUrl: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2021-26855" },
  { cveId: "CVE-2023-34362", vendor: "Progress Software", product: "MOVEit Transfer", title: "MOVEit Transfer SQL injection", summary: "An SQL injection vulnerability in MOVEit Transfer was exploited to access affected transfer databases.", action: "Apply vendor updates and follow CISA/FBI MOVEit campaign guidance for affected deployments.", sourceUrl: "https://www.cisa.gov/sites/default/files/2023-06/aa23-158a-stopransomware-cl0p-ransomware-gang-exploits-moveit-vulnerability_7.pdf" },
  { cveId: "CVE-2023-22515", vendor: "Atlassian", product: "Confluence Data Center and Server", title: "Confluence broken access control", summary: "A broken access control issue enabled unauthorized administrator-account creation in affected Confluence instances.", action: "Apply Atlassian updates and inspect instances for unauthorized accounts and compromise indicators.", sourceUrl: "https://www.cisa.gov/sites/default/files/2023-10/aa23-289a-threat-actors-exploit-atlassian-confluence-cve-2023-22515-for-initial-access.pdf" },
  { cveId: "CVE-2023-4966", vendor: "Citrix", product: "NetScaler ADC and Gateway", title: "Citrix Bleed information disclosure", summary: "A buffer overflow in certain NetScaler configurations can disclose sensitive information.", action: "Update affected appliances and follow CISA guidance to review and terminate persistent sessions as directed by the vendor.", sourceUrl: "https://www.cisa.gov/guidance-addressing-citrix-netscaler-adc-and-gateway-vulnerability-cve-2023-4966-citrix-bleed" },
  { cveId: "CVE-2024-3400", vendor: "Palo Alto Networks", product: "PAN-OS GlobalProtect", title: "PAN-OS command injection", summary: "An arbitrary file creation issue can lead to command injection on affected PAN-OS configurations with GlobalProtect enabled.", action: "Check affected versions and configuration, then apply Palo Alto Networks guidance and mitigations.", sourceUrl: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a" },
  { cveId: "CVE-2024-21887", vendor: "Ivanti", product: "Connect Secure and Policy Secure", title: "Ivanti command injection", summary: "A command injection vulnerability in web components of affected Ivanti appliances was exploited in combination with other issues.", action: "Apply Ivanti updates and follow CISA guidance to investigate affected appliances.", sourceUrl: "https://www.cisa.gov/sites/default/files/2024-02/AA24-060B-Threat-Actors-Exploit-Multiple-Vulnerabilities-in-Ivanti-Connect-Secure-and-Policy-Secure-Gateways_0.pdf" },
  { cveId: "CVE-2024-1709", vendor: "ConnectWise", product: "ScreenConnect", title: "ScreenConnect authentication bypass", summary: "An authentication bypass in ScreenConnect can allow an actor with network access to the management interface to create an administrator account.", action: "Update ScreenConnect to the vendor-fixed release and review systems for unauthorized access.", sourceUrl: "https://www.cisa.gov/news-events/alerts/2024/02/22/cisa-adds-one-known-exploited-connectwise-vulnerability-cve-2024-1709-catalog" },
  { cveId: "CVE-2024-23897", vendor: "Jenkins", product: "Jenkins CLI", title: "Jenkins CLI path traversal", summary: "A path traversal issue in the Jenkins command-line interface can expose local files and may lead to further compromise.", action: "Update Jenkins and review exposed controllers using current vendor guidance.", sourceUrl: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2024-23897" },
  { cveId: "CVE-2024-0012", vendor: "Palo Alto Networks", product: "PAN-OS management interface", title: "PAN-OS authentication bypass", summary: "An authentication bypass vulnerability affects the web-based management interface in certain PAN-OS products.", action: "Restrict management-interface exposure and apply Palo Alto Networks security updates.", sourceUrl: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2024-0012" },
].map((item) => ({ ...item, source: "CISA Known Exploited Vulnerabilities Catalog / advisory", snapshotDate, status: "Public KEV reference; verify current vendor guidance before action" }));

const existingThreats = await readJson<typeof realThreats>("threat-intelligence.json", []);
await writeJson("threat-intelligence.json", [...new Map([...existingThreats, ...realThreats].map((item) => [item.cveId, item])).values()]);

const knowledge = await readJson<Array<Record<string, any>>>("knowledge-base.json", seededKnowledge);
for (const threat of realThreats) {
  const id = `cisa-${threat.cveId.toLowerCase()}`;
  if (!knowledge.some((item) => item.id === id)) knowledge.push({
    id, title: `${threat.cveId} · ${threat.vendor} ${threat.product}`, category: "CISA KEV",
    content: `${threat.summary} Recommended action: ${threat.action}`,
    keywords: [threat.cveId, threat.vendor, threat.product, "cisa", "kev", "vulnerability", "patch"],
    source: threat.source, sourceUrl: threat.sourceUrl, snapshotDate,
  });
}
await writeJson("knowledge-base.json", knowledge);

const incidents = await readJson<Incident[]>("incidents.json", []);
const demoScenarios = scenarios.filter((item) => item.expectedClassification === "Suspicious").slice(0, 10);
for (let index = 0; index < demoScenarios.length; index++) {
  const scenario = demoScenarios[index];
  const id = `demo-incident-${String(index + 1).padStart(2, "0")}`;
  if (incidents.some((item) => item.id === id)) continue;
  const result = analyzeRecords(scenario.records);
  const now = new Date(Date.now() - index * 86_400_000).toISOString();
  const status = (["New", "Investigating", "Contained", "Resolved", "New"] as const)[index % 5];
  incidents.push({ id, title: `[DEMO] ${scenario.title}`, severity: result.detections[0]?.severity ?? "low", status, createdAt: now, updatedAt: now, evidence: scenario.records.map((record) => JSON.stringify(record)), detections: result.detections, owner: index % 3 === 0 ? "Demo Analyst" : "", notes: [], history: [{ status, changedAt: now }] });
}
await writeJson("incidents.json", incidents);

const alerts = await readJson<Array<Record<string, any>>>("alerts.json", []);
for (let index = 0; index < demoScenarios.length; index++) {
  const id = `demo-alert-${String(index + 1).padStart(2, "0")}`;
  if (alerts.some((item) => item.id === id)) continue;
  const result = analyzeRecords(demoScenarios[index].records);
  alerts.push({ id, title: demoScenarios[index].title, severity: result.detections[0]?.severity ?? "low", status: "Open", source: "Synthetic training event", incidentId: `demo-incident-${String(index + 1).padStart(2, "0")}`, createdAt: new Date(Date.now() - index * 3_600_000).toISOString(), description: demoScenarios[index].description, synthetic: true });
}
await writeJson("alerts.json", alerts);

const analyses = await readJson<Array<Record<string, any>>>("analyses.json", []);
for (let index = 0; index < demoScenarios.length; index++) {
  const id = `demo-analysis-${String(index + 1).padStart(2, "0")}`;
  if (analyses.some((item) => item.id === id)) continue;
  const result = analyzeRecords(demoScenarios[index].records);
  analyses.push({ id, timestamp: new Date(Date.now() - index * 3_600_000).toISOString(), ...result, source: "Synthetic training event", synthetic: true });
}
await writeJson("analyses.json", analyses);

const investigations = await readJson<Array<Record<string, any>>>("investigations.json", []);
for (let index = 0; index < demoScenarios.length; index++) {
  const id = `demo-investigation-${String(index + 1).padStart(2, "0")}`;
  if (investigations.some((item) => item.id === id)) continue;
  const incident = incidents.find((item) => item.id === `demo-incident-${String(index + 1).padStart(2, "0")}`)!;
  const relatedKnowledge = searchKnowledge(knowledge as any, `${incident.title} ${incident.evidence.join(" ")}`);
  investigations.push({
    id, incidentId: incident.id, createdAt: incident.createdAt, provider: "offline", synthetic: true,
    steps: [
      { name: "Load incident evidence", status: "completed", result: `${incident.evidence.length} evidence item(s) loaded` },
      { name: "Run deterministic rules", status: "completed", result: `${incident.detections.length} rule finding(s) associated` },
      { name: "Retrieve defensive knowledge", status: "completed", result: relatedKnowledge.map((item) => item.title) },
      { name: "AI summary", status: "unavailable", result: "Demo history only; no provider call was made." },
    ],
    report: { title: `Investigation: ${incident.title}`, findings: incident.detections, evidence: incident.evidence, nextSteps: incident.detections.map((item) => item.recommendation), caveat: "Synthetic demonstration record. Heuristic findings are not confirmation of malicious activity." },
  });
}
await writeJson("investigations.json", investigations);

const audit = await readJson<Array<Record<string, any>>>("audit-log.json", []);
for (let index = 0; audit.filter((item) => item.metadata?.syntheticDemo).length < 10; index++) {
  const id = `demo-audit-${String(index + 1).padStart(2, "0")}`;
  if (audit.some((item) => item.id === id)) continue;
  audit.push({ id, timestamp: new Date(Date.now() - index * 1_800_000).toISOString(), action: "demo_seed_event", target: `demo-incident-${String((index % 10) + 1).padStart(2, "0")}`, result: "sample only", metadata: { syntheticDemo: true } });
}
await writeJson("audit-log.json", audit.slice(-5000));

console.log(JSON.stringify({ incidents: incidents.length, alerts: alerts.length, analyses: analyses.length, investigations: investigations.length, knowledge: knowledge.length, cisaThreatReferences: realThreats.length, auditEntries: audit.length, scenarios: scenarios.length }, null, 2));
