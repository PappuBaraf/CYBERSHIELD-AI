import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { analyzeRecords, scenarios, searchKnowledge, seededKnowledge } from "../server/soc.js";

test("each built-in synthetic scenario matches the deterministic detection engine", () => {
  assert.equal(scenarios.length, 12);
  for (const scenario of scenarios) {
    const result = analyzeRecords(scenario.records);
    assert.equal(result.classification, scenario.expectedClassification, scenario.id);
    assert.equal(result.rejected, 0, scenario.id);
    assert.ok(scenario.expectedClassification !== "Suspicious" || result.detections.length > 0, scenario.id);
  }
});

test("scenario JSON seed stays synchronized with the tested scenarios", async () => {
  const data = JSON.parse(await readFile(new URL("../data/scenarios.json", import.meta.url), "utf8"));
  assert.deepEqual(data.map((scenario: { id: string }) => scenario.id), scenarios.map((scenario) => scenario.id));
  for (const scenario of data) {
    assert.equal(analyzeRecords(scenario.records).classification, scenario.expectedClassification, scenario.id);
  }
});

test("analysis rejects malformed record entries without throwing", () => {
  const result = analyzeRecords([null, [], "not an event", { eventType: "maintenance", message: "routine backup" }]);
  assert.equal(result.processed, 4);
  assert.equal(result.valid, 1);
  assert.equal(result.rejected, 3);
  assert.equal(result.classification, "Benign");
});

test("knowledge retrieval ranks relevant sources and returns no unrelated matches", () => {
  const results = searchKnowledge(seededKnowledge, "how should I review an unusual login and MFA event");
  assert.equal(results[0]?.id, "kb-account-review");
  assert.deepEqual(searchKnowledge(seededKnowledge, "quantum cooking recipe"), []);
  assert.deepEqual(searchKnowledge(seededKnowledge, "   "), []);
});

test("all four local detection methodologies produce labeled findings and ATT&CK/KEV context", () => {
  const intel = [{ ...seededKnowledge[0], category: "CISA KEV", title: "CVE-2021-44228 · Apache Log4j2" }];
  const result = analyzeRecords([
    { indicatorId: "CSAI-DEMO-IOC-0001" },
    { eventType: "authentication", status: "failed", message: "login failed" },
    { eventType: "network", message: "unusual outbound traffic", bytes: 60_000_000, cve: "CVE-2021-44228" },
  ], intel);
  assert.equal(result.classification, "Suspicious");
  assert.ok(result.detections.some((item) => item.methodology === "Signature-based" && item.ruleId === "SIG-IOC-001"));
  assert.ok(result.detections.some((item) => item.methodology === "Behavior-based" && item.techniques?.some((technique) => technique.id === "T1110")));
  assert.ok(result.detections.some((item) => item.methodology === "Anomaly-based" && item.ruleId === "ANOM-001"));
  assert.ok(result.detections.some((item) => item.methodology === "Intelligence-driven" && item.intelligenceMatches?.includes("CVE-2021-44228")));
  assert.equal(analyzeRecords([{ indicatorId: "other-value" }]).classification, "Benign");
});
