import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createApp, csvCell } from "../server/app.js";
import { isValidAddress, performScan } from "../server/scanService.js";

const GOOD = "0x" + "a".repeat(40);
let server: Server;
let base: string;
let stop: () => void;
let scanCalls = 0;

before(async () => {
  const made = createApp({
    scan: async (address) => {
      scanCalls++;
      return {
        status: "ok",
        result: {
          address, riskScore: 42, verified: true, name: "Mock", symbol: "MCK",
          totalSupply: null, priceUsd: null, priceChange24h: null, liquidityUsd: null, flags: [],
          providers: { sourcify: true, dexscreener: false, coingecko: false, goplus: false,
            surfacescan: false, thegraph: false, dune: false, rpc: false },
        },
      };
    },
  });
  stop = made.stop;
  server = made.app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => { stop(); server.close(); });

const post = (path: string, body: unknown) =>
  fetch(base + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

test("isValidAddress accepts/rejects correctly", () => {
  assert.equal(isValidAddress(GOOD), true);
  assert.equal(isValidAddress("0x123"), false);
  assert.equal(isValidAddress("0x" + "g".repeat(40)), false);
  assert.equal(isValidAddress(`${GOOD}"}){x}`), false);
  assert.equal(isValidAddress(undefined), false);
});

test("performScan rejects invalid address without network", async () => {
  const r = await performScan("not-an-address");
  assert.deepEqual(r, { status: "error", reason: "INVALID_ADDRESS" });
});

test("GET /api/health", async () => {
  const res = await fetch(base + "/api/health");
  assert.equal(res.status, 200);
  const j: any = await res.json();
  assert.equal(j.ok, true);
  assert.equal(j.queue, false);
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.equal(res.headers.get("x-powered-by"), null);
});

test("POST /api/scan rejects bad input with 400", async () => {
  for (const body of [{}, { address: "" }, { address: 123 }, { address: "0xabc" }]) {
    const res = await post("/api/scan", body);
    assert.equal(res.status, 400, JSON.stringify(body));
  }
  assert.equal(scanCalls, 0);
});

test("POST /api/scan direct mode returns result", async () => {
  const res = await post("/api/scan", { address: GOOD });
  assert.equal(res.status, 200);
  const j: any = await res.json();
  assert.equal(j.mode, "direct");
  assert.equal(j.result.status, "ok");
  assert.equal(j.result.result.address, GOOD);
  assert.equal(scanCalls, 1);
});

test("invalid JSON -> 400, oversize -> 413, unknown api -> 404", async () => {
  const bad = await fetch(base + "/api/scan", { method: "POST", headers: { "content-type": "application/json" }, body: "{nope" });
  assert.equal(bad.status, 400);
  const big = await post("/api/scan", { address: GOOD, pad: "x".repeat(20000) });
  assert.equal(big.status, 413);
  const nf = await fetch(base + "/api/nope");
  assert.equal(nf.status, 404);
});

test("job + share endpoints refuse when queue disabled", async () => {
  assert.equal((await fetch(base + "/api/job/1")).status, 400);
  assert.equal((await post("/api/share", { jobId: "1" })).status, 400);
  assert.equal((await post("/api/share", {})).status, 400);
  assert.equal((await fetch(base + "/api/share/nope")).status, 404);
});

test("audit log records scans and supports filters + exports", async () => {
  const j: any = await (await fetch(base + "/api/audit?action=scan_completed")).json();
  assert.ok(j.total >= 1);
  assert.ok(j.entries.every((e: any) => e.action === "scan_completed"));

  const csv = await fetch(base + "/api/audit/export?format=csv");
  assert.match(csv.headers.get("content-type") || "", /text\/csv/);
  const text = await csv.text();
  assert.ok(text.startsWith("id,timestamp,action"));
  assert.ok(text.includes("scan_requested"));

  const json = await fetch(base + "/api/audit/export");
  assert.ok(Array.isArray(await json.json()));

  const stats: any = await (await fetch(base + "/api/stats")).json();
  assert.ok(stats.totalScans >= 1 && stats.completedScans >= 1);
});

test("csvCell escapes quotes and neutralises formulas", () => {
  assert.equal(csvCell('a"b'), '"a""b"');
  assert.equal(csvCell("=1+1"), `"'=1+1"`);
  assert.equal(csvCell(undefined), '""');
});

test("CORS: allowed origin echoed, foreign origin not", async () => {
  const ok = await fetch(base + "/api/health", { headers: { Origin: "http://127.0.0.1:5000" } });
  assert.equal(ok.headers.get("access-control-allow-origin"), "http://127.0.0.1:5000");
  const bad = await fetch(base + "/api/health", { headers: { Origin: "http://evil.example" } });
  assert.equal(bad.headers.get("access-control-allow-origin"), null);
});
