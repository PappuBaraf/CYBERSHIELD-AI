import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { performScan } from "../server/scanService.js";

const GOOD = "0x" + "b".repeat(40);
const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

test("scan with all providers failing -> ok result, high risk, honest flags", async () => {
  globalThis.fetch = (async () => json({}, 500)) as typeof fetch;
  const r = await performScan(GOOD);
  assert.equal(r.status, "ok");
  if (r.status !== "ok") return;
  assert.equal(r.result.verified, false);
  assert.equal(r.result.riskScore, 90); // 50 + 15 + 15 + 10
  assert.ok(r.result.flags.includes("Source not verified on Sourcify"));
  assert.match(r.result.flags[0], /providers were unreachable/);
  assert.ok(Object.values(r.result.providers).every((v) => v === false));
});

test("scan with mocked healthy providers lowers risk and fills fields", async () => {
  globalThis.fetch = (async (input: any) => {
    const url = String(input);
    if (url.includes("sourcify")) return json([{ name: "x" }]);
    if (url.includes("dexscreener")) return json({ pairs: [{ priceUsd: "1.5", liquidity: { usd: 100000 } }] });
    if (url.includes("coingecko"))
      return json({ name: "Tok", symbol: "tok", market_data: { current_price: { usd: 2 }, total_supply: 1000 } });
    if (url.includes("llamarpc")) return json({ result: "0x6080" });
    return json({}, 404);
  }) as typeof fetch;
  const r = await performScan(GOOD);
  assert.equal(r.status, "ok");
  if (r.status !== "ok") return;
  assert.equal(r.result.riskScore, 50);
  assert.equal(r.result.verified, true);
  assert.equal(r.result.name, "Tok");
  assert.equal(r.result.priceUsd, 2);
  assert.equal(r.result.liquidityUsd, 100000);
  assert.equal(r.result.providers.rpc, true);
});

test("network exceptions are swallowed per-provider, scan still completes", async () => {
  globalThis.fetch = (async () => { throw new Error("ECONNREFUSED"); }) as typeof fetch;
  const r = await performScan(GOOD);
  assert.equal(r.status, "ok");
});
