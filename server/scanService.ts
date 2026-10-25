export interface ScanResult {
  address: string;
  riskScore: number;
  verified: boolean;
  name: string | null;
  symbol: string | null;
  totalSupply: number | null;
  priceUsd: number | null;
  priceChange24h: number | null;
  liquidityUsd: number | null;
  flags: string[];
  providers: {
    sourcify: boolean;
    dexscreener: boolean;
    coingecko: boolean;
    goplus: boolean;
    surfacescan: boolean;
    thegraph: boolean;
    dune: boolean;
    rpc: boolean;
  };
}

export function isValidAddress(address: unknown): address is string {
  return typeof address === "string" && /^0x[a-fA-F0-9]{40}$/.test(address);
}

const FETCH_TIMEOUT_MS = 15000;

async function fetchJson(url: string, options?: RequestInit): Promise<any> {
  const res = await fetch(url, { ...options, signal: options?.signal ?? AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!res.ok) {
    throw new Error(`Request failed: ${res.status}`);
  }
  return res.json();
}

export async function performScan(address: string): Promise<{ status: "ok"; result: ScanResult } | { status: "error"; reason: string }> {
  if (!isValidAddress(address)) {
    return { status: "error", reason: "INVALID_ADDRESS" };
  }
  try {
    const result = await doScan(address);
    return {
      status: "ok",
      result,
    };
  } catch (err: any) {
    return {
      status: "error",
      reason: err?.message || "SCAN_FAILED",
    };
  }
}

async function doScan(address: string): Promise<ScanResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);

  try {
    return await executeScan(address, controller.signal);
  } finally {
    clearTimeout(timeout);
  }
}

// Optional: GoPlus security scan
async function fetchGoplus(address: string) {
  const chainId = 1;
  const apiKey = process.env.GOPLUS_API_KEY;
  const url = `https://api.gopluslabs.io/api/v1/token_security/${chainId}?contract_addresses=${address}`;
  try {
    const json: any = await fetchJson(url, {
      headers: apiKey ? { "API-KEY": apiKey } : undefined,
    } as any);
    const result = json?.result?.[address.toLowerCase()] || json?.result?.[address] || null;
    if (!result) return { active: false, flags: [] as string[] };

    const flags: string[] = [];
    if (result.is_honeypot === 1 || result.is_honeypot === "1") {
      flags.push("GoPlus: Possible honeypot");
    }
    if (result.is_open_source === 0 || result.is_open_source === "0") {
      flags.push("GoPlus: Source not open");
    }
    if (result.is_proxy === 1 || result.is_proxy === "1") {
      flags.push("GoPlus: Proxy contract");
    }
    if (result.owner_address) {
      flags.push(`GoPlus: Owner ${result.owner_address}`);
    }
    return { active: true, flags };
  } catch {
    return { active: false, flags: [] as string[] };
  }
}

// Optional: SurfaceScan integration (generic)
async function fetchSurfaceScan(address: string) {
  const baseUrl = process.env.SURFACESCAN_API_URL;
  if (!baseUrl) return { active: false, flags: [] as string[] };

  const apiKey = process.env.SURFACESCAN_API_KEY;
  const url = `${baseUrl.replace(/\/$/, "")}/api/v1/scan?address=${address}`;
  try {
    const json: any = await fetchJson(url, {
      headers: apiKey ? { Authorization: `Bearer ${apiKey}` } : undefined,
    } as any);
    const flags: string[] = [];
    if (json?.risk_level) {
      flags.push(`SurfaceScan: Risk level ${json.risk_level}`);
    }
    if (Array.isArray(json?.issues)) {
      for (const issue of json.issues) {
        if (issue?.label) flags.push(`SurfaceScan: ${issue.label}`);
      }
    }
    return { active: true, flags };
  } catch {
    return { active: false, flags: [] as string[] };
  }
}

// Optional: TheGraph for holders / token info
async function fetchTheGraph(address: string) {
  const endpoint = process.env.THEGRAPH_ENDPOINT;
  if (!endpoint) return { active: false, flags: [] as string[] };

  const query = `
    {
      token(id: "${address.toLowerCase()}") {
        name
        symbol
        totalSupply
      }
    }
  `;
  try {
    const json: any = await fetchJson(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ query }),
    });
    const token = json?.data?.token;
    const flags: string[] = [];
    if (!token) {
      flags.push("TheGraph: No token data");
    } else {
      flags.push("TheGraph: Token indexed");
    }
    return { active: true, flags };
  } catch {
    return { active: false, flags: [] as string[] };
  }
}

// Optional: Dune Analytics metrics
async function fetchDune(address: string) {
  const apiKey = process.env.DUNE_API_KEY;
  const queryId = process.env.DUNE_QUERY_ID;
  if (!apiKey || !queryId) return { active: false, flags: [] as string[] };

  const url = `https://api.dune.com/api/v1/query/${queryId}/results?limit=1`;
  try {
    const json: any = await fetchJson(url, {
      headers: { "X-Dune-API-Key": apiKey },
    });
    const flags: string[] = [];
    if (json?.result?.rows?.length) {
      flags.push("Dune: Query returned data");
    } else {
      flags.push("Dune: No rows for token");
    }
    return { active: true, flags };
  } catch {
    return { active: false, flags: [] as string[] };
  }
}

// RPC deep scan
async function fetchRpcDeep(address: string) {
  const rpcUrl =
    process.env.RPC_URL ||
    process.env.ETH_RPC_URL ||
    "https://eth.llamarpc.com";
  try {
    const body = (method: string, params: any[]) => ({
      jsonrpc: "2.0",
      id: 1,
      method,
      params,
    });

    const codeRes = await fetch(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body("eth_getCode", [address, "latest"])),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!codeRes.ok) throw new Error(`RPC HTTP ${codeRes.status}`);
    const codeJson: any = await codeRes.json();
    if (typeof codeJson?.result !== "string") throw new Error("RPC returned no result");
    const bytecode: string = codeJson.result;

    const hasCode = bytecode && bytecode !== "0x";
    const flags: string[] = [];
    if (!hasCode) {
      flags.push("RPC: Address has no bytecode (EOA or non-deployed).");
    } else {
      const sizeBytes = (bytecode.length - 2) / 2;
      flags.push(`RPC: Contract bytecode size ~${sizeBytes} bytes`);
    }

    return { active: true, flags };
  } catch {
    return { active: false, flags: [] as string[] };
  }
}

async function executeScan(address: string, signal?: AbortSignal): Promise<ScanResult> {
  const checksum = address;

  let sourcifyOk = false;
  let dexscreenerOk = false;
  let coingeckoOk = false;
  let goplusOk = false;
  let surfaceOk = false;
  let graphOk = false;
  let duneOk = false;
  let rpcOk = false;

  let name: string | null = null;
  let symbol: string | null = null;
  let totalSupply: number | null = null;
  let priceUsd: number | null = null;
  let priceChange: number | null = null;
  let liquidity: number | null = null;
  const flags: string[] = [];
  let lookupFailures = 0;

  // Sourcify
  try {
    const meta = await fetchJson(
      `https://sourcify.dev/server/files/any/1/${checksum}`
    );
    if (Array.isArray(meta) && meta.length > 0) {
      sourcifyOk = true;
    }
  } catch (e: any) {
    // Sourcify answers 404 for unknown contracts; anything else is an outage
    if (!String(e?.message).includes("404")) lookupFailures++;
  }

  // Dexscreener
  try {
    const dex = await fetchJson(
      `https://api.dexscreener.com/latest/dex/tokens/${checksum}`
    );
    if (dex && dex.pairs && dex.pairs.length > 0) {
      dexscreenerOk = true;
      const best = dex.pairs[0];
      if (best.liquidity && best.liquidity.usd) {
        liquidity = Number(best.liquidity.usd) || null;
      }
      if (best.priceUsd) {
        priceUsd = Number(best.priceUsd) || null;
      }
    }
  } catch {
    lookupFailures++;
  }

  // CoinGecko
  try {
    const cg = await fetchJson(
      `https://api.coingecko.com/api/v3/coins/ethereum/contract/${checksum}`
    );
    coingeckoOk = true;
    name = cg.name ?? null;
    symbol = cg.symbol ?? null;
    if (cg.market_data) {
      priceUsd = cg.market_data.current_price?.usd ?? priceUsd;
      priceChange =
        cg.market_data.price_change_percentage_24h_in_currency?.usd ?? null;
      totalSupply = cg.market_data.total_supply ?? null;
    }
  } catch (e: any) {
    if (!String(e?.message).includes("404")) lookupFailures++;
  }

  // Additional providers
  const [goplus, surface, graph, dune, rpc] = await Promise.all([
    fetchGoplus(checksum),
    fetchSurfaceScan(checksum),
    fetchTheGraph(checksum),
    fetchDune(checksum),
    fetchRpcDeep(checksum),
  ]);

  if (goplus.active) {
    goplusOk = true;
    flags.push(...goplus.flags);
  }
  if (surface.active) {
    surfaceOk = true;
    flags.push(...surface.flags);
  }
  if (graph.active) {
    graphOk = true;
    flags.push(...graph.flags);
  }
  if (dune.active) {
    duneOk = true;
    flags.push(...dune.flags);
  }
  if (rpc.active) {
    rpcOk = true;
    flags.push(...rpc.flags);
  }

  if (lookupFailures >= 3) {
    flags.unshift("WARNING: all primary data providers were unreachable. Findings below reflect missing data, not a verdict on the contract.");
  }
  if (!sourcifyOk) {
    flags.push("Source not verified on Sourcify");
  }
  if (!dexscreenerOk) {
    flags.push("No liquidity found on Dexscreener");
  }
  if (!coingeckoOk) {
    flags.push("Token not found on CoinGecko");
  }

  const riskScoreBase = 50;
  const penalty =
    (!sourcifyOk ? 15 : 0) +
    (!dexscreenerOk ? 15 : 0) +
    (!coingeckoOk ? 10 : 0);
  const riskScore = Math.max(1, Math.min(99, riskScoreBase + penalty));

  const result: ScanResult = {
    address: checksum,
    riskScore,
    verified: sourcifyOk,
    name,
    symbol,
    totalSupply,
    priceUsd,
    priceChange24h: priceChange,
    liquidityUsd: liquidity,
    flags,
    providers: {
      sourcify: sourcifyOk,
      dexscreener: dexscreenerOk,
      coingecko: coingeckoOk,
      goplus: goplusOk,
      surfacescan: surfaceOk,
      thegraph: graphOk,
      dune: duneOk,
      rpc: rpcOk,
    },
  };

  return result;
}
