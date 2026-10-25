export interface ScanResult {
  status: "ok" | "error";
  result?: any;
  reason?: string;
}

interface AsyncResponse {
  mode: "async";
  jobId: string;
}

interface DirectResponse {
  mode: "direct";
  result: ScanResult;
}

interface JobStatus {
  status: "pending" | "completed" | "failed";
  result?: ScanResult;
  error?: string;
}

function getApiBaseUrl(): string {
  if (typeof window === "undefined") return "";
  const { hostname, protocol } = window.location;
  if (hostname === "localhost" || hostname === "127.0.0.1") {
    return "";
  }
  if (hostname.endsWith(".replit.dev") || hostname.endsWith(".repl.co")) {
    return `${protocol}//${hostname.replace(/^([^.]+)/, "$1-3001")}`;
  }
  return "";
}

const API_BASE = getApiBaseUrl();

async function fetchJson(url: string, options?: RequestInit) {
  const fullUrl = url.startsWith("/api") ? `${API_BASE}${url}` : url;
  const res = await fetch(fullUrl, options);
  if (!res.ok) {
    let msg = `Request failed: ${res.status}`;
    try {
      const body = await res.json();
      if (body?.error) msg = body.error;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(msg);
  }
  return res.json();
}

async function pollJob(jobId: string, maxAttempts = 60): Promise<ScanResult> {
  for (let i = 0; i < maxAttempts; i++) {
    const status: JobStatus = await fetchJson(`/api/job/${jobId}`);
    if (status.status === "completed" && status.result) {
      return status.result;
    }
    if (status.status === "failed") {
      throw new Error(status.error || "Scan failed");
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error("Scan timed out");
}

export async function scanContract(address: string): Promise<ScanResult> {
  const payload = { address };
  const data: AsyncResponse | DirectResponse = await fetchJson("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if ("mode" in data && data.mode === "async") {
    return pollJob(data.jobId);
  }

  if ("mode" in data && data.mode === "direct") {
    return data.result;
  }

  throw new Error("Unexpected response from server");
}
