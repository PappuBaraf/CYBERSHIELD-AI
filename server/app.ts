import express, { type Express, type Request, type Response, type NextFunction } from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import { v4 as uuidv4 } from "uuid";
import { getJobStatusDirect, enqueueScanJob, isQueueEnabled } from "./queue.js";
import { performScan, isValidAddress, type ScanResult } from "./scanService.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  action: string;
  address?: string;
  jobId?: string;
  details?: string;
}

interface SharedReport {
  id: string;
  jobId: string;
  address: string;
  result: ScanResult;
  createdAt: string;
  expiresAt: string;
  viewCount: number;
}

export const REPORT_VERSION = "1.0.0";
const REPORT_TTL_HOURS = 24;

export interface AppDeps {
  /** Override for tests */
  scan?: typeof performScan;
}

/** Spreadsheet-safe CSV cell: escapes quotes and neutralises formula injection. */
export function csvCell(value: unknown): string {
  let s = value === undefined || value === null ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return `"${s.replace(/"/g, '""')}"`;
}

export function createApp(deps: AppDeps = {}): { app: Express; stop: () => void } {
  const scan = deps.scan ?? performScan;
  const app = express();
  const auditLog: AuditLogEntry[] = [];
  const sharedReports = new Map<string, SharedReport>();

  const clientOrigins = (
    process.env.CLIENT_ORIGIN ||
    "http://127.0.0.1:5000,http://localhost:5000,http://127.0.0.1:5173,http://localhost:5173"
  )
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  app.disable("x-powered-by");
  app.use((_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    next();
  });
  app.use(
    cors({
      origin: (origin, cb) => cb(null, !origin || clientOrigins.includes(origin)),
    })
  );
  app.use(express.json({ limit: "10kb" }));

  function addAudit(entry: Omit<AuditLogEntry, "id" | "timestamp">) {
    const full: AuditLogEntry = { id: uuidv4(), timestamp: new Date().toISOString(), ...entry };
    auditLog.push(full);
    if (auditLog.length > 10000) auditLog.shift();
    return full;
  }

  const cleanup = setInterval(() => {
    const now = Date.now();
    for (const [id, r] of sharedReports) {
      if (new Date(r.expiresAt).getTime() < now) sharedReports.delete(id);
    }
  }, 60_000);
  cleanup.unref();

  app.get("/api/health", (_req, res) => {
    res.json({ ok: true, queue: isQueueEnabled(), time: new Date().toISOString() });
  });

  app.get("/api/test", (_req, res) => {
    res.json({ ok: true, env: process.env.NODE_ENV, time: new Date().toISOString() });
  });

  app.post("/api/scan", async (req, res, next) => {
    try {
      const address = typeof req.body?.address === "string" ? req.body.address.trim() : "";
      if (!isValidAddress(address)) {
        return res
          .status(400)
          .json({ error: "Invalid address. Expected a 0x-prefixed 40-hex-character Ethereum address." });
      }
      addAudit({ action: "scan_requested", address });

      if (isQueueEnabled()) {
        const jobId = await enqueueScanJob(address);
        return res.json({ mode: "async", jobId });
      }

      const result = await scan(address);
      addAudit({
        action: result.status === "ok" ? "scan_completed" : "scan_failed",
        address,
        details: result.status === "error" ? result.reason : undefined,
      });
      return res.json({ mode: "direct", result });
    } catch (err) {
      next(err);
    }
  });

  app.get("/api/job/:id", async (req, res, next) => {
    try {
      if (!isQueueEnabled()) {
        return res.status(400).json({ status: "failed", error: "Queue not enabled" });
      }
      const status = await getJobStatusDirect(req.params.id);
      return res.json(status);
    } catch (err) {
      next(err);
    }
  });

  app.post("/api/share", async (req, res, next) => {
    try {
      const jobId = req.body?.jobId;
      if (typeof jobId !== "string" || !jobId) {
        return res.status(400).json({ error: "Missing jobId" });
      }
      if (!isQueueEnabled()) {
        return res.status(400).json({ error: "Queue not enabled, cannot share" });
      }
      const status: any = await getJobStatusDirect(jobId);
      // Worker returns { status: "ok", result: ScanResult }
      const scanResult: ScanResult | undefined =
        status.status === "completed" && status.result?.status === "ok" ? status.result.result : undefined;
      if (!scanResult) {
        return res.status(400).json({ error: "Job not completed or result not available" });
      }
      const shareId = uuidv4();
      const now = new Date();
      const expiresAt = new Date(now.getTime() + REPORT_TTL_HOURS * 3600 * 1000);
      sharedReports.set(shareId, {
        id: shareId,
        jobId,
        address: scanResult.address,
        result: scanResult,
        createdAt: now.toISOString(),
        expiresAt: expiresAt.toISOString(),
        viewCount: 0,
      });
      addAudit({
        action: "report_shared",
        jobId,
        address: scanResult.address,
        details: `Share ID: ${shareId}, expires: ${expiresAt.toISOString()}`,
      });
      return res.json({ shareId, shareUrl: `/share/${shareId}`, expiresAt: expiresAt.toISOString() });
    } catch (err) {
      next(err);
    }
  });

  app.get("/api/share/:shareId", (req, res) => {
    const report = sharedReports.get(req.params.shareId);
    if (!report || new Date(report.expiresAt) < new Date()) {
      if (report) sharedReports.delete(req.params.shareId);
      return res.status(404).json({ error: "Report not found or expired" });
    }
    report.viewCount++;
    addAudit({
      action: "shared_report_viewed",
      address: report.address,
      details: `Share ID: ${report.id}, view count: ${report.viewCount}`,
    });
    return res.json({ ...report, reportVersion: REPORT_VERSION });
  });

  app.get("/api/audit", (req, res) => {
    const limit = Math.min(Math.max(parseInt(String(req.query.limit)) || 100, 1), 1000);
    const offset = Math.max(parseInt(String(req.query.offset)) || 0, 0);
    const action = typeof req.query.action === "string" ? req.query.action : undefined;
    const address = typeof req.query.address === "string" ? req.query.address : undefined;

    let filtered = auditLog;
    if (action) filtered = filtered.filter((e) => e.action === action);
    if (address) filtered = filtered.filter((e) => e.address === address);

    const total = filtered.length;
    const end = Math.max(filtered.length - offset, 0);
    const start = Math.max(end - limit, 0);
    const entries = filtered.slice(start, end).reverse();

    addAudit({ action: "audit_log_accessed", details: `limit: ${limit}, offset: ${offset}` });
    res.json({ total, limit, offset, entries });
  });

  app.get("/api/audit/export", (req, res) => {
    const format = req.query.format === "csv" ? "csv" : "json";
    const entries = [...auditLog].reverse();
    addAudit({ action: "audit_log_exported", details: `format: ${format}, entries: ${entries.length}` });

    if (format === "csv") {
      const headers = ["id", "timestamp", "action", "address", "jobId", "details"];
      const csv = [
        headers.join(","),
        ...entries.map((e) => headers.map((h) => csvCell((e as any)[h])).join(",")),
      ].join("\n");
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", "attachment; filename=audit_log.csv");
      return res.send(csv);
    }
    res.setHeader("Content-Disposition", "attachment; filename=audit_log.json");
    return res.json(entries);
  });

  app.get("/api/stats", (_req, res) => {
    res.json({
      totalScans: auditLog.filter((e) => e.action === "scan_requested").length,
      completedScans: auditLog.filter((e) => e.action === "scan_completed").length,
      failedScans: auditLog.filter((e) => e.action === "scan_failed").length,
      sharedReports: sharedReports.size,
      auditLogEntries: auditLog.length,
      reportVersion: REPORT_VERSION,
    });
  });

  // Unknown API routes -> JSON 404
  app.use("/api", (_req, res) => res.status(404).json({ error: "Not found" }));

  if (process.env.NODE_ENV === "production") {
    const staticPath = path.resolve(__dirname, "../dist/public");
    app.use(express.static(staticPath));
    app.use((req, res, next) => {
      if (req.path.startsWith("/api/") || req.path.startsWith("/admin/")) return next();
      res.sendFile(path.join(staticPath, "index.html"));
    });
  }

  // Global error handler (must be last). Never leak stack traces to the client.
  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    if (err?.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
    if (err?.type === "entity.parse.failed") return res.status(400).json({ error: "Invalid JSON body" });
    console.error("Server error:", err?.message);
    res.status(500).json({ error: "Internal Server Error" });
  });

  return { app, stop: () => clearInterval(cleanup) };
}
