import type { Express, Request, Response } from "express";
import type { Server } from "node:http";
import { z } from "zod";
import { storage } from "./storage";
import {
  newScanRequestSchema,
  refreshFeedRequestSchema,
  updateFindingStatusSchema,
} from "@shared/schema";
import { profilePorts } from "./lib/ports";
import { runScan } from "./lib/scanner";
import { renderJson, renderMarkdown } from "./lib/report";
import { refreshNvd, refreshKev, refreshEpss } from "./feeds";
import { seedCves, seedKev, seedEpss } from "./seed";

// Track currently-running scans to prevent runaway concurrency.
let activeScans = 0;
const MAX_ACTIVE_SCANS = 2;

// Lightweight in-memory rate limit per IP for scan creation (10/min).
const scanRateBuckets = new Map<string, number[]>();
function rateLimitOk(ip: string, max = 10, windowMs = 60_000): boolean {
  const now = Date.now();
  const bucket = scanRateBuckets.get(ip) ?? [];
  const fresh = bucket.filter((t) => now - t < windowMs);
  if (fresh.length >= max) {
    scanRateBuckets.set(ip, fresh);
    return false;
  }
  fresh.push(now);
  scanRateBuckets.set(ip, fresh);
  return true;
}

async function ensureSeedData() {
  if ((await storage.countCves()) === 0) await storage.upsertCves(seedCves);
  if ((await storage.countKev()) === 0) await storage.upsertKev(seedKev);
  if ((await storage.countEpss()) === 0) await storage.upsertEpss(seedEpss);
}

function clientIp(req: Request): string {
  return (req.ip || req.socket.remoteAddress || "unknown").toString();
}

async function startScan(scanId: number, target: string, ports: number[]) {
  activeScans++;
  try {
    const cveSnapshot = await storage.searchCves("CVE-", 1000);
    const kevAll = await storage.getKevByIds(cveSnapshot.map((c) => c.cveId));
    const epssAll = await storage.getEpssByIds(cveSnapshot.map((c) => c.cveId));
    const kevSet = new Set(kevAll.map((k) => k.cveId));
    const epssMap = new Map(epssAll.map((e) => [e.cveId, e.epss ?? 0]));

    const result = await runScan({
      scanId,
      target,
      ports,
      cveSnapshot,
      kevSet,
      epssMap,
    });
    const summary: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const f of result.findings) {
      summary[f.severity] = (summary[f.severity] ?? 0) + 1;
      await storage.addFinding({ ...f, createdAt: Date.now() });
    }
    await storage.updateScan(scanId, {
      status: "complete",
      finishedAt: Date.now(),
      resolvedIp: result.resolvedIp,
      summary: JSON.stringify(summary),
    });
  } catch (err: any) {
    await storage.updateScan(scanId, {
      status: "failed",
      finishedAt: Date.now(),
      error: String(err?.message || err),
    });
  } finally {
    activeScans--;
  }
}

export async function registerRoutes(httpServer: Server, app: Express): Promise<Server> {
  await ensureSeedData();

  // ---- Health ----
  app.get("/api/health", (_req, res) => res.json({ ok: true, version: "0.1.0" }));

  // ---- Dashboard summary ----
  app.get("/api/dashboard", async (_req, res) => {
    const scans = await storage.listScans();
    const findings = await storage.recentFindings(10);
    const cveCount = await storage.countCves();
    const kevCount = await storage.countKev();
    const epssCount = await storage.countEpss();
    const meta = await storage.listFeedMeta();

    const summary = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    } as Record<string, number>;
    for (const s of scans) {
      try {
        const sum = s.summary ? JSON.parse(s.summary) : {};
        for (const k of Object.keys(summary)) summary[k] += sum[k] ?? 0;
      } catch {}
    }

    res.json({
      scans: scans.slice(0, 10),
      totalScans: scans.length,
      findings,
      summary,
      feeds: { cveCount, kevCount, epssCount, meta },
    });
  });

  // ---- Scans ----
  app.get("/api/scans", async (_req, res) => {
    const list = await storage.listScans();
    res.json(list);
  });

  app.get("/api/scans/:id", async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).json({ message: "Invalid id" });
    const scan = await storage.getScan(id);
    if (!scan) return res.status(404).json({ message: "Scan not found" });
    const findings = await storage.getFindingsByScan(id);
    res.json({ scan, findings });
  });

  app.post("/api/scans", async (req, res) => {
    const ip = clientIp(req);
    if (!rateLimitOk(ip)) {
      return res.status(429).json({ message: "Rate limit exceeded; wait a minute and retry." });
    }
    if (activeScans >= MAX_ACTIVE_SCANS) {
      return res.status(429).json({ message: "Too many active scans; try again shortly." });
    }
    const parsed = newScanRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res
        .status(400)
        .json({ message: "Validation failed", errors: parsed.error.flatten() });
    }
    let ports: number[];
    try {
      ports = profilePorts(parsed.data.profile, parsed.data.customPorts);
    } catch (e: any) {
      return res.status(400).json({ message: e?.message || "Invalid ports" });
    }
    const scan = await storage.createScan({
      target: parsed.data.target,
      profile: parsed.data.profile,
      ports: JSON.stringify(ports),
      authorizedAck: 1,
      startedAt: Date.now(),
      status: "running",
    });
    // Run asynchronously so the API responds quickly.
    void startScan(scan.id, scan.target, ports);
    res.status(202).json({ id: scan.id, status: "running" });
  });

  // ---- Findings ----
  app.patch("/api/findings/:id", async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).json({ message: "Invalid id" });
    const parsed = updateFindingStatusSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ message: "Validation failed", errors: parsed.error.flatten() });
    }
    const updated = await storage.updateFindingStatus(id, parsed.data.status);
    if (!updated) return res.status(404).json({ message: "Finding not found" });
    res.json(updated);
  });

  // ---- Reports ----
  app.get("/api/scans/:id/report.json", async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).json({ message: "Invalid id" });
    const scan = await storage.getScan(id);
    if (!scan) return res.status(404).json({ message: "Scan not found" });
    const findings = await storage.getFindingsByScan(id);
    const cveIds = new Set<string>();
    for (const f of findings) {
      try {
        for (const c of JSON.parse(f.cveIds || "[]")) cveIds.add(c);
      } catch {}
    }
    const ids = Array.from(cveIds);
    const kev = await storage.getKevByIds(ids);
    const epss = await storage.getEpssByIds(ids);
    const json = renderJson({ scan, findings, kev, epss });
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="sentinelscope-scan-${id}.json"`);
    res.send(JSON.stringify(json, null, 2));
  });

  app.get("/api/scans/:id/report.md", async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).json({ message: "Invalid id" });
    const scan = await storage.getScan(id);
    if (!scan) return res.status(404).json({ message: "Scan not found" });
    const findings = await storage.getFindingsByScan(id);
    const cveIds = new Set<string>();
    for (const f of findings) {
      try {
        for (const c of JSON.parse(f.cveIds || "[]")) cveIds.add(c);
      } catch {}
    }
    const ids = Array.from(cveIds);
    const kev = await storage.getKevByIds(ids);
    const epss = await storage.getEpssByIds(ids);
    const md = renderMarkdown({ scan, findings, kev, epss });
    res.setHeader("Content-Type", "text/markdown; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="sentinelscope-scan-${id}.md"`);
    res.send(md);
  });

  // ---- Vulnerability feed ----
  app.get("/api/cves", async (req, res) => {
    const q = String(req.query.q || "CVE-").slice(0, 100);
    const limit = Math.min(parseInt(String(req.query.limit ?? "50"), 10) || 50, 200);
    const rows = await storage.searchCves(q, limit);
    res.json(rows);
  });

  app.get("/api/cves/:id", async (req, res) => {
    const id = String(req.params.id || "").toUpperCase().slice(0, 64);
    if (!/^CVE-\d{4}-\d{1,7}$/.test(id)) return res.status(400).json({ message: "Invalid CVE id" });
    const c = await storage.getCveById(id);
    if (!c) return res.status(404).json({ message: "Not found" });
    const k = (await storage.getKevByIds([id]))[0] ?? null;
    const e = (await storage.getEpssByIds([id]))[0] ?? null;
    res.json({ cve: c, kev: k, epss: e });
  });

  // Feed metadata
  app.get("/api/feeds", async (_req, res) => {
    const meta = await storage.listFeedMeta();
    const cveCount = await storage.countCves();
    const kevCount = await storage.countKev();
    const epssCount = await storage.countEpss();
    res.json({ meta, cveCount, kevCount, epssCount });
  });

  // Trigger refresh
  app.post("/api/feeds/refresh", async (req, res) => {
    const parsed = refreshFeedRequestSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ message: "Validation failed" });
    const results: any[] = [];
    if (parsed.data.source === "all" || parsed.data.source === "nvd") results.push(await refreshNvd());
    if (parsed.data.source === "all" || parsed.data.source === "kev") results.push(await refreshKev());
    if (parsed.data.source === "all" || parsed.data.source === "epss") results.push(await refreshEpss());
    res.json({ results });
  });

  // Settings (read/write a small allowlisted set)
  const allowedSettings = z.enum(["preferred_profile", "warn_banner_dismissed"]);
  app.get("/api/settings/:key", async (req, res) => {
    const parsed = allowedSettings.safeParse(req.params.key);
    if (!parsed.success) return res.status(400).json({ message: "Unknown setting" });
    const r = await storage.getSetting(parsed.data);
    res.json({ key: parsed.data, value: r?.value ?? null });
  });
  app.put("/api/settings/:key", async (req, res) => {
    const parsed = allowedSettings.safeParse(req.params.key);
    if (!parsed.success) return res.status(400).json({ message: "Unknown setting" });
    const body = z.object({ value: z.string().max(500) }).safeParse(req.body);
    if (!body.success) return res.status(400).json({ message: "Validation failed" });
    await storage.setSetting(parsed.data, body.data.value);
    res.json({ ok: true });
  });

  return httpServer;
}
