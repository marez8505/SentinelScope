/**
 * Feed updaters for NVD CVE, CISA KEV, and FIRST EPSS.
 *
 * Sources:
 *   NVD CVE API:   https://services.nvd.nist.gov/rest/json/cves/2.0
 *                  Docs: https://nvd.nist.gov/developers/vulnerabilities
 *   CISA KEV JSON: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 *   FIRST EPSS:    https://api.first.org/data/v1/epss
 *                  Docs: https://api.first.org/epss/
 *
 * All updaters are best-effort: on network failure they record an error in
 * feed_meta but the application continues with bundled seed data.
 */
import { storage } from "./storage";
import type { Cve, Kev, Epss } from "@shared/schema";

const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL = "https://api.first.org/data/v1/epss";

const FETCH_TIMEOUT_MS = 20_000;

async function safeFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, {
      ...init,
      signal: ctrl.signal,
      headers: {
        Accept: "application/json",
        "User-Agent": "SentinelScope/0.1 (local research tool)",
        ...(init.headers || {}),
      },
    });
  } finally {
    clearTimeout(t);
  }
}

export interface FeedResult {
  source: string;
  ok: boolean;
  count: number;
  message: string;
}

/** Refresh the most recently modified slice of NVD CVEs.
 *  Conservative: pulls a single page (resultsPerPage=200) — the user can rerun.
 *  This avoids the documented NVD rate-limit issue. */
export async function refreshNvd(opts?: { keyword?: string; resultsPerPage?: number }): Promise<FeedResult> {
  const url = new URL(NVD_URL);
  const perPage = Math.min(Math.max(opts?.resultsPerPage ?? 100, 1), 200);
  url.searchParams.set("resultsPerPage", String(perPage));
  if (opts?.keyword) {
    url.searchParams.set("keywordSearch", opts.keyword);
  }

  const headers: Record<string, string> = {};
  if (process.env.NVD_API_KEY) headers["apiKey"] = process.env.NVD_API_KEY;

  try {
    const res = await safeFetch(url.toString(), { headers });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as any;
    const items = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
    const rows: Cve[] = items.map((entry: any) => mapNvdCve(entry));
    const written = await storage.upsertCves(rows);
    const meta = {
      source: "nvd",
      lastSync: Date.now(),
      lastStatus: "ok",
      recordCount: written,
      message: `Imported ${written} CVE records from NVD`,
    };
    await storage.setFeedMeta(meta);
    return { source: "nvd", ok: true, count: written, message: meta.message };
  } catch (err: any) {
    const message = `NVD fetch failed: ${err?.message || String(err)}`;
    await storage.setFeedMeta({
      source: "nvd",
      lastSync: Date.now(),
      lastStatus: "error",
      recordCount: 0,
      message,
    });
    return { source: "nvd", ok: false, count: 0, message };
  }
}

function mapNvdCve(entry: any): Cve {
  const cve = entry?.cve ?? {};
  const id = cve.id || "UNKNOWN";
  const descs = Array.isArray(cve.descriptions) ? cve.descriptions : [];
  const desc = (descs.find((d: any) => d.lang === "en") || descs[0])?.value ?? "";
  const metrics = cve.metrics || {};
  const v31 = (metrics.cvssMetricV31 || [])[0]?.cvssData;
  const v30 = (metrics.cvssMetricV30 || [])[0]?.cvssData;
  const v3 = v31 || v30;
  const cpes: string[] = [];
  for (const cfg of cve.configurations || []) {
    for (const node of cfg.nodes || []) {
      for (const m of node.cpeMatch || []) {
        if (m.criteria) cpes.push(m.criteria);
      }
    }
  }
  const refs = (cve.references || []).map((r: any) => r.url).filter(Boolean);
  return {
    cveId: id,
    description: desc,
    cvssV3Score: v3?.baseScore ?? null,
    cvssV3Severity: v3?.baseSeverity ?? null,
    cvssVector: v3?.vectorString ?? null,
    cpes: JSON.stringify(cpes),
    keywords: JSON.stringify([]),
    references: JSON.stringify(refs),
    publishedDate: cve.published ?? null,
    lastModifiedDate: cve.lastModified ?? null,
    raw: null,
  };
}

/** Refresh the CISA Known Exploited Vulnerabilities catalog. */
export async function refreshKev(): Promise<FeedResult> {
  try {
    const res = await safeFetch(KEV_URL);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as any;
    const items: any[] = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
    const rows: Kev[] = items.map((it) => ({
      cveId: it.cveID,
      vendorProject: it.vendorProject ?? null,
      product: it.product ?? null,
      vulnerabilityName: it.vulnerabilityName ?? null,
      dateAdded: it.dateAdded ?? null,
      shortDescription: it.shortDescription ?? null,
      requiredAction: it.requiredAction ?? null,
      dueDate: it.dueDate ?? null,
      knownRansomware: it.knownRansomwareCampaignUse ?? null,
      notes: it.notes ?? null,
      cwes: JSON.stringify(it.cwes ?? []),
    }));
    const written = await storage.upsertKev(rows);
    const message = `Imported ${written} KEV entries from CISA`;
    await storage.setFeedMeta({
      source: "kev",
      lastSync: Date.now(),
      lastStatus: "ok",
      recordCount: written,
      message,
    });
    return { source: "kev", ok: true, count: written, message };
  } catch (err: any) {
    const message = `KEV fetch failed: ${err?.message || String(err)}`;
    await storage.setFeedMeta({
      source: "kev",
      lastSync: Date.now(),
      lastStatus: "error",
      recordCount: 0,
      message,
    });
    return { source: "kev", ok: false, count: 0, message };
  }
}

/** Refresh EPSS scores for the given CVE list (or for the top N most recent CVEs we know).
 *  FIRST EPSS supports comma-separated CVE IDs up to ~2000 chars per request, so we batch. */
export async function refreshEpss(cveIds?: string[]): Promise<FeedResult> {
  try {
    let ids = cveIds;
    if (!ids || ids.length === 0) {
      // pull from local CVE table — small subset to remain polite
      const rows = (await storage.searchCves("CVE-", 200)).map((c) => c.cveId);
      ids = rows.slice(0, 200);
    }
    if (!ids.length) {
      const message = "No CVE IDs available to query EPSS";
      await storage.setFeedMeta({
        source: "epss",
        lastSync: Date.now(),
        lastStatus: "skipped",
        recordCount: 0,
        message,
      });
      return { source: "epss", ok: true, count: 0, message };
    }

    const batches: string[][] = [];
    let cur: string[] = [];
    let curLen = 0;
    for (const id of ids) {
      const addLen = id.length + 1;
      if (curLen + addLen > 1800 && cur.length) {
        batches.push(cur);
        cur = [];
        curLen = 0;
      }
      cur.push(id);
      curLen += addLen;
    }
    if (cur.length) batches.push(cur);

    let total = 0;
    for (const batch of batches) {
      const url = new URL(EPSS_URL);
      url.searchParams.set("cve", batch.join(","));
      const res = await safeFetch(url.toString());
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as any;
      const items: any[] = Array.isArray(data?.data) ? data.data : [];
      const rows: Epss[] = items.map((it) => ({
        cveId: it.cve,
        epss: parseFloat(it.epss ?? "0") || 0,
        percentile: parseFloat(it.percentile ?? "0") || 0,
        date: it.date ?? null,
      }));
      total += await storage.upsertEpss(rows);
    }
    const message = `Imported ${total} EPSS scores from FIRST`;
    await storage.setFeedMeta({
      source: "epss",
      lastSync: Date.now(),
      lastStatus: "ok",
      recordCount: total,
      message,
    });
    return { source: "epss", ok: true, count: total, message };
  } catch (err: any) {
    const message = `EPSS fetch failed: ${err?.message || String(err)}`;
    await storage.setFeedMeta({
      source: "epss",
      lastSync: Date.now(),
      lastStatus: "error",
      recordCount: 0,
      message,
    });
    return { source: "epss", ok: false, count: 0, message };
  }
}
