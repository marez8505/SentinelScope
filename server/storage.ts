import {
  scans,
  findings,
  cves,
  kev,
  epss,
  feedMeta,
  settings,
  type Scan,
  type Finding,
  type Cve,
  type Kev,
  type Epss,
  type FeedMeta,
  type Setting,
  type InsertScan,
  type InsertFinding,
} from "@shared/schema";
import { drizzle } from "drizzle-orm/better-sqlite3";
import Database from "better-sqlite3";
import { eq, desc, and, inArray } from "drizzle-orm";
import { chmodSync } from "node:fs";

const DB_PATH = "data.db";
const sqlite = new Database(DB_PATH);
sqlite.pragma("journal_mode = WAL");
sqlite.pragma("foreign_keys = ON");

// Restrict DB file permissions on POSIX systems. The SQLite WAL/SHM sidecar
// files inherit perms from the main DB on creation, but we re-chmod them too
// after they appear (best-effort; never fatal).
if (process.platform !== "win32") {
  for (const path of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`]) {
    try {
      chmodSync(path, 0o600);
    } catch {
      // File may not exist yet (WAL/SHM created lazily) — ignored.
    }
  }
}

// Lightweight inline migrations (template avoids drizzle-kit at runtime).
sqlite.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    resolved_ip TEXT,
    profile TEXT NOT NULL,
    ports TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    error TEXT,
    summary TEXT,
    authorized_ack INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    port INTEGER,
    service TEXT,
    product TEXT,
    version TEXT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_score REAL,
    cve_ids TEXT,
    evidence TEXT,
    match_basis TEXT,
    confidence TEXT,
    "references" TEXT,
    remediation TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);

  CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    cvss_v3_score REAL,
    cvss_v3_severity TEXT,
    cvss_vector TEXT,
    cpes TEXT,
    keywords TEXT,
    "references" TEXT,
    published_date TEXT,
    last_modified_date TEXT,
    raw TEXT
  );

  CREATE TABLE IF NOT EXISTS kev (
    cve_id TEXT PRIMARY KEY,
    vendor_project TEXT,
    product TEXT,
    vulnerability_name TEXT,
    date_added TEXT,
    short_description TEXT,
    required_action TEXT,
    due_date TEXT,
    known_ransomware TEXT,
    notes TEXT,
    cwes TEXT
  );

  CREATE TABLE IF NOT EXISTS epss (
    cve_id TEXT PRIMARY KEY,
    epss REAL,
    percentile REAL,
    date TEXT
  );

  CREATE TABLE IF NOT EXISTS feed_meta (
    source TEXT PRIMARY KEY,
    last_sync INTEGER,
    last_status TEXT,
    record_count INTEGER,
    message TEXT
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

export const db = drizzle(sqlite);

export interface IStorage {
  // scans
  createScan(s: InsertScan & { startedAt: number; status: string; resolvedIp?: string | null }): Promise<Scan>;
  getScan(id: number): Promise<Scan | undefined>;
  listScans(): Promise<Scan[]>;
  updateScan(id: number, patch: Partial<Scan>): Promise<Scan | undefined>;

  // findings
  addFinding(f: InsertFinding & { createdAt: number }): Promise<Finding>;
  getFindingsByScan(scanId: number): Promise<Finding[]>;
  getFinding(id: number): Promise<Finding | undefined>;
  updateFindingStatus(id: number, status: string): Promise<Finding | undefined>;
  recentFindings(limit?: number): Promise<Finding[]>;

  // CVEs
  upsertCves(rows: Cve[]): Promise<number>;
  searchCves(q: string, limit?: number): Promise<Cve[]>;
  countCves(): Promise<number>;
  getCveById(id: string): Promise<Cve | undefined>;

  // KEV / EPSS
  upsertKev(rows: Kev[]): Promise<number>;
  countKev(): Promise<number>;
  getKevByIds(ids: string[]): Promise<Kev[]>;
  upsertEpss(rows: Epss[]): Promise<number>;
  countEpss(): Promise<number>;
  getEpssByIds(ids: string[]): Promise<Epss[]>;

  // feed meta
  setFeedMeta(m: FeedMeta): Promise<void>;
  getFeedMeta(source: string): Promise<FeedMeta | undefined>;
  listFeedMeta(): Promise<FeedMeta[]>;

  // settings
  setSetting(key: string, value: string): Promise<void>;
  getSetting(key: string): Promise<Setting | undefined>;
}

export class DatabaseStorage implements IStorage {
  // ---- Scans ----
  async createScan(s: InsertScan & { startedAt: number; status: string; resolvedIp?: string | null }): Promise<Scan> {
    return db
      .insert(scans)
      .values({
        target: s.target,
        profile: s.profile,
        ports: s.ports,
        authorizedAck: s.authorizedAck,
        status: s.status,
        startedAt: s.startedAt,
        resolvedIp: s.resolvedIp ?? null,
      })
      .returning()
      .get();
  }
  async getScan(id: number): Promise<Scan | undefined> {
    return db.select().from(scans).where(eq(scans.id, id)).get();
  }
  async listScans(): Promise<Scan[]> {
    return db.select().from(scans).orderBy(desc(scans.startedAt)).all();
  }
  async updateScan(id: number, patch: Partial<Scan>): Promise<Scan | undefined> {
    const current = await this.getScan(id);
    if (!current) return undefined;
    const merged = { ...current, ...patch };
    db.update(scans).set(merged).where(eq(scans.id, id)).run();
    return this.getScan(id);
  }

  // ---- Findings ----
  async addFinding(f: InsertFinding & { createdAt: number }): Promise<Finding> {
    return db.insert(findings).values(f).returning().get();
  }
  async getFindingsByScan(scanId: number): Promise<Finding[]> {
    return db.select().from(findings).where(eq(findings.scanId, scanId)).all();
  }
  async getFinding(id: number): Promise<Finding | undefined> {
    return db.select().from(findings).where(eq(findings.id, id)).get();
  }
  async updateFindingStatus(id: number, status: string): Promise<Finding | undefined> {
    db.update(findings).set({ status }).where(eq(findings.id, id)).run();
    return this.getFinding(id);
  }
  async recentFindings(limit = 25): Promise<Finding[]> {
    return db.select().from(findings).orderBy(desc(findings.createdAt)).limit(limit).all();
  }

  // ---- CVEs ----
  async upsertCves(rows: Cve[]): Promise<number> {
    if (!rows.length) return 0;
    const tx = sqlite.transaction((items: Cve[]) => {
      const stmt = sqlite.prepare(`
        INSERT INTO cves (cve_id, description, cvss_v3_score, cvss_v3_severity, cvss_vector,
                          cpes, keywords, "references", published_date, last_modified_date, raw)
        VALUES (@cveId, @description, @cvssV3Score, @cvssV3Severity, @cvssVector,
                @cpes, @keywords, @references, @publishedDate, @lastModifiedDate, @raw)
        ON CONFLICT(cve_id) DO UPDATE SET
          description=excluded.description,
          cvss_v3_score=excluded.cvss_v3_score,
          cvss_v3_severity=excluded.cvss_v3_severity,
          cvss_vector=excluded.cvss_vector,
          cpes=excluded.cpes,
          keywords=excluded.keywords,
          "references"=excluded."references",
          published_date=excluded.published_date,
          last_modified_date=excluded.last_modified_date,
          raw=excluded.raw
      `);
      for (const r of items) {
        stmt.run({
          cveId: r.cveId,
          description: r.description ?? null,
          cvssV3Score: r.cvssV3Score ?? null,
          cvssV3Severity: r.cvssV3Severity ?? null,
          cvssVector: r.cvssVector ?? null,
          cpes: r.cpes ?? null,
          keywords: r.keywords ?? null,
          references: r.references ?? null,
          publishedDate: r.publishedDate ?? null,
          lastModifiedDate: r.lastModifiedDate ?? null,
          raw: r.raw ?? null,
        });
      }
      return items.length;
    });
    return tx(rows);
  }
  async searchCves(q: string, limit = 50): Promise<Cve[]> {
    const pattern = `%${q.toLowerCase()}%`;
    const rows = sqlite
      .prepare(
        `SELECT * FROM cves
         WHERE LOWER(cve_id) LIKE ?
            OR LOWER(description) LIKE ?
            OR LOWER(keywords) LIKE ?
         ORDER BY cvss_v3_score DESC
         LIMIT ?`,
      )
      .all(pattern, pattern, pattern, limit) as any[];
    return rows.map(rowToCve);
  }
  async countCves(): Promise<number> {
    const r = sqlite.prepare(`SELECT COUNT(*) AS c FROM cves`).get() as { c: number };
    return r.c;
  }
  async getCveById(id: string): Promise<Cve | undefined> {
    const r = sqlite.prepare(`SELECT * FROM cves WHERE cve_id = ?`).get(id) as any;
    return r ? rowToCve(r) : undefined;
  }

  // ---- KEV ----
  async upsertKev(rows: Kev[]): Promise<number> {
    if (!rows.length) return 0;
    const tx = sqlite.transaction((items: Kev[]) => {
      const stmt = sqlite.prepare(`
        INSERT INTO kev (cve_id, vendor_project, product, vulnerability_name, date_added,
                         short_description, required_action, due_date, known_ransomware, notes, cwes)
        VALUES (@cveId, @vendorProject, @product, @vulnerabilityName, @dateAdded,
                @shortDescription, @requiredAction, @dueDate, @knownRansomware, @notes, @cwes)
        ON CONFLICT(cve_id) DO UPDATE SET
          vendor_project=excluded.vendor_project,
          product=excluded.product,
          vulnerability_name=excluded.vulnerability_name,
          date_added=excluded.date_added,
          short_description=excluded.short_description,
          required_action=excluded.required_action,
          due_date=excluded.due_date,
          known_ransomware=excluded.known_ransomware,
          notes=excluded.notes,
          cwes=excluded.cwes
      `);
      for (const r of items) stmt.run(r);
      return items.length;
    });
    return tx(rows);
  }
  async countKev(): Promise<number> {
    const r = sqlite.prepare(`SELECT COUNT(*) AS c FROM kev`).get() as { c: number };
    return r.c;
  }
  async getKevByIds(ids: string[]): Promise<Kev[]> {
    if (!ids.length) return [];
    return db.select().from(kev).where(inArray(kev.cveId, ids)).all();
  }

  // ---- EPSS ----
  async upsertEpss(rows: Epss[]): Promise<number> {
    if (!rows.length) return 0;
    const tx = sqlite.transaction((items: Epss[]) => {
      const stmt = sqlite.prepare(`
        INSERT INTO epss (cve_id, epss, percentile, date)
        VALUES (@cveId, @epss, @percentile, @date)
        ON CONFLICT(cve_id) DO UPDATE SET
          epss=excluded.epss,
          percentile=excluded.percentile,
          date=excluded.date
      `);
      for (const r of items) stmt.run(r);
      return items.length;
    });
    return tx(rows);
  }
  async countEpss(): Promise<number> {
    const r = sqlite.prepare(`SELECT COUNT(*) AS c FROM epss`).get() as { c: number };
    return r.c;
  }
  async getEpssByIds(ids: string[]): Promise<Epss[]> {
    if (!ids.length) return [];
    return db.select().from(epss).where(inArray(epss.cveId, ids)).all();
  }

  // ---- Feed meta ----
  async setFeedMeta(m: FeedMeta): Promise<void> {
    sqlite
      .prepare(
        `INSERT INTO feed_meta (source, last_sync, last_status, record_count, message)
         VALUES (@source, @lastSync, @lastStatus, @recordCount, @message)
         ON CONFLICT(source) DO UPDATE SET
           last_sync=excluded.last_sync,
           last_status=excluded.last_status,
           record_count=excluded.record_count,
           message=excluded.message`,
      )
      .run(m);
  }
  async getFeedMeta(source: string): Promise<FeedMeta | undefined> {
    return db.select().from(feedMeta).where(eq(feedMeta.source, source)).get();
  }
  async listFeedMeta(): Promise<FeedMeta[]> {
    return db.select().from(feedMeta).all();
  }

  // ---- Settings ----
  async setSetting(key: string, value: string): Promise<void> {
    sqlite
      .prepare(
        `INSERT INTO settings (key, value) VALUES (?, ?)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
      )
      .run(key, value);
  }
  async getSetting(key: string): Promise<Setting | undefined> {
    return db.select().from(settings).where(eq(settings.key, key)).get();
  }
}

function rowToCve(r: any): Cve {
  return {
    cveId: r.cve_id,
    description: r.description,
    cvssV3Score: r.cvss_v3_score,
    cvssV3Severity: r.cvss_v3_severity,
    cvssVector: r.cvss_vector,
    cpes: r.cpes,
    keywords: r.keywords,
    references: r.references,
    publishedDate: r.published_date,
    lastModifiedDate: r.last_modified_date,
    raw: r.raw,
  };
}

export const storage = new DatabaseStorage();
