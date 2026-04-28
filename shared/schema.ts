import { sqliteTable, text, integer, real } from "drizzle-orm/sqlite-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

/** -------------------------------------------------------------------------
 * Scans
 * -------------------------------------------------------------------------*/
export const scans = sqliteTable("scans", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  target: text("target").notNull(),
  resolvedIp: text("resolved_ip"),
  profile: text("profile").notNull(), // quick | standard | web | custom
  ports: text("ports").notNull(), // JSON-encoded number[]
  status: text("status").notNull(), // queued | running | complete | failed
  startedAt: integer("started_at").notNull(),
  finishedAt: integer("finished_at"),
  error: text("error"),
  summary: text("summary"), // JSON: counts by severity
  authorizedAck: integer("authorized_ack").notNull().default(0), // 0/1
});

export const insertScanSchema = createInsertSchema(scans).omit({
  id: true,
  finishedAt: true,
  error: true,
  summary: true,
  resolvedIp: true,
  status: true,
  startedAt: true,
});
export type InsertScan = z.infer<typeof insertScanSchema>;
export type Scan = typeof scans.$inferSelect;

/** -------------------------------------------------------------------------
 * Findings
 * -------------------------------------------------------------------------*/
export const findings = sqliteTable("findings", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  scanId: integer("scan_id").notNull(),
  host: text("host").notNull(),
  port: integer("port"),
  service: text("service"),
  product: text("product"),
  version: text("version"),
  title: text("title").notNull(),
  description: text("description").notNull(),
  severity: text("severity").notNull(), // info | low | medium | high | critical
  cvssScore: real("cvss_score"),
  cveIds: text("cve_ids"), // JSON-encoded string[]
  evidence: text("evidence"), // JSON or text
  matchBasis: text("match_basis"), // service|version|keyword|cpe|header|tls|dns
  confidence: text("confidence"), // low|medium|high
  references: text("references"), // JSON-encoded string[]
  remediation: text("remediation"),
  status: text("status").notNull().default("open"), // open|accepted_risk|resolved
  createdAt: integer("created_at").notNull(),
});

export const insertFindingSchema = createInsertSchema(findings).omit({
  id: true,
  createdAt: true,
});
export type InsertFinding = z.infer<typeof insertFindingSchema>;
export type Finding = typeof findings.$inferSelect;

/** -------------------------------------------------------------------------
 * CVE / KEV / EPSS
 * -------------------------------------------------------------------------*/
export const cves = sqliteTable("cves", {
  cveId: text("cve_id").primaryKey(),
  description: text("description"),
  cvssV3Score: real("cvss_v3_score"),
  cvssV3Severity: text("cvss_v3_severity"),
  cvssVector: text("cvss_vector"),
  cpes: text("cpes"), // JSON
  keywords: text("keywords"), // JSON
  references: text("references"), // JSON
  publishedDate: text("published_date"),
  lastModifiedDate: text("last_modified_date"),
  raw: text("raw"), // JSON for extra
});
export type Cve = typeof cves.$inferSelect;

export const kev = sqliteTable("kev", {
  cveId: text("cve_id").primaryKey(),
  vendorProject: text("vendor_project"),
  product: text("product"),
  vulnerabilityName: text("vulnerability_name"),
  dateAdded: text("date_added"),
  shortDescription: text("short_description"),
  requiredAction: text("required_action"),
  dueDate: text("due_date"),
  knownRansomware: text("known_ransomware"),
  notes: text("notes"),
  cwes: text("cwes"), // JSON
});
export type Kev = typeof kev.$inferSelect;

export const epss = sqliteTable("epss", {
  cveId: text("cve_id").primaryKey(),
  epss: real("epss"),
  percentile: real("percentile"),
  date: text("date"),
});
export type Epss = typeof epss.$inferSelect;

/** -------------------------------------------------------------------------
 * Feed metadata
 * -------------------------------------------------------------------------*/
export const feedMeta = sqliteTable("feed_meta", {
  source: text("source").primaryKey(), // nvd|kev|epss
  lastSync: integer("last_sync"),
  lastStatus: text("last_status"),
  recordCount: integer("record_count"),
  message: text("message"),
});
export type FeedMeta = typeof feedMeta.$inferSelect;

/** -------------------------------------------------------------------------
 * Settings (single-row)
 * -------------------------------------------------------------------------*/
export const settings = sqliteTable("settings", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
});
export type Setting = typeof settings.$inferSelect;

/** -------------------------------------------------------------------------
 * Zod request/input shapes
 * -------------------------------------------------------------------------*/
// Allowed scan profile names. "custom" lets caller pass their own port list.
export const scanProfiles = ["quick", "standard", "web", "custom"] as const;
export type ScanProfile = (typeof scanProfiles)[number];

// Strict target validation. Hostname per RFC 1123 OR IPv4 OR IPv6 in brackets/raw.
// Disallow URLs, schemes, paths, credentials, query, '@', whitespace.
const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})$/;
// Loose IPv6 (rfc-ish) — bracketed allowed, but stripped before storage.
const IPV6_RE = /^[0-9a-f:]{2,39}$/i;

export const targetSchema = z
  .string()
  .trim()
  .min(1, "Target is required")
  .max(253, "Target too long")
  .refine((v) => !/\s/.test(v), "No whitespace")
  .refine((v) => !v.includes("://"), "Provide host only, not a URL")
  .refine((v) => !v.includes("/"), "No path component")
  .refine((v) => !v.includes("@"), "No credentials allowed")
  .refine((v) => !v.includes("?") && !v.includes("#"), "No query/fragment")
  .transform((v) => (v.startsWith("[") && v.endsWith("]") ? v.slice(1, -1) : v))
  .refine(
    (v) => HOSTNAME_RE.test(v) || IPV4_RE.test(v) || IPV6_RE.test(v),
    "Must be a hostname, IPv4, or IPv6 address",
  );

export const portsArraySchema = z
  .array(z.number().int().min(1).max(65535))
  .min(1, "At least one port")
  .max(200, "Too many ports (max 200)");

export const portsStringSchema = z
  .string()
  .trim()
  .min(1)
  .max(2048)
  .regex(/^[0-9,\s\-]+$/, "Only digits, commas, spaces, and dashes allowed");

export const newScanRequestSchema = z.object({
  target: targetSchema,
  profile: z.enum(scanProfiles),
  customPorts: portsStringSchema.optional(),
  authorizedAck: z.literal(true, {
    errorMap: () => ({ message: "You must acknowledge authorization" }),
  }),
});
export type NewScanRequest = z.infer<typeof newScanRequestSchema>;

export const findingStatusSchema = z.enum(["open", "accepted_risk", "resolved"]);

export const updateFindingStatusSchema = z.object({
  status: findingStatusSchema,
});

export const refreshFeedRequestSchema = z.object({
  source: z.enum(["nvd", "kev", "epss", "all"]),
});

export const severities = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof severities)[number];
