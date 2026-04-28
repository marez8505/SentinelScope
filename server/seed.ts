/**
 * Bundled sample data so SentinelScope can run fully offline.
 * Loaded on first start when the CVE/KEV/EPSS tables are empty.
 * This is a curated, illustrative subset — refresh from official feeds for live data.
 */
import type { Cve, Kev, Epss } from "@shared/schema";

export const seedCves: Cve[] = [
  {
    cveId: "CVE-2014-0160",
    description:
      "OpenSSL 1.0.1 through 1.0.1f Heartbeat extension (Heartbleed) allows remote attackers to obtain sensitive memory contents via crafted heartbeat packets.",
    cvssV3Score: 7.5,
    cvssV3Severity: "HIGH",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cpes: JSON.stringify(["cpe:2.3:a:openssl:openssl:1.0.1*"]),
    keywords: JSON.stringify(["openssl", "heartbleed", "tls"]),
    references: JSON.stringify([
      "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
      "https://heartbleed.com/",
    ]),
    publishedDate: "2014-04-07",
    lastModifiedDate: "2023-11-07",
    raw: null,
  },
  {
    cveId: "CVE-2017-5638",
    description:
      "Apache Struts 2 Jakarta Multipart parser allows remote code execution via crafted Content-Type header.",
    cvssV3Score: 9.8,
    cvssV3Severity: "CRITICAL",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cpes: JSON.stringify(["cpe:2.3:a:apache:struts:*"]),
    keywords: JSON.stringify(["apache", "struts", "jakarta"]),
    references: JSON.stringify([
      "https://nvd.nist.gov/vuln/detail/CVE-2017-5638",
      "https://cwiki.apache.org/confluence/display/WW/S2-045",
    ]),
    publishedDate: "2017-03-11",
    lastModifiedDate: "2023-12-11",
    raw: null,
  },
  {
    cveId: "CVE-2021-44228",
    description:
      "Apache Log4j2 JNDI lookup in log messages allows attackers to execute arbitrary code (Log4Shell).",
    cvssV3Score: 10.0,
    cvssV3Severity: "CRITICAL",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    cpes: JSON.stringify(["cpe:2.3:a:apache:log4j:*"]),
    keywords: JSON.stringify(["log4j", "log4shell", "apache"]),
    references: JSON.stringify([
      "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
      "https://logging.apache.org/log4j/2.x/security.html",
    ]),
    publishedDate: "2021-12-10",
    lastModifiedDate: "2024-01-31",
    raw: null,
  },
  {
    cveId: "CVE-2018-15473",
    description:
      "OpenSSH through 7.7 username enumeration via auth response timing differences.",
    cvssV3Score: 5.3,
    cvssV3Severity: "MEDIUM",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cpes: JSON.stringify(["cpe:2.3:a:openbsd:openssh:*"]),
    keywords: JSON.stringify(["openssh", "ssh", "enumeration"]),
    references: JSON.stringify([
      "https://nvd.nist.gov/vuln/detail/CVE-2018-15473",
    ]),
    publishedDate: "2018-08-17",
    lastModifiedDate: "2023-02-23",
    raw: null,
  },
  {
    cveId: "CVE-2023-44487",
    description:
      "HTTP/2 Rapid Reset Attack — multiple HTTP/2 implementations allow denial of service via rapid stream cancellation.",
    cvssV3Score: 7.5,
    cvssV3Severity: "HIGH",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    cpes: JSON.stringify(["cpe:2.3:a:nginx:nginx:*", "cpe:2.3:a:apache:httpd:*"]),
    keywords: JSON.stringify(["http/2", "rapid reset", "nginx", "apache"]),
    references: JSON.stringify([
      "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
    ]),
    publishedDate: "2023-10-10",
    lastModifiedDate: "2024-03-04",
    raw: null,
  },
];

export const seedKev: Kev[] = [
  {
    cveId: "CVE-2017-5638",
    vendorProject: "Apache",
    product: "Struts",
    vulnerabilityName: "Apache Struts 2 Jakarta Multipart Parser RCE",
    dateAdded: "2021-11-03",
    shortDescription:
      "Apache Struts 2 contains a remote code execution vulnerability via the Jakarta Multipart parser.",
    requiredAction: "Apply updates per vendor instructions.",
    dueDate: "2022-05-03",
    knownRansomware: "Known",
    notes: "",
    cwes: JSON.stringify(["CWE-20"]),
  },
  {
    cveId: "CVE-2021-44228",
    vendorProject: "Apache",
    product: "Log4j2",
    vulnerabilityName: "Apache Log4j2 Remote Code Execution Vulnerability",
    dateAdded: "2021-12-10",
    shortDescription:
      "Apache Log4j2 contains a remote code execution vulnerability through unauthenticated JNDI lookup.",
    requiredAction: "Apply updates per vendor instructions.",
    dueDate: "2021-12-24",
    knownRansomware: "Known",
    notes: "",
    cwes: JSON.stringify(["CWE-20", "CWE-400", "CWE-502"]),
  },
];

export const seedEpss: Epss[] = [
  { cveId: "CVE-2017-5638", epss: 0.9745, percentile: 0.9999, date: "2025-01-01" },
  { cveId: "CVE-2021-44228", epss: 0.9756, percentile: 0.9999, date: "2025-01-01" },
  { cveId: "CVE-2014-0160", epss: 0.9412, percentile: 0.9985, date: "2025-01-01" },
  { cveId: "CVE-2018-15473", epss: 0.0123, percentile: 0.8421, date: "2025-01-01" },
  { cveId: "CVE-2023-44487", epss: 0.6612, percentile: 0.9912, date: "2025-01-01" },
];
