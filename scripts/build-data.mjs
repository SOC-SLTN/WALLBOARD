// scripts/build-data.mjs
// The "backend". Runs on GitHub's servers via the Action — no CORS, no proxy,
// not subject to your office network filtering. Reads sources.json, fetches
// every source, normalises it, and writes same-origin JSON the boards read.
//
// Run locally to test:  node scripts/build-data.mjs
// Requires Node 18+ (uses global fetch) and one dependency (fast-xml-parser).

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { XMLParser } from "fast-xml-parser";

const cfg = JSON.parse(await readFile(new URL("../sources.json", import.meta.url)));
const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "@_" });
const UA = { "User-Agent": "soc-wallboard-backend (+github-actions)" };
const nowISO = () => new Date().toISOString();

async function getText(url, headers = {}) {
  const r = await fetch(url, { headers: { ...UA, ...headers } });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.text();
}
const getJSON = async (url, headers = {}) => JSON.parse(await getText(url, headers));
const asArray = (x) => (Array.isArray(x) ? x : x == null ? [] : [x]);

/* ---------- CSAF advisories (e.g. NCSC-NL) ------------------------------ */
// Reads a CSAF directory-based changes.csv (newest-first list of advisory
// files), fetches the top N advisory JSONs, and extracts a headline for each.
async function buildCsafSource(src) {
  const csv = await getText(src.changes);
  const base = src.base.endsWith("/") ? src.base : src.base + "/";
  const rows = csv.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((line) => {
    const i = line.indexOf(",");
    if (i < 0) return null;
    const path = line.slice(0, i).replace(/^"|"$/g, "").replace(/^\.?\//, "").trim();
    const date = line.slice(i + 1).replace(/^"|"$/g, "").trim();
    return { path, date };
  }).filter(Boolean);
  rows.sort((a, b) => (Date.parse(b.date) || 0) - (Date.parse(a.date) || 0));

  const abbr = (s) => (s ? s[0].toUpperCase() : "");
  const items = [];
  for (const r of rows.slice(0, src.max ?? 20)) {
    try {
      const d = (await getJSON(base + r.path)).document || {};
      const id = d.tracking?.id || "";
      const notes = d.notes || [];
      const kans = notes.find((n) => n.title === "Kans")?.text;      // likelihood
      const schade = notes.find((n) => n.title === "Schade")?.text;  // impact
      const rating = kans && schade ? `[${abbr(kans)}/${abbr(schade)}] ` : "";
      const rel = d.tracking?.current_release_date || r.date;
      const d2 = rel ? new Date(rel) : null;
      items.push({
        source: src.name,
        title: `${id ? id + " " : ""}${rating}${d.title || ""}`.trim(),
        link: base + r.path,
        date: d2 && !isNaN(d2) ? d2.toISOString() : null,
      });
    } catch { /* skip a single bad advisory, keep going */ }
  }
  console.log(`news(csaf): ${src.name} -> ${items.length}`);
  return items;
}

/* ---------- NEWS (RSS / Atom) ------------------------------------------- */
async function buildNews() {
  const items = [], health = [];
  for (const f of cfg.news?.feeds ?? []) {
    try {
      const doc = parser.parse(await getText(f.url));
      const rssItems = asArray(doc?.rss?.channel?.item);
      const atomItems = asArray(doc?.feed?.entry);
      const raw = rssItems.length ? rssItems : atomItems;
      const mapped = raw.slice(0, 12).map((it) => {
        const title = (it.title?.["#text"] ?? it.title ?? "").toString().trim();
        const dateStr = it.pubDate || it.published || it.updated || it.date;
        const link = typeof it.link === "string" ? it.link : it.link?.["@_href"] || "";
        const d = dateStr ? new Date(dateStr) : null;
        return { source: f.name, title, link, date: d && !isNaN(d) ? d.toISOString() : null };
      }).filter((x) => x.title);
      items.push(...mapped);
      health.push({ name: f.name, ok: true, count: mapped.length });
      console.log(`news: ${f.name} -> ${mapped.length}`);
    } catch (e) {
      health.push({ name: f.name, ok: false, error: String(e.message || e) });
      console.error(`news: ${f.name} FAILED -> ${e.message || e}`);
    }
  }
  for (const src of cfg.news?.csaf ?? []) {
    try {
      const csafItems = await buildCsafSource(src);
      items.push(...csafItems);
      health.push({ name: src.name, ok: csafItems.length > 0, count: csafItems.length });
    } catch (e) {
      health.push({ name: src.name, ok: false, error: String(e.message || e) });
      console.error(`news(csaf): ${src.name} FAILED -> ${e.message || e}`);
    }
  }
  items.sort((a, b) => (Date.parse(b.date) || 0) - (Date.parse(a.date) || 0));
  return { generatedAt: nowISO(), items: items.slice(0, cfg.news?.max ?? 24), health };
}

/* ---------- VULNERABILITIES (CISA KEV + NVD) ---------------------------- */
async function buildVulns() {
  const out = [], health = [];

  if (cfg.vulns?.kev?.enabled) {
    try {
      const data = await getJSON(cfg.vulns.kev.url);
      const cutoff = Date.now() - (cfg.vulns.kev.recentDays ?? 21) * 864e5;
      for (const v of data.vulnerabilities ?? []) {
        const d = v.dateAdded ? new Date(v.dateAdded) : null;
        if (d && d.getTime() >= cutoff)
          out.push({
            id: v.cveID,
            product: `${v.vendorProject || ""} ${v.product || ""}`.trim(),
            desc: v.vulnerabilityName || v.shortDescription || "",
            date: d.toISOString(), score: null, kev: true,
          });
      }
      health.push({ name: "CISA KEV", ok: true });
      console.log(`vulns: KEV -> ${out.length}`);
    } catch (e) {
      health.push({ name: "CISA KEV", ok: false, error: String(e.message || e) });
      console.error(`vulns: KEV FAILED -> ${e.message || e}`);
    }
  }

  if (cfg.vulns?.nvd?.enabled) {
    try {
      const days = cfg.vulns.nvd.lookbackDays ?? 3;
      const iso = (d) => d.toISOString().slice(0, 19) + ".000";
      const start = new Date(Date.now() - days * 864e5), end = new Date();
      const sev = cfg.vulns.nvd.severity || "CRITICAL";
      const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${iso(start)}&pubEndDate=${iso(end)}&cvssV3Severity=${sev}&resultsPerPage=200`;
      const headers = cfg.vulns.nvd.apiKey ? { apiKey: cfg.vulns.nvd.apiKey } : {};
      const data = await getJSON(url, headers);
      let n = 0;
      for (const w of data.vulnerabilities ?? []) {
        const c = w.cve, m = c.metrics || {};
        const metric = (m.cvssMetricV31 || m.cvssMetricV30 || [])[0];
        const score = metric ? metric.cvssData.baseScore : null;
        const desc = (c.descriptions || []).find((x) => x.lang === "en")?.value || "";
        if (score != null) {
          out.push({ id: c.id, product: "", desc, date: c.published ? new Date(c.published).toISOString() : null, score, kev: false });
          n++;
        }
      }
      health.push({ name: "NVD", ok: true });
      console.log(`vulns: NVD -> ${n}`);
    } catch (e) {
      health.push({ name: "NVD", ok: false, error: String(e.message || e) });
      console.error(`vulns: NVD FAILED -> ${e.message || e}`);
    }
  }

  // Merge, KEV wins on duplicate id; exploited first, then newest.
  const byId = new Map();
  for (const v of out) {
    const ex = byId.get(v.id);
    byId.set(v.id, ex ? { ...ex, ...v, kev: ex.kev || v.kev, score: v.score ?? ex.score } : v);
  }
  const merged = [...byId.values()].sort((a, b) =>
    a.kev !== b.kev ? (a.kev ? -1 : 1) : (Date.parse(b.date) || 0) - (Date.parse(a.date) || 0)
  );
  return { generatedAt: nowISO(), items: merged.slice(0, cfg.vulns?.max ?? 30), health };
}

/* ---------- RANSOMWARE (ransomware.live) -------------------------------- */
async function buildRansomware() {
  if (!cfg.ransomware?.enabled) return null;
  const data = await getJSON(cfg.ransomware.url);
  const list = Array.isArray(data) ? data : data.victims || data.data || [];
  const items = list.slice(0, cfg.ransomware.max ?? 40).map((v) => ({
    victim: v.victim || "", group: v.group || v.group_name || "",
    country: v.country || "", activity: v.activity || v.sector || "",
    attackdate: v.attackdate || v.discovered || v.published || null,
  }));
  console.log(`ransomware -> ${items.length}`);
  return { generatedAt: nowISO(), items };
}

/* ---------- Write outputs (one failure never blanks a file) ------------- */
await mkdir("data", { recursive: true });
for (const [file, fn] of [
  ["data/news.json", buildNews],
  ["data/vulns.json", buildVulns],
  ["data/ransomware.json", buildRansomware],
]) {
  try {
    const res = await fn();
    if (res) { await writeFile(file, JSON.stringify(res)); console.log(`wrote ${file}`); }
  } catch (e) {
    // Leave the last good file in place rather than overwriting with nothing.
    console.error(`skipped ${file}: ${e.message || e}`);
  }
}
