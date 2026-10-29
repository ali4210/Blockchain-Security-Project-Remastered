#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const Database = require("better-sqlite3");

const nvdDir = path.join(os.homedir(), ".local/state/nvd-mirror");
const osvDir = path.join(os.homedir(), ".local/state/osv-mirror");
const dbPath = path.join(nvdDir, "index.sqlite");

// Full corpora (412k NVD CVEs / 1.9GB raw, 269k OSV records / 1.4GB raw) do not fit
// in a single JSON string (V8 string length ceiling ~512MB) -- this streams each
// source file in, writes it straight to SQLite, and discards it before the next file.
for (const suffix of ["", "-wal", "-shm"]) fs.rmSync(dbPath + suffix, { force: true });

const db = new Database(dbPath);
db.pragma("journal_mode = WAL");
db.pragma("synchronous = NORMAL");
db.exec("CREATE TABLE IF NOT EXISTS cves (cve_id TEXT PRIMARY KEY, data TEXT NOT NULL)");
db.exec("CREATE TABLE IF NOT EXISTS osv (id TEXT PRIMARY KEY, data TEXT NOT NULL)");
db.exec("DELETE FROM cves");
db.exec("DELETE FROM osv");

const insertCve = db.prepare("INSERT OR REPLACE INTO cves (cve_id, data) VALUES (?, ?)");
const insertOsv = db.prepare("INSERT OR REPLACE INTO osv (id, data) VALUES (?, ?)");

// --- NVD: one page file at a time, one transaction per file ---
let nvdTotal = 0;
let nvdSkipped = 0;

const nvdFiles = fs.readdirSync(nvdDir)
  .filter((f) => f.startsWith("page_") && f.endsWith(".json"))
  .sort();

for (const file of nvdFiles) {
  let data;
  try {
    data = JSON.parse(fs.readFileSync(path.join(nvdDir, file), "utf8"));
  } catch (err) {
    console.warn(`[!] skipping corrupt NVD file ${file}: ${err.message}`);
    nvdSkipped++;
    continue;
  }

  const items = data.vulnerabilities ?? [];
  let pageCount = 0;
  const insertPage = db.transaction((rows) => {
    for (const item of rows) {
      if (item?.cve?.id) {
        insertCve.run(item.cve.id, JSON.stringify(item.cve));
        pageCount++;
      }
    }
  });
  insertPage(items);
  nvdTotal += pageCount;
  console.log(`[+] ${file}: ${pageCount} CVEs inserted, ${nvdTotal} total so far`);
}

console.log(`[+] NVD index complete: ${nvdTotal} CVEs` +
  (nvdSkipped ? ` (${nvdSkipped} corrupt files skipped)` : ""));

// --- OSV: one ecosystem directory at a time, one transaction per directory ---
// (one record per file here, unlike NVD's ~2000-per-page -- batching per directory
// instead of per file avoids ~270k single-row transactions)
let osvTotal = 0;
let osvSkipped = 0;

for (const eco of fs.readdirSync(osvDir)) {
  const ecoDir = path.join(osvDir, eco);
  if (!fs.statSync(ecoDir).isDirectory()) continue;

  const files = fs.readdirSync(ecoDir).filter((f) => f.endsWith(".json"));
  let ecoCount = 0;
  let ecoSkipped = 0;

  const insertDir = db.transaction(() => {
    for (const file of files) {
      try {
        const rec = JSON.parse(fs.readFileSync(path.join(ecoDir, file), "utf8"));
        if (!rec.id) continue;
        insertOsv.run(rec.id, JSON.stringify(rec));
        ecoCount++;
      } catch (err) {
        console.warn(`[!] skipping corrupt OSV file ${eco}/${file}: ${err.message}`);
        ecoSkipped++;
      }
    }
  });
  insertDir();

  osvTotal += ecoCount;
  osvSkipped += ecoSkipped;
  console.log(`[+] osv/${eco}: ${ecoCount} advisories inserted, ${osvTotal} total so far` +
    (ecoSkipped ? ` (${ecoSkipped} corrupt files skipped)` : ""));
}

console.log(`[+] OSV index complete: ${osvTotal} advisories` +
  (osvSkipped ? ` (${osvSkipped} corrupt files skipped)` : ""));

db.close();
console.log(`[+] wrote ${dbPath}`);
