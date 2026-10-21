#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const nvdDir = path.join(os.homedir(), ".local/state/nvd-mirror");
const osvDir = path.join(os.homedir(), ".local/state/osv-mirror");

// --- NVD: merge all pages into one id -> cve record map ---
const nvdIndex = {};
let nvdSkipped = 0;

for (const file of fs.readdirSync(nvdDir)) {
  if (!file.startsWith("page_") || !file.endsWith(".json")) continue;
  try {
    const data = JSON.parse(fs.readFileSync(path.join(nvdDir, file), "utf8"));
    for (const item of data.vulnerabilities ?? []) {
      if (item?.cve?.id) nvdIndex[item.cve.id] = item.cve;
    }
  } catch (err) {
    console.warn(`[!] skipping corrupt NVD file ${file}: ${err.message}`);
    nvdSkipped++;
  }
}
fs.writeFileSync(path.join(nvdDir, "index.json"), JSON.stringify(nvdIndex));
console.log(`[+] NVD index: ${Object.keys(nvdIndex).length} CVEs` +
  (nvdSkipped ? ` (${nvdSkipped} corrupt files skipped)` : ""));

// --- OSV: id -> full record, and (ecosystem/name) -> [ids] (coarse match) ---
const byId = {};
const byPackage = {};
let osvSkipped = 0;

for (const eco of fs.readdirSync(osvDir)) {
  const ecoDir = path.join(osvDir, eco);
  if (!fs.statSync(ecoDir).isDirectory()) continue;

  for (const file of fs.readdirSync(ecoDir)) {
    if (!file.endsWith(".json") || file === "all.zip") continue;
    try {
      const rec = JSON.parse(fs.readFileSync(path.join(ecoDir, file), "utf8"));
      if (!rec.id) continue;
      byId[rec.id] = rec;
      for (const aff of rec.affected ?? []) {
        const pkgEco = aff.package?.ecosystem;
        const name = aff.package?.name;
        if (!pkgEco || !name) continue;
        const key = `${pkgEco}/${name}`;
        (byPackage[key] ??= []).push(rec.id);
      }
    } catch (err) {
      console.warn(`[!] skipping corrupt OSV file ${eco}/${file}: ${err.message}`);
      osvSkipped++;
    }
  }
}
fs.writeFileSync(path.join(osvDir, "index-by-id.json"), JSON.stringify(byId));
fs.writeFileSync(path.join(osvDir, "index-by-package.json"), JSON.stringify(byPackage));
console.log(`[+] OSV index: ${Object.keys(byId).length} advisories, ` +
  `${Object.keys(byPackage).length} packages` +
  (osvSkipped ? ` (${osvSkipped} corrupt files skipped)` : ""));