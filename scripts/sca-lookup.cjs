const OSV_BATCH = "https://api.osv.dev/v1/querybatch";
const OSV_RECORD = "https://api.osv.dev/v1/vulns/";
const NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const CVE = /^CVE-\d{4}-\d{4,}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function requireObject(value, label) {
  if (!object(value) || value.error || value.code !== undefined) {
    throw new Error(`${label}: invalid response or service error`);
  }
}
function coordinate(item) {
  if (!object(item) || !["npm", "PyPI"].includes(item.ecosystem) ||
      typeof item.name !== "string" || !item.name ||
      typeof item.version !== "string" || !item.version) {
    throw new Error("invalid package coordinate");
  }
  return { package: { ecosystem: item.ecosystem, name: item.name }, version: item.version };
}

async function lookup(packages, request, options = {}) {
  if (!Array.isArray(packages) || !packages.length || packages.length > 10000 ||
      typeof request !== "function") throw new Error("invalid lookup inputs");
  const pause = options.pause ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  const records = packages.map((item) => ({
    ecosystem: item.ecosystem, name: item.name, version: item.version,
    advisoryIds: new Set(),
  }));
  const queries = packages.map(coordinate);

  for (let offset = 0; offset < queries.length; offset += 100) {
    let pending = queries.slice(offset, offset + 100).map((query, index) => ({
      index: offset + index, query, seen: new Set(),
    }));
    let round = 0;
    while (pending.length) {
      if (++round > 20) throw new Error("OSV pagination limit exceeded");
      const response = await request(OSV_BATCH, {
        queries: pending.map((item) => item.query),
      });
      requireObject(response, "OSV batch");
      if (!Array.isArray(response.results) || response.results.length !== pending.length) {
        throw new Error("OSV batch response count mismatch");
      }
      const next = [];
      for (let index = 0; index < pending.length; index++) {
        const item = pending[index];
        const result = response.results[index];
        requireObject(result, "OSV result");
        const vulns = result.vulns ?? [];
        if (!Array.isArray(vulns)) throw new Error("invalid OSV vulnerability list");
        for (const vuln of vulns) {
          if (!object(vuln) || typeof vuln.id !== "string" || !ID.test(vuln.id)) {
            throw new Error("invalid advisory ID");
          }
          records[item.index].advisoryIds.add(vuln.id);
        }
        const token = result.next_page_token;
        if (token !== undefined && token !== "") {
          if (typeof token !== "string" || token.length > 4096 || item.seen.has(token)) {
            throw new Error("invalid or repeated OSV page token");
          }
          item.seen.add(token);
          next.push({
            ...item,
            query: { ...item.query, page_token: token },
          });
        }
      }
      pending = next;
    }
  }

  const ids = [...new Set(records.flatMap((item) => [...item.advisoryIds]))].sort();
  if (ids.length > 2000) throw new Error("advisory detail limit exceeded");
  const advisories = [];
  const cves = new Set();

  for (const id of ids) {
    const response = await request(OSV_RECORD + encodeURIComponent(id));
    requireObject(response, "OSV advisory");
    if (response.id !== id) throw new Error("advisory identity mismatch");
    const aliases = response.aliases ?? [];
    if (!Array.isArray(aliases) || aliases.some((alias) => typeof alias !== "string")) {
      throw new Error("invalid advisory aliases");
    }
    if (response.withdrawn !== undefined && typeof response.withdrawn !== "string") {
      throw new Error("invalid withdrawn status");
    }
    const cveAliases = [...new Set(
      [id, ...aliases].filter((alias) => CVE.test(alias))
    )].sort();
    for (const cve of cveAliases) cves.add(cve);
    advisories.push({
      id,
      aliases,
      cveAliases,
      withdrawn: response.withdrawn ?? null,
      summary: typeof response.summary === "string" ? response.summary : null,
      record: response,
    });
  }

  const requestedCves = [...cves].sort();
  if (requestedCves.length > 2000) throw new Error("NVD CVE limit exceeded");
  const nvdRecords = new Map();

  for (let offset = 0; offset < requestedCves.length; offset += 100) {
    const group = requestedCves.slice(offset, offset + 100);
    let start = 0;
    let total = null;
    let pages = 0;
    do {
      if (++pages > 20) throw new Error("NVD pagination limit exceeded");
      await pause(6500);
      const url = new URL(NVD);
      url.searchParams.set("cveIds", group.join(","));
      url.searchParams.set("startIndex", String(start));
      url.searchParams.set("resultsPerPage", "100");

      const response = await request(url.href);
      requireObject(response, "NVD");
      if (!Number.isInteger(response.totalResults) || response.totalResults < 0 ||
          response.totalResults > group.length ||
          response.startIndex !== start ||
          !Array.isArray(response.vulnerabilities)) {
        throw new Error("invalid NVD pagination response");
      }
      if (total !== null && total !== response.totalResults) {
        throw new Error("NVD total changed during pagination");
      }
      total = response.totalResults;
      const batch = response.vulnerabilities;
      if (start + batch.length > total || (start < total && !batch.length)) {
        throw new Error("NVD pagination made no valid progress");
      }
      for (const item of batch) {
        const cve = item?.cve;
        if (!object(cve) || !group.includes(cve.id) || nvdRecords.has(cve.id)) {
          throw new Error("unexpected or duplicate NVD CVE");
        }
        nvdRecords.set(cve.id, cve);
      }
      start += batch.length;
    } while (start < total);
  }

  return {
    status: "lookup-completed",
    packages: records.map((item) => ({
      ...item, advisoryIds: [...item.advisoryIds].sort(),
    })),
    advisories,
    nvdRequestedIds: requestedCves,
    nvdRecords: [...nvdRecords.values()].sort((a, b) => a.id.localeCompare(b.id)),
    nvdMissingIds: requestedCves.filter((id) => !nvdRecords.has(id)),
    nvdStatus: requestedCves.length ? "queried" : "not-queried-no-CVE-aliases",
    securityAcceptance: "not-established",
  };
}

module.exports = { lookup, coordinate, OSV_BATCH, OSV_RECORD, NVD };
