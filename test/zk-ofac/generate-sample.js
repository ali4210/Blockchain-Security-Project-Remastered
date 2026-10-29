// Section G: builds real circuit inputs from the REAL OFAC SDN snapshot
// already mirrored by scripts/mirror-ofac.py, not fabricated addresses.
const fs = require("fs");
const path = require("path");
const circomlibjs = require("circomlibjs");

const SNAPSHOT = path.join(process.env.HOME, ".local/state/ofac-mirror/ofac-crypto-snapshot.json");
// Documented canaries, also used by scripts/run-ofac-screening.py elsewhere in
// this pipeline -- real, verified-present/verified-absent entries, not invented.
const FLAGGED_CANARY = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"; // real, LAZARUS GROUP
const CLEAN_CANARY = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";   // real, not in the SDN snapshot

function addrToField(addr) {
  return BigInt(addr.toLowerCase()).toString();
}

async function main() {
  const snapshot = JSON.parse(fs.readFileSync(SNAPSHOT, "utf8"));
  const ethEntries = snapshot.entries.filter((e) => e.currency === "ETH").slice(0, 8);
  if (!ethEntries.some((e) => e.address.toLowerCase() === FLAGGED_CANARY.toLowerCase())) {
    throw new Error("documented flagged canary not found in the first 8 real ETH entries");
  }

  // circomlibjs ships a pure-JS/WASM poseidon implementation matching the
  // circuit's Poseidon(1) exactly -- same constants, same permutation.
  const poseidon = await circomlibjs.buildPoseidon();
  const hashOf = (addr) => poseidon.F.toString(poseidon([BigInt(addr.toLowerCase())]));

  const flaggedHashes = ethEntries.map((e) => hashOf(e.address));

  const out = {
    source_snapshot: SNAPSHOT,
    flagged_entries: ethEntries.map((e) => ({ address: e.address, entity_name: e.entity_name })),
    flaggedHashes,
    clean_input: { address: addrToField(CLEAN_CANARY), raw_address: CLEAN_CANARY },
    flagged_input: { address: addrToField(FLAGGED_CANARY), raw_address: FLAGGED_CANARY },
  };
  fs.writeFileSync(path.join(__dirname, "sample-data.json"), JSON.stringify(out, null, 2));
  console.log(`[+] wrote sample-data.json: ${ethEntries.length} real flagged entries (incl. documented Lazarus canary)`);
  for (const e of out.flagged_entries) console.log(`    - ${e.address} (${e.entity_name})`);
}

main().catch((e) => { console.error(e); process.exit(1); });
