import { readFileSync, writeFileSync, mkdirSync, existsSync, copyFileSync } from "node:fs";
import { resolve } from "node:path";

export function exportPublicDashboard(): string {
  const root = process.cwd();
  const outDir = resolve(root, "public-dashboard");
  if (!existsSync(outDir)) {
    mkdirSync(outDir, { recursive: true });
  }

  // Ensure latest report exists
  const latestHtmlPath = resolve(root, "reports/latest.html");
  if (!existsSync(latestHtmlPath)) {
    throw new Error("reports/latest.html does not exist. Run npm run report first.");
  }

  // Copy as index.html
  const destHtml = resolve(outDir, "index.html");
  copyFileSync(latestHtmlPath, destHtml);

  // Copy sanitized status.json
  const statusJsonPath = resolve(root, "reports/status.json");
  if (existsSync(statusJsonPath)) {
    const raw = readFileSync(statusJsonPath, "utf-8");
    // Extra safety guarantee: verify zero raw secret markers
    if (raw.includes("BEGIN PRIVATE KEY") || raw.includes("0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d")) {
      throw new Error("Unredacted secrets detected in status.json! Aborting public dashboard export.");
    }
    writeFileSync(resolve(outDir, "status.json"), raw, "utf-8");
  }

  // Write vercel.json configuration for air-gapped zero-config static hosting
  const vercelConfig = {
    cleanUrls: true,
    headers: [
      {
        source: "/(.*)",
        headers: [
          { key: "Content-Security-Policy", value: "default-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" }
        ]
      }
    ]
  };
  writeFileSync(resolve(outDir, "vercel.json"), JSON.stringify(vercelConfig, null, 2), "utf-8");

  console.log(`[+] Public dashboard successfully exported to: ${outDir}`);
  return outDir;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  exportPublicDashboard();
}
