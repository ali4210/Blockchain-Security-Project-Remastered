import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

export interface GovernanceMapping {
  mitreAttack: {
    techniqueId: string;
    techniqueName: string;
    tactic: string;
  };
  cisControls: {
    controlId: string;
    controlName: string;
    assetType: string;
  };
  iso27001: {
    controlId: string;
    title: string;
  };
  cset: {
    category: string;
    component: string;
  };
}

export interface EnrichedFinding {
  id: string;
  sourceTool: string;
  severity: string;
  title: string;
  description: string;
  target: string;
  dread?: Record<string, unknown>;
  governance: GovernanceMapping;
  rawDetails?: Record<string, unknown>;
}

export function mapFindingToGovernance(
  title: string,
  tool: string,
  description: string = ""
): GovernanceMapping {
  const normTool = tool.toLowerCase();
  const combined = `${title} ${description}`.toLowerCase();

  // 1. Host Governance / Lynis Baseline / System Hardening (Tool-first priority)
  if (
    normTool.includes("lynis") ||
    combined.includes("host_governance") ||
    combined.includes("hardening") ||
    combined.includes("sysctl") ||
    combined.includes("kernel")
  ) {
    return {
      mitreAttack: {
        techniqueId: "T1059.004",
        techniqueName: "Command and Scripting Interpreter: Unix Shell",
        tactic: "Execution",
      },
      cisControls: {
        controlId: "CIS-04.1",
        controlName: "Establish and Maintain a Secure Configuration Process",
        assetType: "Operating Systems",
      },
      iso27001: {
        controlId: "A.8.9",
        title: "Configuration Management",
      },
      cset: {
        category: "System Configuration",
        component: "Baseline Hardening & Host Compliance",
      },
    };
  }

  // 2. Arbitrary Send / Reentrancy / Fund Draining / Token Transfer Exploits
  if (
    combined.includes("arbitrary-send") ||
    combined.includes("reentrancy") ||
    combined.includes("drain") ||
    combined.includes("swc-107") ||
    combined.includes("swc-105")
  ) {
    return {
      mitreAttack: {
        techniqueId: "T1565.002",
        techniqueName: "Transmitted Data Manipulation",
        tactic: "Impact",
      },
      cisControls: {
        controlId: "CIS-16.1",
        controlName: "Establish and Maintain a Secure Application Development Process",
        assetType: "Applications",
      },
      iso27001: {
        controlId: "A.8.28",
        title: "Secure Coding",
      },
      cset: {
        category: "Software Development",
        component: "Application Security & State Guardrails",
      },
    };
  }

  // 3. Front-running / MEV / Transaction Ordering / Price Manipulation
  if (
    combined.includes("front-run") ||
    combined.includes("sandwich") ||
    combined.includes("mempool") ||
    combined.includes("oracle") ||
    combined.includes("slippage")
  ) {
    return {
      mitreAttack: {
        techniqueId: "T1499.004",
        techniqueName: "Application Exhaustion / Manipulation",
        tactic: "Impact",
      },
      cisControls: {
        controlId: "CIS-16.11",
        controlName: "Leverage Vetted Libraries or Software Components",
        assetType: "Applications",
      },
      iso27001: {
        controlId: "A.8.26",
        title: "Application Security Requirements",
      },
      cset: {
        category: "Financial System Integrity",
        component: "Transaction Sequencing & Market Feeds",
      },
    };
  }

  // 4. Access Control / Authorization / Ownership Bypass
  if (
    combined.includes("access") ||
    combined.includes("owner") ||
    combined.includes("auth") ||
    combined.includes("privilege") ||
    combined.includes("unprotected")
  ) {
    return {
      mitreAttack: {
        techniqueId: "T1078.004",
        techniqueName: "Valid Accounts: Cloud Accounts",
        tactic: "Privilege Escalation",
      },
      cisControls: {
        controlId: "CIS-06.1",
        controlName: "Establish an Access Granting Process",
        assetType: "Identities",
      },
      iso27001: {
        controlId: "A.8.3",
        title: "Information Access Restriction",
      },
      cset: {
        category: "Access Control",
        component: "Identity & Entitlement Verification",
      },
    };
  }

  // 5. Default Fallback Baseline Mapping
  return {
    mitreAttack: {
      techniqueId: "T1190",
      techniqueName: "Exploit Public-Facing Application",
      tactic: "Initial Access",
    },
    cisControls: {
      controlId: "CIS-16.1",
      controlName: "Establish and Maintain a Secure Application Development Process",
      assetType: "Applications",
    },
    iso27001: {
      controlId: "A.8.25",
      title: "Secure Development Lifecycle",
    },
    cset: {
      category: "General Security Assessment",
      component: "Vulnerability Management Baseline",
    },
  };
}

export function enrichFindings(normalized: unknown[]): EnrichedFinding[] {
  if (!Array.isArray(normalized)) {
    return [];
  }

  const enriched: EnrichedFinding[] = [];

  for (const item of normalized) {
    if (!item || typeof item !== "object") continue;

    const record = item as Record<string, unknown>;
    const id = String(record.id || "FINDING-GENERIC");
    const tool = String(record.sourceTool || record.tool || "generic");
    const severity = String(record.severity || "MEDIUM");
    const title = String(record.title || record.check || "Security Finding");
    const description = String(record.description || record.detail || "");
    const target = String(record.target || "unknown");

    const governance = mapFindingToGovernance(title, tool, description);

    enriched.push({
      id,
      sourceTool: tool,
      severity,
      title,
      description,
      target,
      ...(record.dread ? { dread: record.dread as Record<string, unknown> } : {}),
      governance,
      ...(record.rawDetails ? { rawDetails: record.rawDetails as Record<string, unknown> } : {}),
    });
  }

  return enriched;
}

// CLI entry point
if (import.meta.url.endsWith(process.argv[1] || "")) {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    console.log("Usage: tsx scripts/enrich-findings.mts [--input <file>] [--output <file>]");
    console.log("Enriches normalized findings with MITRE ATT&CK, CIS Controls, ISO 27001, and CSET mappings.");
    process.exit(0);
  }

  const inputIdx = args.indexOf("--input");
  const outputIdx = args.indexOf("--output");

  if (inputIdx !== -1 && args[inputIdx + 1]) {
    const inputPath = resolve(args[inputIdx + 1]);
    const rawContent = JSON.parse(readFileSync(inputPath, "utf-8"));
    const findings = Array.isArray(rawContent) ? rawContent : rawContent.findings || [];
    const result = enrichFindings(findings);

    if (outputIdx !== -1 && args[outputIdx + 1]) {
      const outputPath = resolve(args[outputIdx + 1]);
      writeFileSync(outputPath, JSON.stringify(result, null, 2), "utf-8");
      console.log(`Enriched ${result.length} findings to ${outputPath}`);
    } else {
      console.log(JSON.stringify(result, null, 2));
    }
  }
}
