import type { ScanReport, Severity } from "./solanaRules";

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

/** Browser- and Node-safe synchronous SHA-256 hex digest for SARIF alert deduplication. */
function sha256HexSync(input: string): string {
  const bytes = new TextEncoder().encode(input);
  const bitLen = bytes.length * 8;
  const paddedLen = Math.ceil((bytes.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLen);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(paddedLen - 4, bitLen >>> 0, false);

  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const w = new Uint32Array(64);

  for (let offset = 0; offset < paddedLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (hh + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      hh = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0;
    h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0;
    h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0;
    h[7] = (h[7] + hh) >>> 0;
  }

  return Array.from(h, (v) => v.toString(16).padStart(8, "0")).join("");
}

function mapSarifLevel(sev: Severity): "error" | "warning" | "note" {
  if (sev === "CRITICAL" || sev === "HIGH") return "error";
  if (sev === "MEDIUM") return "warning";
  return "note";
}

/**
 * Generates an OASIS SARIF 2.1.0 compliant security report directly compatible
 * with GitHub Code Scanning (`github/codeql-action/upload-sarif@v3`).
 */
export function buildSarifReport(report: ScanReport) {
  const seenRules = new Map<string, {
    id: string;
    name: string;
    shortDescription: { text: string };
    fullDescription: { text: string };
    help: { text: string; markdown: string };
    properties: { tags: string[]; "security-severity": string };
  }>();

  for (const f of report.findings) {
    if (!seenRules.has(f.ruleId)) {
      seenRules.set(f.ruleId, {
        id: f.ruleId,
        name: f.title,
        shortDescription: { text: f.title },
        fullDescription: { text: f.description },
        help: {
          text: f.remediation,
          markdown: `### ${f.title}\n\n**Category:** ${f.sealevelCategory} (${f.cwe})\n\n**Exploit Scenario:** ${f.exploitScenario}\n\n**Recommended Patch:** ${f.remediation}\n\n\`\`\`diff\n${f.diffBefore}\n${f.diffAfter}\n\`\`\``,
        },
        properties: {
          tags: ["security", "solana", "anchor", f.severity.toLowerCase()],
          "security-severity": f.cvss.toFixed(1),
        },
      });
    }
  }

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "AEGIS SolSec Engine",
            version: report.scannerVersion,
            informationUri: "https://github.com/letox4/aegis-solana",
            rules: Array.from(seenRules.values()),
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: report.scannedAt,
            properties: {
              targetName: report.targetName,
              targetProgramId: report.targetProgramId || null,
              securityScore: report.securityScore,
              riskGrade: report.riskGrade,
              sourceCodeSha256: report.sourceCodeSha256,
              reportHashHex: report.reportHashHex,
            },
          },
        ],
        results: report.findings.map((f) => {
          const uri = f.filePath || "programs/target/src/lib.rs";
          const startLine = Math.max(1, f.line);
          return {
            ruleId: f.ruleId,
            level: mapSarifLevel(f.severity),
            message: {
              text: `[${f.severity} · CVSS ${f.cvss.toFixed(1)}] ${f.title}: ${f.exploitScenario}`,
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri,
                  },
                  region: {
                    startLine,
                    snippet: { text: f.snippet },
                  },
                },
              },
            ],
            fingerprints: {
              aegisFindingId: f.id,
            },
            partialFingerprints: {
              primaryLocationLineHash: sha256HexSync(
                `${f.ruleId}:${uri}:${startLine}`
              ).slice(0, 32),
            },
          };
        }),
      },
    ],
  };
}
