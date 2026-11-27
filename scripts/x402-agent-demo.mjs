#!/usr/bin/env node
/**
 * AEGIS Autonomous Pentest Agent CLI & CI Gate (x402 V2 + SPL Memo + SARIF 2.1.0)
 *
 * Usage:
 *   node scripts/x402-agent-demo.mjs [API_URL] [KEYPAIR_PATH]
 *   node scripts/x402-agent-demo.mjs https://.../api/x402/scan \
 *     --target programs/aegis402/src/lib.rs \
 *     --keypair ~/.config/solana/id.json \
 *     --sarif aegis-report.sarif \
 *     --fail-on-critical
 */

import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";
import { createRequire } from "module";

const require = createRequire(new URL("../app/package.json", import.meta.url));
const {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} = require("@solana/web3.js");

function parseArgs(argv) {
  const args = argv.slice(2);
  let apiUrl = "http://localhost:3000/api/x402/scan";
  let keypairPath = path.join(os.homedir(), ".config", "solana", "id.json");
  let targetFile = null;
  let sarifOut = null;
  let failOnCritical = false;

  const positional = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--target" && args[i + 1]) {
      targetFile = args[++i];
    } else if (a === "--keypair" && args[i + 1]) {
      keypairPath = args[++i];
    } else if (a === "--sarif" && args[i + 1]) {
      sarifOut = args[++i];
    } else if (a === "--fail-on-critical") {
      failOnCritical = true;
    } else if (!a.startsWith("--")) {
      positional.push(a);
    }
  }
  if (positional[0]) apiUrl = positional[0];
  if (positional[1]) keypairPath = positional[1];

  return { apiUrl, keypairPath, targetFile, sarifOut, failOnCritical };
}

const RPC_URL = process.env.SOLANA_RPC_URL || "https://api.devnet.solana.com";
const SPL_MEMO_PROGRAM_ID = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

const SAMPLE_VULNERABLE_CODE = `
use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;

#[program]
pub mod sample_target {
    use super::*;
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        ctx.accounts.vault.balance = ctx.accounts.vault.balance - amount;
        let _now = Clock::get().unwrap();
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub authority: AccountInfo<'info>,
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}
`;

function mapSarifLevel(sev) {
  if (sev === "CRITICAL" || sev === "HIGH") return "error";
  if (sev === "MEDIUM") return "warning";
  return "note";
}

function toSarif(report) {
  const findings = report.findings || [];
  const seenRules = new Map();

  for (const f of findings) {
    if (!seenRules.has(f.ruleId)) {
      const cvssStr = Number(f.cvss || 0).toFixed(1);
      seenRules.set(f.ruleId, {
        id: f.ruleId,
        name: f.title,
        shortDescription: { text: f.title },
        fullDescription: { text: f.description || f.title },
        help: {
          text: f.remediation || f.exploitScenario || f.title,
          markdown: `### ${f.title}\n\n**Category:** ${f.sealevelCategory || "Solana Security"} (${f.cwe || "CWE"})\n\n**Exploit Scenario:** ${f.exploitScenario || ""}\n\n**Recommended Patch:** ${f.remediation || ""}\n\n\`\`\`diff\n${f.diffBefore || ""}\n${f.diffAfter || ""}\n\`\`\``,
        },
        properties: {
          tags: ["security", "solana", "anchor", String(f.severity || "medium").toLowerCase()],
          "security-severity": cvssStr,
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
            version: report.scannerVersion || "3.0.0",
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
        results: findings.map((f) => {
          const uri = f.filePath || "programs/target/src/lib.rs";
          const startLine = Math.max(1, f.line || 1);
          const primaryLocationLineHash = crypto
            .createHash("sha256")
            .update(`${f.ruleId}:${uri}:${startLine}`, "utf-8")
            .digest("hex")
            .slice(0, 32);

          return {
            ruleId: f.ruleId,
            level: mapSarifLevel(f.severity),
            message: {
              text: `[${f.severity} · CVSS ${Number(f.cvss || 0).toFixed(1)}] ${f.title}: ${f.exploitScenario}`,
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri },
                  region: {
                    startLine,
                    snippet: { text: f.snippet || "" },
                  },
                },
              },
            ],
            fingerprints: {
              aegisFindingId: f.id,
            },
            partialFingerprints: {
              primaryLocationLineHash,
            },
          };
        }),
      },
    ],
  };
}

async function main() {
  const opts = parseArgs(process.argv);

  let codeToScan = SAMPLE_VULNERABLE_CODE;
  let targetName = "Autonomous Agent Target Vault";
  let targetProgramId = "8AaU3VSHXHyKcVTe9JCA67oRR5djpjfAUgcM1cCtpe7p";

  if (opts.targetFile) {
    if (!fs.existsSync(opts.targetFile)) {
      console.error(`Target Rust file not found: ${opts.targetFile}`);
      process.exit(1);
    }
    const raw = fs.readFileSync(opts.targetFile, "utf-8");
    codeToScan = `// === AEGIS_FILE: ${opts.targetFile} ===\n${raw}`;
    targetName = path.basename(opts.targetFile);
    const idMatch = raw.match(/declare_id!\s*\(\s*"([1-9A-HJ-NP-Za-km-z]{32,44})"\s*\)/);
    if (idMatch) targetProgramId = idMatch[1];
  }

  console.log("=================================================================");
  console.log("  AEGIS AUTONOMOUS PENTEST AGENT — x402 V2 + SPL MEMO SOLANA");
  console.log("=================================================================\n");

  console.log(`[1/5] Probing protected endpoint: POST ${opts.apiUrl}`);
  const probeRes = await fetch(opts.apiUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ targetName, targetProgramId, code: codeToScan }),
  });

  if (probeRes.status !== 402) {
    console.error(`Expected HTTP 402 Payment Required, got ${probeRes.status}`);
    process.exit(1);
  }

  const paymentRequired = JSON.parse(
    Buffer.from(probeRes.headers.get("payment-required"), "base64").toString("utf-8")
  );
  const reqOption = paymentRequired.accepts[0];
  console.log(`[2/5] HTTP 402 Payment Required (x402Version=${paymentRequired.x402Version})`);
  console.log(`      Network      : ${reqOption.network}`);
  console.log(`      PayTo        : ${reqOption.payTo}`);
  console.log(`      Amount       : ${reqOption.amount} lamports (0.001 SOL)`);
  console.log(`      Memo Binding : ${reqOption.extra.memoRequired}\n`);

  if (!fs.existsSync(opts.keypairPath)) {
    console.error(`Keypair not found at ${opts.keypairPath}.`);
    process.exit(1);
  }
  const secretKey = Uint8Array.from(JSON.parse(fs.readFileSync(opts.keypairPath, "utf-8")));
  const agentWallet = Keypair.fromSecretKey(secretKey);
  const connection = new Connection(RPC_URL, "confirmed");

  console.log(`[3/5] Signing 0.001 SOL + SPL Memo("${reqOption.extra.memoRequired}") on Devnet...`);
  const tx = new Transaction()
    .add(
      SystemProgram.transfer({
        fromPubkey: agentWallet.publicKey,
        toPubkey: new PublicKey(reqOption.payTo),
        lamports: Number(reqOption.amount),
      })
    )
    .add(
      new TransactionInstruction({
        programId: SPL_MEMO_PROGRAM_ID,
        keys: [{ pubkey: agentWallet.publicKey, isSigner: true, isWritable: false }],
        data: Buffer.from(reqOption.extra.memoRequired, "utf-8"),
      })
    );

  const signature = await sendAndConfirmTransaction(connection, tx, [agentWallet], {
    commitment: "confirmed",
  });
  console.log(`      Confirmed TX : https://explorer.solana.com/tx/${signature}?cluster=devnet\n`);

  const paymentSignatureB64 = Buffer.from(
    JSON.stringify({
      x402Version: 2,
      resource: paymentRequired.resource,
      accepted: reqOption,
      payload: { signature, account: agentWallet.publicKey.toBase58() },
    }),
    "utf-8"
  ).toString("base64");

  console.log(`[4/5] Retrying POST ${opts.apiUrl} with PAYMENT-SIGNATURE header...`);
  const paidRes = await fetch(opts.apiUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "PAYMENT-SIGNATURE": paymentSignatureB64,
    },
    body: JSON.stringify({ targetName, targetProgramId, code: codeToScan }),
  });

  if (!paidRes.ok) {
    console.error(`Paid retry failed (${paidRes.status}):`, await paidRes.text());
    process.exit(1);
  }

  const result = await paidRes.json();
  console.log(`[5/5] HTTP 200 OK! PAYMENT-RESPONSE=${Boolean(paidRes.headers.get("payment-response"))}`);
  console.log(`      Ed25519 Oracle Proof : ${Boolean(result.oracleAttestation)}`);
  console.log(`      Security Score       : ${result.report.securityScore}/100 (Grade ${result.report.riskGrade})`);
  console.log(`      Source Code SHA-256  : ${result.report.sourceCodeSha256}`);
  console.log(`      Findings             : ${result.report.summary.total}\n`);
  for (const f of result.report.findings) {
    console.log(`      - [${f.severity} | CVSS ${f.cvss}] ${f.ruleId} (${f.filePath}:${f.line}): ${f.title}`);
  }

  if (opts.sarifOut) {
    fs.writeFileSync(opts.sarifOut, JSON.stringify(toSarif(result.report), null, 2), "utf-8");
    console.log(`\n      Wrote SARIF 2.1.0 report to ${opts.sarifOut}`);
  }

  if (opts.failOnCritical && (result.report.summary?.critical || 0) > 0) {
    console.error(`\n[CI GATE FAILED] ${result.report.summary.critical} CRITICAL finding(s) detected.`);
    process.exit(2);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
