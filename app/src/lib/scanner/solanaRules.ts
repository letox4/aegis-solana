import crypto from "crypto";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface SecurityFinding {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  cvss: number;
  cwe: string;
  sealevelCategory: string;
  filePath: string;
  line: number;
  snippet: string;
  description: string;
  exploitScenario: string;
  remediation: string;
  diffBefore: string;
  diffAfter: string;
  exploitPocTs: string;
}

export interface ScannedFileSummary {
  path: string;
  lines: number;
  findings: number;
}

export interface InstructionAttackNode {
  instruction: string;
  filePath: string;
  line: number;
  contextStruct: string;
  signers: string[];
  mutableAccounts: string[];
  uncheckedAccounts: string[];
  cpiTargets: string[];
  riskLevel: "CRITICAL" | "HIGH" | "SAFE";
}

export interface ScanReport {
  scanId: string;
  scannedAt: string;
  targetName: string;
  targetProgramId?: string;
  linesAnalyzed: number;
  filesScanned: ScannedFileSummary[];
  attackSurface: InstructionAttackNode[];
  securityScore: number;
  riskGrade: "A+" | "A" | "B" | "C" | "D" | "F";
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  sourceCodeSha256: string;
  reportHashHex: string;
  findings: SecurityFinding[];
  scannerVersion: string;
}

export const MAX_SCAN_CODE_BYTES = 100_000;
export const MULTI_FILE_MARKER_PREFIX = "// === AEGIS_FILE: ";
export const MULTI_FILE_MARKER_SUFFIX = " ===";

interface ParsedAccountsStruct {
  name: string;
  startLine: number;
  body: string;
  fields: Array<{
    name: string;
    typeStr: string;
    attrs: string;
    line: number;
    isMut: boolean;
  }>;
}

interface ParsedInstructionHandler {
  name: string;
  contextStructName: string;
  startLine: number;
  endLine: number;
  bodyLines: string[];
  cpiCalls: Array<{ kind: string; line: number; snippet: string }>;
}

interface RawMatch {
  line: number;
  snippet: string;
  contextName?: string;
  fieldName?: string;
}

export function splitMultiFilePayload(
  sourceCode: string,
  defaultPath = "programs/target/src/lib.rs"
): Array<{ path: string; content: string }> {
  const lines = sourceCode.split(/\r?\n/);
  const files: Array<{ path: string; lines: string[] }> = [];
  let current: { path: string; lines: string[] } | null = null;

  for (const line of lines) {
    if (line.startsWith(MULTI_FILE_MARKER_PREFIX) && line.endsWith(MULTI_FILE_MARKER_SUFFIX)) {
      const path = line
        .slice(MULTI_FILE_MARKER_PREFIX.length, -MULTI_FILE_MARKER_SUFFIX.length)
        .trim();
      current = { path: path || defaultPath, lines: [] };
      files.push(current);
    } else if (current) {
      current.lines.push(line);
    }
  }

  if (files.length === 0) {
    return [{ path: defaultPath, content: sourceCode }];
  }

  return files.map((f) => ({ path: f.path, content: f.lines.join("\n") }));
}

export function sanitizeRustPreservingLines(source: string): string {
  let out = "";
  let i = 0;
  let inLineComment = false;
  let inBlockComment = false;
  let inString = false;

  while (i < source.length) {
    const ch = source[i];
    const next = source[i + 1];

    if (inLineComment) {
      if (ch === "\n") {
        inLineComment = false;
        out += "\n";
      } else {
        out += ch;
      }
      i++;
      continue;
    }

    if (inBlockComment) {
      if (ch === "*" && next === "/") {
        inBlockComment = false;
        out += "  ";
        i += 2;
      } else {
        out += ch === "\n" ? "\n" : " ";
        i++;
      }
      continue;
    }

    if (inString) {
      out += ch;
      if (ch === "\\" && i + 1 < source.length) {
        out += source[i + 1];
        i += 2;
        continue;
      }
      if (ch === '"') inString = false;
      i++;
      continue;
    }

    if (ch === "'") {
      const charSlice = source.slice(i, i + 16);
      const charMatch = charSlice.match(
        /^'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,6}\}|.)|[^'\\\r\n])'/
      );
      if (charMatch) {
        out += charMatch[0];
        i += charMatch[0].length;
        continue;
      }
      out += ch;
      i++;
    } else if (ch === '"') {
      inString = true;
      out += ch;
      i++;
    } else if (ch === "/" && next === "/") {
      inLineComment = true;
      out += "//";
      i += 2;
    } else if (ch === "/" && next === "*") {
      inBlockComment = true;
      out += "  ";
      i += 2;
    } else {
      out += ch;
      i++;
    }
  }

  let searchPos = 0;
  while (true) {
    const cfgIdx = out.indexOf("#[cfg(test)]", searchPos);
    if (cfgIdx === -1) break;
    const openBrace = out.indexOf("{", cfgIdx);
    const semiIdx = out.indexOf(";", cfgIdx);
    if (semiIdx !== -1 && (openBrace === -1 || semiIdx < openBrace)) {
      searchPos = semiIdx + 1;
      continue;
    }
    if (openBrace === -1) break;
    let depth = 0;
    let end = openBrace;
    for (let j = openBrace; j < out.length; j++) {
      if (out[j] === "{") depth++;
      else if (out[j] === "}") {
        depth--;
        if (depth === 0) {
          end = j;
          break;
        }
      }
    }
    const blanked = out.slice(cfgIdx, end + 1).replace(/[^\n]/g, " ");
    out = out.slice(0, cfgIdx) + blanked + out.slice(end + 1);
    searchPos = end + 1;
  }

  return out;
}

function extractAccountStructs(cleanCode: string): ParsedAccountsStruct[] {
  const results: ParsedAccountsStruct[] = [];
  const marker = "#[derive(Accounts)]";
  let searchFrom = 0;

  while (true) {
    const idx = cleanCode.indexOf(marker, searchFrom);
    if (idx === -1) break;

    const structPos = cleanCode.indexOf("struct ", idx);
    if (structPos === -1 || structPos - idx > 400) {
      searchFrom = idx + marker.length;
      continue;
    }

    const openBrace = cleanCode.indexOf("{", structPos);
    if (openBrace === -1) break;

    let depth = 0;
    let closeBrace = -1;
    for (let j = openBrace; j < cleanCode.length; j++) {
      if (cleanCode[j] === "{") depth++;
      else if (cleanCode[j] === "}") {
        depth--;
        if (depth === 0) {
          closeBrace = j;
          break;
        }
      }
    }
    if (closeBrace === -1) break;

    const headerSlice = cleanCode.slice(structPos + 7, openBrace);
    const nameMatch = headerSlice.match(/^([A-Za-z0-9_]+)/);
    const name = nameMatch ? nameMatch[1] : "UnknownAccounts";
    const startLine = cleanCode.slice(0, structPos).split("\n").length;
    const body = cleanCode.slice(openBrace + 1, closeBrace);
    const bodyStartLine = cleanCode.slice(0, openBrace + 1).split("\n").length;

    const fields: ParsedAccountsStruct["fields"] = [];
    const bodyLines = body.split("\n");
    let pendingAttrs: string[] = [];
    let pendingFieldBuf = "";
    let pendingFieldLine = bodyStartLine;

    for (let li = 0; li < bodyLines.length; li++) {
      const rawLine = bodyLines[li];
      const trimmed = rawLine.trim();
      const absLine = bodyStartLine + li;

      if (!trimmed) continue;
      if (
        trimmed.startsWith("///") ||
        trimmed.startsWith("#[") ||
        (pendingAttrs.length > 0 && !trimmed.startsWith("pub ") && !pendingFieldBuf)
      ) {
        pendingAttrs.push(trimmed);
        continue;
      }

      if (trimmed.startsWith("pub ")) {
        pendingFieldBuf = trimmed;
        pendingFieldLine = absLine;
      } else if (pendingFieldBuf) {
        pendingFieldBuf += " " + trimmed;
      }

      if (pendingFieldBuf && pendingFieldBuf.includes(",")) {
        const cleanField = pendingFieldBuf.replace(/,\s*$/, "");
        const colonIdx = cleanField.indexOf(":");
        if (colonIdx !== -1) {
          const fname = cleanField.slice(4, colonIdx).trim();
          const ftype = cleanField.slice(colonIdx + 1).trim();
          const attrs = pendingAttrs.join("\n");
          const isMut = /\bmut\b/.test(attrs);
          fields.push({ name: fname, typeStr: ftype, attrs, line: pendingFieldLine, isMut });
        }
        pendingAttrs = [];
        pendingFieldBuf = "";
      }
    }

    results.push({ name, startLine, body, fields });
    searchFrom = closeBrace + 1;
  }

  return results;
}

/**
 * Inter-Procedural O(n) brace-balanced extractor for Anchor instruction handlers:
 * `pub fn <ix>(ctx: Context<<StructName>>, ...) -> Result<()>`
 * Maps every instruction to its `#[derive(Accounts)]` struct and extracts outbound CPIs.
 */
function extractInstructionHandlers(cleanCode: string): ParsedInstructionHandler[] {
  const handlers: ParsedInstructionHandler[] = [];
  let searchFrom = 0;

  while (true) {
    const pubFnIdx = cleanCode.indexOf("pub fn ", searchFrom);
    if (pubFnIdx === -1) break;

    const openParen = cleanCode.indexOf("(", pubFnIdx);
    if (openParen === -1 || openParen - pubFnIdx > 80) {
      searchFrom = pubFnIdx + 7;
      continue;
    }

    const fnName = cleanCode.slice(pubFnIdx + 7, openParen).trim();
    if (!/^[a-zA-Z0-9_]+$/.test(fnName)) {
      searchFrom = openParen + 1;
      continue;
    }

    // Find matching closing parenthesis for signature
    let pDepth = 0;
    let closeParen = -1;
    for (let j = openParen; j < cleanCode.length && j < openParen + 600; j++) {
      if (cleanCode[j] === "(") pDepth++;
      else if (cleanCode[j] === ")") {
        pDepth--;
        if (pDepth === 0) {
          closeParen = j;
          break;
        }
      }
    }
    if (closeParen === -1) {
      searchFrom = openParen + 1;
      continue;
    }

    const sigParams = cleanCode.slice(openParen + 1, closeParen);
    const ctxMatch = sigParams.match(/Context\s*<\s*(?:['a-z_]+\s*,\s*)*([A-Z][A-Za-z0-9_]*)\s*>/);
    if (!ctxMatch) {
      searchFrom = closeParen + 1;
      continue;
    }
    const contextStructName = ctxMatch[1];

    const bodyBrace = cleanCode.indexOf("{", closeParen);
    if (bodyBrace === -1 || bodyBrace - closeParen > 120) {
      searchFrom = closeParen + 1;
      continue;
    }

    let bDepth = 0;
    let closeBrace = -1;
    for (let j = bodyBrace; j < cleanCode.length; j++) {
      if (cleanCode[j] === "{") bDepth++;
      else if (cleanCode[j] === "}") {
        bDepth--;
        if (bDepth === 0) {
          closeBrace = j;
          break;
        }
      }
    }
    if (closeBrace === -1) break;

    const startLine = cleanCode.slice(0, pubFnIdx).split("\n").length;
    const bodyStartLine = cleanCode.slice(0, bodyBrace + 1).split("\n").length;
    const bodyText = cleanCode.slice(bodyBrace + 1, closeBrace);
    const bodyLines = bodyText.split("\n");
    const endLine = bodyStartLine + bodyLines.length;

    const cpiCalls: ParsedInstructionHandler["cpiCalls"] = [];
    const cpiPatterns: Array<{ kind: string; re: RegExp }> = [
      { kind: "system_program::transfer", re: /\bsystem_program::transfer\s*\(/ },
      { kind: "token_2022 / interface CPI", re: /\b(?:token_2022|token_interface)::(?:transfer_checked|transfer|mint_to|burn)\s*\(/ },
      { kind: "token::transfer / mint / burn", re: /\btoken::(?:transfer_checked|transfer|mint_to|burn|close_account)\s*\(/ },
      { kind: "raw invoke_signed()", re: /\binvoke_signed\s*\(/ },
      { kind: "raw invoke()", re: /\binvoke\s*\(/ },
    ];

    bodyLines.forEach((rawLn, idx) => {
      const codeLn = rawLn.replace(/\/\/.*$/, "").trim();
      if (!codeLn) return;
      for (const pat of cpiPatterns) {
        if (pat.re.test(codeLn)) {
          cpiCalls.push({
            kind: pat.kind,
            line: bodyStartLine + idx,
            snippet: codeLn.slice(0, 120),
          });
          break;
        }
      }
    });

    handlers.push({
      name: fnName,
      contextStructName,
      startLine,
      endLine,
      bodyLines,
      cpiCalls,
    });

    searchFrom = closeBrace + 1;
  }

  return handlers;
}

interface RuleDefinition {
  ruleId: string;
  title: string;
  severity: Severity;
  cvss: number;
  cwe: string;
  sealevelCategory: string;
  description: string;
  exploitScenario: string;
  remediation: string;
  buildDiff: (m: RawMatch) => { before: string; after: string };
  buildPoc: (m: RawMatch, targetProgramId?: string) => string;
  detect: (
    cleanCode: string,
    lines: string[],
    structs: ParsedAccountsStruct[],
    handlers: ParsedInstructionHandler[]
  ) => RawMatch[];
}

function getLocalFunctionWindow(
  lines: string[],
  idx: number,
  before: number,
  after: number
): string {
  const fnStartRe = /^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+/;
  let start = Math.max(0, idx - before);
  for (let j = idx; j >= start; j--) {
    if (j < idx && fnStartRe.test(lines[j])) {
      start = j;
      break;
    }
  }
  let end = Math.min(lines.length, idx + after + 1);
  for (let j = idx + 1; j < end; j++) {
    if (fnStartRe.test(lines[j])) {
      end = j;
      break;
    }
  }
  return lines
    .slice(start, end)
    .map((l) => l.replace(/\/\/.*$/, "").trim())
    .filter(Boolean)
    .join("\n");
}

function findLineMatches(
  lines: string[],
  regex: RegExp,
  filter?: (line: string, idx: number, all: string[]) => boolean
): RawMatch[] {
  const hits: RawMatch[] = [];
  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("///")) return;
    if (regex.test(line)) {
      if (!filter || filter(line, idx, lines)) {
        hits.push({ line: idx + 1, snippet: trimmed.slice(0, 140) });
      }
    }
  });
  return hits;
}

const RULES: RuleDefinition[] = [
  {
    ruleId: "AEGIS-SOL-001",
    title: "Missing Signer Check on Privileged Authority Account",
    severity: "CRITICAL",
    cvss: 9.8,
    cwe: "CWE-287: Improper Authentication",
    sealevelCategory: "Sealevel Attack #1: Signer Authorization",
    description:
      "A privileged authority/admin/manager/owner account inside `#[derive(Accounts)]` is typed as `AccountInfo` or `UncheckedAccount` instead of `Signer<'info>`, allowing any caller to pass an arbitrary pubkey without signing.",
    exploitScenario:
      "An attacker crafts a transaction passing the protocol admin's public key in the privileged account slot without holding the private key, bypassing authorization and draining vault funds.",
    remediation:
      "Replace `AccountInfo<'info>` / `UncheckedAccount<'info>` with `pub authority: Signer<'info>` and pair it with `has_one = authority` on the protected state account.",
    buildDiff: (m) => ({
      before: `- pub ${m.fieldName || "authority"}: AccountInfo<'info>, // Missing signer check`,
      after: `+ #[account(has_one = ${m.fieldName || "authority"} @ ErrorCode::Unauthorized)]\n+ pub ${m.fieldName || "authority"}: Signer<'info>,`,
    }),
    buildPoc: (m, pid) => `// Anchor Exploit PoC — ${m.contextName || "PrivilegedInstruction"} (AEGIS-SOL-001)
const attacker = anchor.web3.Keypair.generate();
await program.methods
  .withdraw(new anchor.BN(1_000_000_000))
  .accounts({
    vault: victimVaultPda,
    ${m.fieldName || "authority"}: victimAdminPubkey, // <-- Passed WITHOUT signing!
    recipient: attacker.publicKey,
  })
  .signers([attacker])
  .rpc(); // Target: ${pid || "PROGRAM_ID"}`,
    detect: (_code, _lines, structs) => {
      const hits: RawMatch[] = [];
      for (const st of structs) {
        for (const f of st.fields) {
          const isPrivName =
            /(authority|admin|owner|manager|governance|operator|signer|treasury_owner)/i.test(
              f.name
            );
          const isUncheckedType = /\b(AccountInfo|UncheckedAccount)\s*</.test(f.typeStr);
          if (isPrivName && isUncheckedType && !f.attrs.includes("is_signer")) {
            hits.push({
              line: f.line,
              snippet: `pub ${f.name}: ${f.typeStr} (in struct ${st.name})`,
              contextName: st.name,
              fieldName: f.name,
            });
          }
        }
      }
      return hits;
    },
  },
  {
    ruleId: "AEGIS-SOL-002",
    title: "Unchecked AccountInfo Without Safety Verification or Owner Constraint",
    severity: "CRITICAL",
    cvss: 9.1,
    cwe: "CWE-345: Insufficient Verification of Data Authenticity",
    sealevelCategory: "Sealevel Attack #2: Account Data Matching / Owner Checks",
    description:
      "Raw `AccountInfo<'info>` or `UncheckedAccount<'info>` is used inside `#[derive(Accounts)]` without an Anchor `address =`, `owner =`, or PDA `seeds =` constraint.",
    exploitScenario:
      "An attacker substitutes a forged account owned by a malicious program containing crafted state bytes that deserialize as a legitimate vault or configuration account.",
    remediation:
      "Use strongly-typed `Account<'info, T>`, `SystemAccount<'info>`, or `Program<'info, T>`. If raw `UncheckedAccount` is required (e.g. sysvar), enforce `#[account(address = ...)]` or `owner = ...` alongside `/// CHECK:`.",
    buildDiff: (m) => ({
      before: `- pub ${m.fieldName || "target_account"}: UncheckedAccount<'info>,`,
      after: `+ #[account(owner = crate::ID)] // Or typed Account<'info, VaultState>\n+ pub ${m.fieldName || "target_account"}: Account<'info, ExpectedState>,`,
    }),
    buildPoc: (m, pid) => `// Anchor Exploit PoC — Spoofed Account Owner (AEGIS-SOL-002)
const fakeAccount = anchor.web3.Keypair.generate();
await createForgedAccountWithAttackerAuthority(fakeAccount, attacker.publicKey);
await program.methods
  .execute()
  .accounts({ ${m.fieldName || "account"}: fakeAccount.publicKey })
  .signers([attacker])
  .rpc(); // Target: ${pid || "PROGRAM_ID"}`,
    detect: (_code, _lines, structs) => {
      const hits: RawMatch[] = [];
      for (const st of structs) {
        for (const f of st.fields) {
          if (!/\b(AccountInfo|UncheckedAccount)\s*</.test(f.typeStr)) continue;
          const hasHardConstraint =
            /\b(seeds|owner|address)\s*=/.test(f.attrs) ||
            /\/\/\/\s*CHECK:.*(seeds|owner|address|sysvar|verified|pda)/i.test(f.attrs);
          if (!hasHardConstraint) {
            hits.push({
              line: f.line,
              snippet: `pub ${f.name}: ${f.typeStr} (missing owner/address/seeds constraint)`,
              contextName: st.name,
              fieldName: f.name,
            });
          }
        }
      }
      return hits;
    },
  },
  {
    ruleId: "AEGIS-SOL-003",
    title: "Arbitrary CPI (Cross-Program Invocation) Target Risk",
    severity: "CRITICAL",
    cvss: 9.4,
    cwe: "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
    sealevelCategory: "Sealevel Attack #5: Arbitrary CPI",
    description:
      "Direct `invoke()` / `invoke_signed()` or `CpiContext::new()` targeting an unverified `AccountInfo`/`UncheckedAccount` program account detected without verifying the target `program_id`.",
    exploitScenario:
      "An attacker replaces the expected Token or System Program account with a malicious program that returns `Ok(())` without transferring funds, allowing unauthorized minting or withdrawals.",
    remediation:
      "Use Anchor's typed `Program<'info, System>` / `Program<'info, Token>` with `CpiContext::new`, or assert `require_keys_eq!(prog.key(), expected::ID)` before CPI.",
    buildDiff: (m) => ({
      before: `- ${m.snippet}`,
      after: `+ require_keys_eq!(cpi_program.key(), system_program::ID, ErrorCode::InvalidCpiProgram);\n+ // Better: type account as Program<'info, System> / Program<'info, Token>`,
    }),
    buildPoc: (m, pid) => `// Anchor Exploit PoC — Arbitrary CPI Hijack (AEGIS-SOL-003)
const noopMaliciousProgramId = new PublicKey("MaliciousNoopProg11111111111111111111111111");
await program.methods
  .depositOrSwap(new anchor.BN(10_000_000_000))
  .accounts({ ${m.fieldName || "tokenProgram"}: noopMaliciousProgramId })
  .signers([attacker])
  .rpc(); // Target: ${pid || "PROGRAM_ID"}`,
    detect: (_code, lines, structs) => {
      const uncheckedNames = new Set<string>();
      for (const st of structs) {
        for (const f of st.fields) {
          if (
            /\b(AccountInfo|UncheckedAccount)\s*</.test(f.typeStr) &&
            !/\baddress\s*=/.test(f.attrs)
          ) {
            uncheckedNames.add(f.name);
          }
        }
      }

      const hits: RawMatch[] = [];
      lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("//")) return;
        if (/\b(invoke|invoke_signed)\s*\(/.test(line)) {
          const nearbyCode = lines
            .slice(Math.max(0, idx - 12), idx + 2)
            .filter((l) => !l.trim().startsWith("//"))
            .join("\n");
          if (
            !/(require_keys_eq!|==\s*&?(system_program::ID|spl_token::ID|token::ID))/.test(
              nearbyCode
            )
          ) {
            hits.push({ line: idx + 1, snippet: trimmed.slice(0, 140) });
          }
        } else if (/CpiContext::(new|new_with_signer)\s*\(/.test(line)) {
          const nearby = lines.slice(idx, Math.min(lines.length, idx + 4)).join(" ");
          for (const uname of Array.from(uncheckedNames)) {
            if (new RegExp(`ctx\\.accounts\\.${uname}\\b`).test(nearby)) {
              hits.push({
                line: idx + 1,
                snippet: `CpiContext using unverified AccountInfo '${uname}'`,
                fieldName: uname,
              });
              break;
            }
          }
        }
      });
      return hits;
    },
  },
  {
    ruleId: "AEGIS-SOL-004",
    title: "Unchecked Arithmetic Operations on Financial Balances",
    severity: "HIGH",
    cvss: 8.2,
    cwe: "CWE-190: Integer Overflow or Wraparound",
    sealevelCategory: "Sealevel Attack #9: Integer Overflow / Underflow",
    description:
      "Direct arithmetic operators (`+=`, `-=`, `*=`, `+`, `-`, `*`) are used on lamports, balances, rewards, or amounts instead of `checked_add`, `checked_sub`, or `checked_mul`.",
    exploitScenario:
      "Without `overflow-checks = true`, an attacker triggers u64 underflow wrapping to `u64::MAX`, draining the entire protocol vault.",
    remediation:
      "Always use `.checked_add()`, `.checked_sub()`, `.checked_mul()`, and `.checked_div()` returning a custom Anchor error via `.ok_or(...)`, plus `overflow-checks = true` in `Cargo.toml`.",
    buildDiff: (m) => ({
      before: `- ${m.snippet}`,
      after: `+ vault.balance = vault.balance.checked_sub(amount).ok_or(ErrorCode::ArithmeticUnderflow)?;`,
    }),
    buildPoc: (_m, pid) => `// Anchor Exploit PoC — u64 Underflow Wraparound (AEGIS-SOL-004)
const maliciousAmount = new anchor.BN(vaultBalance).add(new anchor.BN(1));
await program.methods
  .withdraw(maliciousAmount)
  .accounts({ vault: vaultPda, user: attacker.publicKey })
  .signers([attacker])
  .rpc(); // Target: ${pid || "PROGRAM_ID"}`,
    detect: (_code, lines) =>
      findLineMatches(
        lines,
        /\b(amount|balance|lamports|reward|pool|supply|deposit|withdraw|shares|payout|fee)\w*\s*(\+=|-=|\*=|=\s*[\w.]+\s*[\+\-\*]\s*)/i,
        (line) => !line.includes("checked_") && !line.includes("saturating_") && !line.includes("const ")
      ),
  },
  {
    ruleId: "AEGIS-SOL-005",
    title: "Improper Account Closing (Account Revival / Resurrection Attack)",
    severity: "HIGH",
    cvss: 7.9,
    cwe: "CWE-672: Operation on a Resource after Expiration or Release",
    sealevelCategory: "Sealevel Attack #7: Closing Accounts",
    description:
      "Manual lamport draining (`borrow_mut_lamports()` set to 0) detected without clearing account data and setting `CLOSED_ACCOUNT_DISCRIMINATOR`.",
    exploitScenario:
      "An attacker bundles a follow-up instruction in the same transaction that refunds rent-exempt lamports to the drained account before GC, resurrecting stale state and replaying withdrawals.",
    remediation: "Use Anchor's declarative `#[account(mut, close = destination)]` constraint.",
    buildDiff: (m) => ({
      before: `- ${m.snippet}`,
      after: `+ #[account(mut, has_one = authority, close = authority)]\n+ pub state_account: Account<'info, StateAccount>,`,
    }),
    buildPoc: (_m, pid) => `// Anchor Exploit PoC — Same-TX Account Revival (AEGIS-SOL-005)
const tx = new Transaction()
  .add(await program.methods.closeAccount().accounts({ target: targetPda }).instruction())
  .add(SystemProgram.transfer({ fromPubkey: attacker.publicKey, toPubkey: targetPda, lamports: 2_000_000 }))
  .add(await program.methods.claimReward().accounts({ target: targetPda }).instruction());
await sendAndConfirmTransaction(connection, tx, [attacker]); // Target: ${pid || "PROGRAM_ID"}`,
    detect: (_code, lines) =>
      findLineMatches(lines, /borrow_mut_lamports\s*\(\)/, (_line, idx, all) => {
        const window = all.slice(Math.max(0, idx - 3), Math.min(all.length, idx + 8)).join("\n");
        return !window.includes("CLOSED_ACCOUNT_DISCRIMINATOR") && !window.includes("close =");
      }),
  },
  {
    ruleId: "AEGIS-SOL-006",
    title: "Non-Canonical PDA Bump / Unsafe `create_program_address`",
    severity: "HIGH",
    cvss: 7.8,
    cwe: "CWE-330: Use of Unvalidated Seed Parameters",
    sealevelCategory: "Sealevel Attack #8: Bump Seed Canonicalization",
    description:
      "`Pubkey::create_program_address` detected without validating against the canonical bump derived by `find_program_address` / Anchor `bump`.",
    exploitScenario:
      "An attacker supplies a secondary non-canonical bump to derive a shadow PDA, bypassing uniqueness guards or creating duplicate claim accounts.",
    remediation:
      "Use Anchor `seeds = [...]` with `bump` on init (storing `ctx.bumps.<acct>`) and `bump = acct.bump` thereafter.",
    buildDiff: (m) => ({
      before: `- ${m.snippet}`,
      after: `+ let (expected_pda, canonical_bump) = Pubkey::find_program_address(&[b"vault", key.as_ref()], ctx.program_id);\n+ require_eq!(supplied_bump, canonical_bump, ErrorCode::NonCanonicalBump);`,
    }),
    buildPoc: (_m, pid) => `// Anchor Exploit PoC — Shadow PDA via Non-Canonical Bump (AEGIS-SOL-006)
for (let b = canonicalBump - 1; b >= 0; b--) {
  try {
    const shadowPda = PublicKey.createProgramAddressSync([Buffer.from("claim"), attacker.publicKey.toBuffer(), Buffer.from([b])], programId);
    await program.methods.claimOnce(b).accounts({ claim: shadowPda }).signers([attacker]).rpc();
    break;
  } catch {}
} // Target: ${pid || "PROGRAM_ID"}`,
    detect: (_code, lines) => findLineMatches(lines, /create_program_address\s*\(/),
  },
  {
    ruleId: "AEGIS-SOL-007",
    title: "Re-Initialization Vulnerability Risk via `init_if_needed` Without State Guard",
    severity: "HIGH",
    cvss: 7.6,
    cwe: "CWE-665: Improper Initialization",
    sealevelCategory: "Sealevel Attack #4: Reinitialization Attacks",
    description:
      "`init_if_needed` is used without guarding authority/ownership fields against overwriting already-initialized state.",
    exploitScenario:
      "An attacker re-invokes initialization on an active account, hijacking ownership or resetting accumulated state.",
    remediation:
      "Use strict `init`, or explicitly guard owner fields with `if account.owner == Pubkey::default()`.",
    buildDiff: (m) => ({
      before: `- ${m.snippet}`,
      after: `+ #[account(init, payer = authority, space = 8 + State::INIT_SPACE, seeds = [...], bump)]\n+ // Or guard: require!(state.authority == Pubkey::default(), ErrorCode::AlreadyInitialized);`,
    }),
    buildPoc: (_m, pid) => `// Anchor Exploit PoC — Re-initialization Hijack (AEGIS-SOL-007)
await program.methods
  .initialize(attacker.publicKey)
  .accounts({ config: existingProtocolConfigPda, payer: attacker.publicKey })
  .signers([attacker])
  .rpc(); // Target: ${pid || "PROGRAM_ID"}`,
    detect: (cleanCode, lines) =>
      findLineMatches(lines, /init_if_needed/, () => {
        return !cleanCode.includes("Pubkey::default()") && !cleanCode.includes("is_initialized");
      }),
  },
  {
    ruleId: "AEGIS-SOL-008",
    title: "Missing `has_one` / Ownership Constraint on Mutable State Account",
    severity: "HIGH",
    cvss: 8.1,
    cwe: "CWE-639: Authorization Bypass Through User-Controlled Key",
    sealevelCategory: "Sealevel Attack #2: Account Data Matching",
    description:
      "An Anchor Accounts struct accepts a mutable `Account<'info, T>` (non-init) alongside a `Signer<'info>` without `has_one`, `constraint =`, or `seeds =` binding the account to the signer.",
    exploitScenario:
      "Any valid signer signs with their own wallet while passing another user's vault or state account, modifying or draining funds they do not own.",
    remediation:
      "Add `has_one = authority @ MyError::Unauthorized` (or canonical PDA `seeds = [..., authority.key().as_ref()]`) on the mutable state account.",
    buildDiff: (m) => ({
      before: `- #[account(mut)]\n- pub ${m.fieldName || "vault"}: Account<'info, Vault>,`,
      after: `+ #[account(mut, has_one = authority @ ErrorCode::Unauthorized)]\n+ pub ${m.fieldName || "vault"}: Account<'info, Vault>,`,
    }),
    buildPoc: (m, pid) => `// Anchor Exploit PoC — Cross-Account Hijack (AEGIS-SOL-008)
await program.methods
  .updateOrWithdraw()
  .accounts({ ${m.fieldName || "vault"}: victimAccountPubkey, authority: attacker.publicKey })
  .signers([attacker])
  .rpc(); // Target: ${pid || "PROGRAM_ID"}`,
    detect: (_code, _lines, structs) => {
      const hits: RawMatch[] = [];
      for (const st of structs) {
        const hasSigner = st.fields.some((f) => /\bSigner\s*</.test(f.typeStr));
        if (!hasSigner) continue;

        for (const f of st.fields) {
          const isTypedAccount = /\b(Account|InterfaceAccount)\s*</.test(f.typeStr);
          const isInit = /\b(init|init_if_needed)\b/.test(f.attrs);
          const hasRelationGuard = /\b(has_one|constraint|seeds|token::authority|token::mint)\s*=/.test(
            f.attrs
          );
          if (isTypedAccount && f.isMut && !isInit && !hasRelationGuard) {
            hits.push({
              line: f.line,
              snippet: `pub ${f.name}: ${f.typeStr} in ${st.name} (mutable without has_one/constraint/seeds)`,
              contextName: st.name,
              fieldName: f.name,
            });
          }
        }
      }
      return hits;
    },
  },
  {
    ruleId: "AEGIS-SOL-009",
    title: "Duplicate Mutable Account Aliasing Risk",
    severity: "MEDIUM",
    cvss: 6.5,
    cwe: "CWE-662: Improper Synchronization / State Aliasing",
    sealevelCategory: "Sealevel Attack #6: Duplicate Mutable Accounts",
    description:
      "Two mutable accounts of the exact same struct type appear in one Accounts struct without a `key() !=` constraint.",
    exploitScenario:
      "An attacker passes the same account as both source and destination; Anchor serializes the second copy last, duplicating balances or negating debits.",
    remediation:
      "Add `constraint = from_acct.key() != to_acct.key() @ ErrorCode::DuplicateAccount` on one of the two accounts.",
    buildDiff: (m) => ({
      before: `- #[account(mut)] pub to_account: Account<'info, UserLedger>, // ${m.contextName || ""}`,
      after: `+ #[account(mut, constraint = from_account.key() != to_account.key() @ ErrorCode::DuplicateAccount)]\n+ pub to_account: Account<'info, UserLedger>,`,
    }),
    buildPoc: (_m, pid) => `// Anchor Exploit PoC — Self-Transfer Balance Inflation (AEGIS-SOL-009)
await program.methods
  .transferInternal(new anchor.BN(attackerBalance))
  .accounts({ fromAccount: attackerLedgerPda, toAccount: attackerLedgerPda })
  .signers([attacker])
  .rpc(); // Target: ${pid || "PROGRAM_ID"}`,
    detect: (_code, _lines, structs) => {
      const hits: RawMatch[] = [];
      for (const st of structs) {
        const mutTypes = new Map<string, number>();
        for (const f of st.fields) {
          if (!f.isMut) continue;
          const m = f.typeStr.match(
            /\b(?:Account|InterfaceAccount)<['a-z_]+,\s*([A-Z][A-Za-z0-9_]+)>/
          );
          if (!m) continue;
          const tName = m[1];
          if (mutTypes.has(tName) && !st.body.includes("!=")) {
            hits.push({
              line: f.line,
              snippet: `struct ${st.name}: duplicate mutable Account<'info, ${tName}> without key() != check`,
              contextName: st.name,
              fieldName: f.name,
            });
            break;
          }
          mutTypes.set(tName, f.line);
        }
      }
      return hits;
    },
  },
  {
    ruleId: "AEGIS-SOL-010",
    title: "On-Chain Panic / DoS Risk via `.unwrap()` or `.expect()`",
    severity: "MEDIUM",
    cvss: 5.8,
    cwe: "CWE-248: Uncaught Exception / Runtime Panic",
    sealevelCategory: "Solana Best Practices: Error Handling",
    description:
      "Calling `.unwrap()` or `.expect()` inside an on-chain instruction causes an ungraceful BPF runtime abort instead of returning an Anchor `Result<()>` error.",
    exploitScenario:
      "Edge-case inputs trigger opaque runtime aborts that break composable CPI callers.",
    remediation:
      "Replace `.unwrap()` / `.expect()` with `.map_err(|_| ErrorCode::InvalidComputation)?` (or `.ok_or(...)?` for `Option`).",
    buildDiff: (m) => ({
      before: `- ${m.snippet}`,
      after: `+ ${m.snippet.replace(/\.(unwrap|expect)\([^)]*\)/, ".map_err(|_| ErrorCode::InvalidComputation)?")}`,
    }),
    buildPoc: (_m, pid) => `// Anchor PoC — Triggering BPF Panic Abort (AEGIS-SOL-010)
await expect(program.methods.edgeCall(new anchor.BN(0)).rpc()).rejects.toThrow(/Program failed to complete/);
// Target: ${pid || "PROGRAM_ID"}`,
    detect: (_code, lines) =>
      findLineMatches(lines, /\.(unwrap|expect)\s*\(/, (line) => !line.includes("assert")),
  },
  {
    ruleId: "AEGIS-SOL-011",
    title: "Division Before Multiplication (Precision Loss)",
    severity: "MEDIUM",
    cvss: 5.5,
    cwe: "CWE-682: Incorrect Calculation",
    sealevelCategory: "DeFi Economic Security",
    description:
      "Integer division performed before multiplication (`(a / b) * c` or `.checked_div(...)?.checked_mul(...)`) truncates fractional lamports/tokens to zero.",
    exploitScenario:
      "Attackers exploit rounding truncation with dust amounts to execute zero-fee swaps or siphon residuals.",
    remediation: "Multiply first using `u128` intermediates and divide last.",
    buildDiff: (m) => ({
      before: `- ${m.snippet}`,
      after: `+ let result = u64::try_from((a as u128).checked_mul(c as u128)?.checked_div(b as u128)?)?;`,
    }),
    buildPoc: (_m, pid) => `// Anchor PoC — Dust Rounding Truncation to Zero Fee (AEGIS-SOL-011)
for (let i = 0; i < 10; i++) {
  await program.methods.swap(new anchor.BN(99)).rpc();
} // Target: ${pid || "PROGRAM_ID"}`,
    detect: (_code, lines) =>
      findLineMatches(
        lines,
        /(\/\s*[a-zA-Z0-9_]+\s*\)\s*\*|checked_div\([^)]+\)\?\s*\.checked_mul)/
      ),
  },
  {
    ruleId: "AEGIS-SOL-012",
    title: "Hardcoded Secret Key, Seed Phrase, or Private Key Material",
    severity: "CRITICAL",
    cvss: 10.0,
    cwe: "CWE-798: Use of Hard-coded Credentials",
    sealevelCategory: "Key Management & OPSEC",
    description:
      "Potential hardcoded secret key, seed phrase, or private key material detected inside source code.",
    exploitScenario:
      "Automated bots sweep exposed keypairs or hijack program upgrade authority seconds after a public push.",
    remediation:
      "Rotate exposed credentials immediately and load secrets exclusively from environment variables or hardware/Squads multisigs.",
    buildDiff: () => ({
      before: `- const SECRET_KEY: &str = "hardcoded_secret...";`,
      after: `+ // Remove from source, scrub git history, and transfer upgrade authority to a Squads v4 Multisig.`,
    }),
    buildPoc: () => `// Immediate Remediation Verification (AEGIS-SOL-012)
// solana program set-upgrade-authority <PROGRAM_ID> --new-upgrade-authority <SQUADS_MULTISIG>`,
    detect: (_code, lines) =>
      findLineMatches(
        lines,
        /(PRIVATE_KEY|SECRET_KEY|SEED_PHRASE|MNEMONIC)\s*[:=]\s*["'\[][^"'\]]{12,}/i
      ),
  },
  {
    ruleId: "AEGIS-SOL-013",
    title: "Raw `try_from_slice` Without Anchor Discriminator Validation",
    severity: "HIGH",
    cvss: 8.0,
    cwe: "CWE-843: Access of Resource Using Incompatible Type (Type Cosplay)",
    sealevelCategory: "Sealevel Attack #3: Type Cosplay",
    description:
      "Manual Borsh deserialization (`try_from_slice`) detected without verifying an 8-byte type discriminator.",
    exploitScenario:
      "An attacker passes an account of Struct A into an instruction expecting Struct B with compatible leading bytes (Type Cosplay).",
    remediation:
      "Use Anchor's `Account<'info, T>` wrapper to automatically enforce owner + 8-byte SHA-256 discriminator.",
    buildDiff: (m) => ({
      before: `- ${m.snippet}`,
      after: `+ let state = Account::<ExpectedType>::try_from(&account_info)?;`,
    }),
    buildPoc: (_m, pid) => `// Anchor Exploit PoC — Type Cosplay Substitution (AEGIS-SOL-013)
await program.methods.privilegedAction().accounts({ adminConfig: lowPrivStructBPda }).signers([attacker]).rpc();
// Target: ${pid || "PROGRAM_ID"}`,
    detect: (_code, lines) => findLineMatches(lines, /try_from_slice\s*\(/),
  },
  {
    ruleId: "AEGIS-SOL-014",
    title: "Unconstrained SPL Token Account (Missing `token::mint` Guard)",
    severity: "CRITICAL",
    cvss: 9.2,
    cwe: "CWE-863: Incorrect Authorization",
    sealevelCategory: "SPL Token Security: Fake Mint / Authority Substitution",
    description:
      "A mutable `Account<'info, TokenAccount>` or `InterfaceAccount<'info, TokenAccount>` inside `#[derive(Accounts)]` does not enforce a `token::mint =` or `associated_token::mint =` constraint.",
    exploitScenario:
      "An attacker creates a worthless SPL mint with 1B supply and passes their fake token account into a deposit/collateral instruction, minting real vault shares or draining legitimate USDC.",
    remediation:
      "Always pin both `token::mint = expected_mint` and `token::authority = expected_owner` on every SPL TokenAccount.",
    buildDiff: (m) => ({
      before: `- #[account(mut)]\n- pub ${m.fieldName || "user_token_account"}: Account<'info, TokenAccount>,`,
      after: `+ #[account(mut, token::mint = vault.mint, token::authority = user)]\n+ pub ${m.fieldName || "user_token_account"}: Account<'info, TokenAccount>,`,
    }),
    buildPoc: (m, pid) => `// Anchor Exploit PoC — Worthless Fake SPL Mint Deposit (AEGIS-SOL-014)
const fakeMint = await createMint(connection, attacker, attacker.publicKey, null, 6);
const fakeAta = await getOrCreateAssociatedTokenAccount(connection, attacker, fakeMint, attacker.publicKey);
await mintTo(connection, attacker, fakeMint, fakeAta.address, attacker, 1_000_000_000_000);
await program.methods.depositCollateral(new anchor.BN(1_000_000_000))
  .accounts({ ${m.fieldName || "userTokenAccount"}: fakeAta.address })
  .signers([attacker]).rpc(); // Target: ${pid || "PROGRAM_ID"}`,
    detect: (_code, _lines, structs) => {
      const hits: RawMatch[] = [];
      for (const st of structs) {
        for (const f of st.fields) {
          if (!f.isMut) continue;
          const isTokenAcct = /\b(Account|InterfaceAccount)<[^,]+,\s*TokenAccount>/.test(f.typeStr);
          if (!isTokenAcct) continue;
          const attrCode = f.attrs
            .split("\n")
            .filter((l) => !l.trim().startsWith("///"))
            .join("\n");
          const hasMintGuard =
            /\b(token::mint|associated_token::mint)\s*=/.test(attrCode) ||
            /\bconstraint\s*=[\s\S]*?\bmint\b/.test(attrCode);
          if (!hasMintGuard) {
            hits.push({
              line: f.line,
              snippet: `pub ${f.name}: ${f.typeStr} in ${st.name} (missing token::mint guard)`,
              contextName: st.name,
              fieldName: f.name,
            });
          }
        }
      }
      return hits;
    },
  },
  {
    ruleId: "AEGIS-SOL-015",
    title: "Unchecked Oracle Price Feed (Missing Staleness / Confidence Guard)",
    severity: "HIGH",
    cvss: 8.4,
    cwe: "CWE-345: Insufficient Verification of Data Authenticity",
    sealevelCategory: "DeFi Oracle Security (Pyth / Switchboard)",
    description:
      "Oracle price retrieval (`get_price_unchecked`, `get_ema_price_unchecked`, `load_price_feed_from_account_info`, or Switchboard `get_result()`) detected without nearby `max_age` / `publish_time` staleness or confidence interval validation.",
    exploitScenario:
      "During Solana congestion or oracle downtime, an attacker borrows or liquidates against a stale or wide-confidence price feed, extracting bad debt from the protocol.",
    remediation:
      "Use `get_price_no_older_than(&clock, MAX_AGE_SECS)` and assert `price.conf * 100 <= price.price.unsigned_abs() * MAX_CONF_PCT`.",
    buildDiff: (m) => ({
      before: `- ${m.snippet}`,
      after: `+ let feed = price_update.get_price_no_older_than(&Clock::get()?, 30)?;\n+ require!(feed.price > 0 && feed.conf.saturating_mul(50) <= feed.price as u64, ErrorCode::StaleOrWideOracle);`,
    }),
    buildPoc: (_m, pid) => `// Anchor Exploit PoC — Stale Oracle Arbitrage (AEGIS-SOL-015)
// Supply a Pyth feed account whose publish_time lags > 60s behind Clock::unix_timestamp
// and execute borrow/swap at outdated mark price. Target: ${pid || "PROGRAM_ID"}`,
    detect: (_cleanCode, lines) =>
      findLineMatches(
        lines,
        /\b(get_price_unchecked|get_ema_price_unchecked|load_price_feed_from_account_info)\b|\bget_result\s*\(/,
        (_line, idx, all) => {
          const nearbyCode = getLocalFunctionWindow(all, idx, 12, 12);
          return !/\b(get_price_no_older_than|publish_time|max_age|conf)\b/.test(nearbyCode);
        }
      ),
  },
  {
    ruleId: "AEGIS-SOL-016",
    title: "Unvalidated `remaining_accounts` Iteration Without Owner/Key Checks",
    severity: "HIGH",
    cvss: 7.7,
    cwe: "CWE-20: Improper Input Validation",
    sealevelCategory: "Sealevel Attack #10: Unchecked Remaining Accounts",
    description:
      "`ctx.remaining_accounts` is accessed or iterated without checking account `.owner` or verifying keys against trusted program PDAs.",
    exploitScenario:
      "An attacker appends forged or duplicate accounts to `remaining_accounts`, injecting spoofed balances, rewards, or arbitrary CPI recipients.",
    remediation:
      "Validate `require_keys_eq!(*acc.owner, expected_owner)` and check for duplicate keys before reading or writing any account in `ctx.remaining_accounts`.",
    buildDiff: (m) => ({
      before: `- ${m.snippet}`,
      after: `+ for acc in ctx.remaining_accounts.iter() {\n+   require_keys_eq!(*acc.owner, crate::ID, ErrorCode::InvalidRemainingAccountOwner);\n+ }`,
    }),
    buildPoc: (_m, pid) => `// Anchor Exploit PoC — Malicious remaining_accounts Injection (AEGIS-SOL-016)
await program.methods.batchDistribute()
  .accounts({ pool: poolPda })
  .remainingAccounts([{ pubkey: forgedAttackerAccount, isWritable: true, isSigner: false }])
  .signers([attacker]).rpc(); // Target: ${pid || "PROGRAM_ID"}`,
    detect: (_code, lines) =>
      findLineMatches(lines, /remaining_accounts\b/, (_line, idx, all) => {
        const windowCode = getLocalFunctionWindow(all, idx, 0, 12);
        const hasOwnerCheck = /\.owner\b/.test(windowCode);
        const hasAccountTryFrom = /\bAccount(?:::<[^>\n]+>)?::try_from\b/.test(windowCode);
        const hasRequireKeysOnOwnerOrKey =
          /\brequire_keys_eq!\s*\([^;\n]*(?:\.owner\b|\.key\s*\(\))/.test(windowCode);
        return !hasOwnerCheck && !hasAccountTryFrom && !hasRequireKeysOnOwnerOrKey;
      }),
  },
  {
    ruleId: "AEGIS-SOL-017",
    title: "Inter-Procedural Unbound Value-Transfer CPI (Instruction ↔ Context Mismatch)",
    severity: "CRITICAL",
    cvss: 9.3,
    cwe: "CWE-285: Improper Authorization Across Call Boundary",
    sealevelCategory: "Inter-Procedural Analysis: Handler ↔ #[derive(Accounts)]",
    description:
      "Cross-referencing `pub fn handler(ctx: Context<T>)` with `#[derive(Accounts)] struct T` shows the instruction executes an outbound value-transfer / `invoke` CPI while `struct T` either lacks a `Signer<'info>` entirely or leaves its mutable vault/state account unbound to any signer.",
    exploitScenario:
      "An attacker invokes the CPI-bearing instruction passing an arbitrary victim vault; because the handler's `Context<T>` never binds the vault to a verified `Signer<'info>`, funds are transferred out without owner consent.",
    remediation:
      "Ensure `Context<T>` declares a `Signer<'info>` and binds every mutable source vault/state account via `has_one = authority` or signer-seeded `seeds = [...]`.",
    buildDiff: (m) => ({
      before: `- // Instruction '${m.contextName}()' executes CPI with unbound mutable '${m.fieldName || "vault"}'`,
      after: `+ #[account(mut, has_one = authority @ ErrorCode::Unauthorized)]\n+ pub ${m.fieldName || "vault"}: Account<'info, VaultState>,\n+ pub authority: Signer<'info>,`,
    }),
    buildPoc: (m, pid) => `// Inter-Procedural Exploit PoC — Unbound CPI Drain in ${m.contextName || "ix"}() (AEGIS-SOL-017)
await program.methods
  .${m.contextName || "withdraw"}(new anchor.BN(1_000_000_000))
  .accounts({ ${m.fieldName || "vault"}: victimVaultPda, authority: attacker.publicKey })
  .signers([attacker])
  .rpc(); // Target: ${pid || "PROGRAM_ID"}`,
    detect: (_code, _lines, structs, handlers) => {
      const structMap = new Map(structs.map((s) => [s.name, s]));
      const hits: RawMatch[] = [];

      for (const h of handlers) {
        if (h.cpiCalls.length === 0) continue;
        const st = structMap.get(h.contextStructName);
        if (!st) continue;

        const signers = st.fields.filter((f) => /\bSigner\s*</.test(f.typeStr));
        const unboundMutState = st.fields.find((f) => {
          if (!f.isMut) return false;
          const isState = /\b(Account|InterfaceAccount)\s*</.test(f.typeStr);
          const isInit = /\b(init|init_if_needed)\b/.test(f.attrs);
          const hasGuard = /\b(has_one|constraint|seeds|token::authority|token::mint)\s*=/.test(
            f.attrs
          );
          return isState && !isInit && !hasGuard;
        });

        if (signers.length === 0 || unboundMutState) {
          const cpi = h.cpiCalls[0];
          hits.push({
            line: cpi.line,
            snippet: `fn ${h.name}(Context<${st.name}>) -> ${cpi.kind} with ${
              signers.length === 0
                ? "zero Signer<'info> accounts"
                : `unbound mutable '${unboundMutState!.name}'`
            }`,
            contextName: h.name,
            fieldName: unboundMutState?.name || "vault",
          });
        }
      }
      return hits;
    },
  },
  {
    ruleId: "AEGIS-SOL-018",
    title: "Stale Deserialized Account Read After CPI Without `.reload()`",
    severity: "HIGH",
    cvss: 8.5,
    cwe: "CWE-662: Stale In-Memory State Post-CPI",
    sealevelCategory: "Inter-Procedural Post-CPI State Freshness",
    description:
      "Anchor deserializes `Account<'info, T>` fields once at instruction entry. Reading `.amount`, `.supply`, or `.balance` on an account *after* executing a token/lamport CPI without calling `.reload()?` uses stale pre-CPI memory.",
    exploitScenario:
      "A protocol mints or transfers tokens via CPI and then checks `ctx.accounts.vault_token.amount` or `mint.supply` to compute shares/solvency without `.reload()?`, allowing attackers to bypass invariant checks or inflate LP shares.",
    remediation:
      "Call `ctx.accounts.<account>.reload()?;` immediately after the CPI before reading any mutated field.",
    buildDiff: (m) => ({
      before: `- ${m.snippet}`,
      after: `+ ctx.accounts.${m.fieldName || "token_account"}.reload()?;\n+ ${m.snippet}`,
    }),
    buildPoc: (m, pid) => `// Post-CPI Stale Account Exploit PoC in ${m.contextName || "ix"}() (AEGIS-SOL-018)
// Trigger CPI that mutates ${m.fieldName || "token_account"} on-chain while handler evaluates
// stale pre-CPI in-memory balance to mint excess shares! Target: ${pid || "PROGRAM_ID"}`,
    detect: (_code, _lines, _structs, handlers) => {
      const hits: RawMatch[] = [];
      for (const h of handlers) {
        const tokenCpis = h.cpiCalls.filter((c) => c.kind !== "system_program::transfer");
        if (tokenCpis.length === 0) continue;

        const firstCpiRelIdx = tokenCpis[0].line - h.startLine;
        const reloadedAccounts = new Set<string>();

        for (let i = Math.max(0, firstCpiRelIdx); i < h.bodyLines.length; i++) {
          const ln = h.bodyLines[i].replace(/\/\/.*$/, "").trim();
          if (!ln) continue;

          const reloadMatch = ln.match(/(?:ctx\.accounts\.)?([a-zA-Z0-9_]+)\.reload\s*\(\s*\)/);
          if (reloadMatch) {
            reloadedAccounts.add(reloadMatch[1]);
            continue;
          }

          const staleRead = ln.match(
            /ctx\.accounts\.([a-zA-Z0-9_]+)\.(amount|supply|delegated_amount)\b/
          );
          if (staleRead && !reloadedAccounts.has(staleRead[1])) {
            hits.push({
              line: h.startLine + i,
              snippet: ln.slice(0, 140),
              contextName: h.name,
              fieldName: staleRead[1],
            });
            break;
          }
        }
      }
      return hits;
    },
  },
  {
    ruleId: "AEGIS-SOL-019",
    title: "Token-2022 Transfer-Fee Blind Accounting (`InterfaceAccount` Delta Drift)",
    severity: "HIGH",
    cvss: 8.0,
    cwe: "CWE-682: Fee-On-Transfer Accounting Discrepancy",
    sealevelCategory: "Token-2022 Extensions Security (TransferFeeConfig)",
    description:
      "A handler accepting Token-2022 `InterfaceAccount<'info, TokenAccount>` or calling `token_interface::transfer_checked` credits the raw `amount` argument to internal state without measuring actual pre/post vault balance delta.",
    exploitScenario:
      "With a Token-2022 mint charging a 5% transfer fee, depositing 100 tokens credits the attacker 100 internal shares while the vault only receives 95 tokens; withdrawing drains other users' principal.",
    remediation:
      "Record `let before = vault_ata.amount;` before CPI, call `vault_ata.reload()?;` after CPI, and credit `let actual_received = vault_ata.amount.checked_sub(before)?;`.",
    buildDiff: (m) => ({
      before: `- ${m.snippet}`,
      after: `+ vault_ata.reload()?;\n+ let received = vault_ata.amount.checked_sub(balance_before).ok_or(ErrorCode::MathOverflow)?;\n+ user.deposited = user.deposited.checked_add(received).ok_or(ErrorCode::MathOverflow)?;`,
    }),
    buildPoc: (_m, pid) => `// Token-2022 Transfer Fee Accounting Drift PoC (AEGIS-SOL-019)
// Deposit Token-2022 asset with TransferFeeConfig (e.g. 500 bps fee) -> credited 100% shares for 95% net tokens!
// Target: ${pid || "PROGRAM_ID"}`,
    detect: (_code, _lines, structs, handlers) => {
      const structMap = new Map(structs.map((s) => [s.name, s]));
      const hits: RawMatch[] = [];

      for (const h of handlers) {
        const st = structMap.get(h.contextStructName);
        const usesToken2022 =
          h.cpiCalls.some((c) => c.kind.includes("token_2022")) ||
          Boolean(st?.fields.some((f) => /InterfaceAccount<[^,]+,\s*TokenAccount>/.test(f.typeStr)));
        if (!usesToken2022) continue;

        const bodyJoined = h.bodyLines.join("\n");
        if (bodyJoined.includes(".reload()")) continue;

        for (let i = 0; i < h.bodyLines.length; i++) {
          const ln = h.bodyLines[i].replace(/\/\/.*$/, "").trim();
          if (/\.(?:checked_add\s*\(\s*amount\s*\)|balance\s*\+=\s*amount|deposited\s*\+=\s*amount)/.test(ln)) {
            hits.push({
              line: h.startLine + i,
              snippet: ln.slice(0, 140),
              contextName: h.name,
            });
            break;
          }
        }
      }
      return hits;
    },
  },
  {
    ruleId: "AEGIS-SOL-020",
    title: "Unprefixed Dynamic PDA Seeds (Cross-Account Seed Collision Risk)",
    severity: "MEDIUM",
    cvss: 6.4,
    cwe: "CWE-330: Ambiguous Cryptographic Domain Separation",
    sealevelCategory: "PDA Architecture: Domain Separation",
    description:
      "Anchor `seeds = [...]` starts directly with a dynamic key/slice instead of a unique static domain literal (`b\"vault\"`, `b\"user\"`, etc.), risking cross-struct PDA seed collisions.",
    exploitScenario:
      "Two distinct PDA types derived from `[authority.key().as_ref()]` without static prefixes resolve to the exact same PDA address, enabling initialization DoS or state confusion.",
    remediation:
      "Always begin every PDA `seeds = [...]` array with a unique constant byte-string prefix such as `seeds = [b\"vault_v1\", authority.key().as_ref()]`.",
    buildDiff: (m) => ({
      before: `- ${m.snippet}`,
      after: `+ #[account(seeds = [b"${m.fieldName || "domain"}", authority.key().as_ref()], bump)]`,
    }),
    buildPoc: (_m, pid) => `// PDA Domain Separation Audit Note (AEGIS-SOL-020)
// Prepend static domain tag b"..." to prevent cross-instruction PDA collisions. Target: ${pid || "PROGRAM_ID"}`,
    detect: (_code, _lines, structs) => {
      const hits: RawMatch[] = [];
      for (const st of structs) {
        for (const f of st.fields) {
          const seedMatch = f.attrs.match(/seeds\s*=\s*\[\s*([^\]]+)\]/);
          if (!seedMatch) continue;
          const firstElem = seedMatch[1].split(",")[0]?.trim() || "";
          if (
            firstElem &&
            !firstElem.startsWith('b"') &&
            !firstElem.startsWith("&b\"") &&
            !/^[A-Z0-9_]+$/.test(firstElem)
          ) {
            hits.push({
              line: f.line,
              snippet: `seeds = [${seedMatch[1].trim().slice(0, 90)}] on '${f.name}' lacks static b"..." prefix`,
              contextName: st.name,
              fieldName: f.name,
            });
          }
        }
      }
      return hits;
    },
  },
];

export function analyzeSolanaContract(
  sourceCode: string,
  targetName = "Untitled Solana Program",
  targetProgramId?: string
): ScanReport {
  const fileEntries = splitMultiFilePayload(sourceCode);
  const findings: SecurityFinding[] = [];
  const filesScanned: ScannedFileSummary[] = [];
  const attackSurface: InstructionAttackNode[] = [];
  let counter = 1;
  let totalLines = 0;

  for (const file of fileEntries) {
    const cleanCode = sanitizeRustPreservingLines(file.content);
    const lines = cleanCode.split(/\r?\n/);
    const structs = extractAccountStructs(cleanCode);
    const handlers = extractInstructionHandlers(cleanCode);
    const structMap = new Map(structs.map((s) => [s.name, s]));
    totalLines += lines.length;
    let fileFindings = 0;

    const fileRuleHits: SecurityFinding[] = [];
    for (const rule of RULES) {
      const matches = rule.detect(cleanCode, lines, structs, handlers);
      for (const match of matches) {
        const diff = rule.buildDiff(match);
        const item: SecurityFinding = {
          id: `FND-${String(counter++).padStart(3, "0")}`,
          ruleId: rule.ruleId,
          title: rule.title,
          severity: rule.severity,
          cvss: rule.cvss,
          cwe: rule.cwe,
          sealevelCategory: rule.sealevelCategory,
          filePath: file.path,
          line: match.line,
          snippet: match.snippet,
          description: rule.description,
          exploitScenario: rule.exploitScenario,
          remediation: rule.remediation,
          diffBefore: diff.before,
          diffAfter: diff.after,
          exploitPocTs: rule.buildPoc(match, targetProgramId),
        };
        findings.push(item);
        fileRuleHits.push(item);
        fileFindings++;
      }
    }

    // Build inter-procedural Instruction ↔ Context<Accounts> ↔ CPI Attack-Surface Graph
    for (const h of handlers) {
      const st = structMap.get(h.contextStructName);
      const signers = st
        ? st.fields.filter((f) => /\bSigner\s*</.test(f.typeStr)).map((f) => f.name)
        : [];
      const mutableAccounts = st ? st.fields.filter((f) => f.isMut).map((f) => f.name) : [];
      const uncheckedAccounts = st
        ? st.fields
            .filter(
              (f) =>
                /\b(AccountInfo|UncheckedAccount)\s*</.test(f.typeStr) &&
                !/\b(seeds|owner|address)\s*=/.test(f.attrs)
            )
            .map((f) => f.name)
        : [];
      const cpiTargets = Array.from(new Set(h.cpiCalls.map((c) => c.kind)));

      const structEndLine = st ? st.startLine + st.body.split("\n").length + 2 : 0;
      const relatedFindings = fileRuleHits.filter(
        (f) =>
          (f.line >= h.startLine && f.line <= h.endLine) ||
          (st && f.line >= st.startLine && f.line <= structEndLine)
      );

      let riskLevel: InstructionAttackNode["riskLevel"] = "SAFE";
      if (relatedFindings.some((f) => f.severity === "CRITICAL") || uncheckedAccounts.length > 0) {
        riskLevel = "CRITICAL";
      } else if (relatedFindings.some((f) => f.severity === "HIGH")) {
        riskLevel = "HIGH";
      }

      attackSurface.push({
        instruction: h.name,
        filePath: file.path,
        line: h.startLine,
        contextStruct: h.contextStructName,
        signers,
        mutableAccounts,
        uncheckedAccounts,
        cpiTargets,
        riskLevel,
      });
    }

    filesScanned.push({
      path: file.path,
      lines: lines.length,
      findings: fileFindings,
    });
  }

  findings.sort((a, b) => b.cvss - a.cvss);

  const summary = {
    critical: findings.filter((f) => f.severity === "CRITICAL").length,
    high: findings.filter((f) => f.severity === "HIGH").length,
    medium: findings.filter((f) => f.severity === "MEDIUM").length,
    low: findings.filter((f) => f.severity === "LOW").length,
    total: findings.length,
  };

  const penalty =
    summary.critical * 28 +
    summary.high * 15 +
    summary.medium * 7 +
    summary.low * 3;
  const securityScore = Math.max(0, Math.min(100, 100 - penalty));

  let riskGrade: ScanReport["riskGrade"] = "A+";
  if (securityScore < 35) riskGrade = "F";
  else if (securityScore < 55) riskGrade = "D";
  else if (securityScore < 72) riskGrade = "C";
  else if (securityScore < 86) riskGrade = "B";
  else if (securityScore < 96) riskGrade = "A";

  const scanId = `${Date.now()}`;
  const sourceCodeSha256 = crypto.createHash("sha256").update(sourceCode, "utf-8").digest("hex");

  const canonicalPayload = JSON.stringify({
    targetName,
    targetProgramId: targetProgramId || "",
    sourceCodeSha256,
    securityScore,
    summary,
    ruleIds: findings.map((f) => `${f.filePath}:${f.ruleId}:${f.line}`),
  });
  const reportHashHex = crypto.createHash("sha256").update(canonicalPayload).digest("hex");

  return {
    scanId,
    scannedAt: new Date().toISOString(),
    targetName,
    targetProgramId,
    linesAnalyzed: totalLines,
    filesScanned,
    attackSurface,
    securityScore,
    riskGrade,
    summary,
    sourceCodeSha256,
    reportHashHex,
    findings,
    scannerVersion: "AEGIS-SolSec-Engine/3.0.0",
  };
}
