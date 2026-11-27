"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import { useConnection, useWallet } from "@solana/wallet-adapter-react";
import { PublicKey, SystemProgram, Transaction } from "@solana/web3.js";
import { motion } from "framer-motion";
import { MachinedPanel } from "@/components/MachinedPanel";
import {
  ProtocolStepper,
  ScoreRingGauge,
  SeverityDistributionBar,
} from "@/components/VisualPrimitives";
import type { EscalatedFindingDraft } from "@/app/page";
import {
  Zap,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  ExternalLink,
  CheckCircle2,
  AlertOctagon,
  FileCode2,
  Sparkles,
  Copy,
  Check,
  BadgeCheck,
  GitBranch,
  Radar,
  Download,
  ArrowUpRight,
  Code2,
  FileDiff,
  Lock,
  Unlock,
} from "lucide-react";
import { CONTRACT_SAMPLES } from "@/lib/scanner/samples";
import {
  MULTI_FILE_MARKER_PREFIX,
  MULTI_FILE_MARKER_SUFFIX,
  ScanReport,
  SecurityFinding,
} from "@/lib/scanner/solanaRules";
import { buildSarifReport } from "@/lib/scanner/sarif";
import type { OnChainProgramInspection, InspectCluster } from "@/lib/solana/programInspector";
import type {
  OracleAttestationProof,
  X402PaymentRequiredPayload,
  X402PaymentResponsePayload,
} from "@/lib/x402/protocol";
import {
  buildMemoIx,
  buildRecordAuditAttestationIxs,
  hexToBytes32,
} from "@/lib/solana/aegisProgram";

export interface ScannerExternalCommand {
  nonce: number;
  mode: "code" | "github" | "onchain";
  presetId?: string;
  cluster?: InspectCluster;
  sampleIdx?: number;
}

interface X402ScannerTabProps {
  onRefreshState: () => Promise<void>;
  onEscalateFinding?: (draft: EscalatedFindingDraft) => void;
  externalCommand?: ScannerExternalCommand | null;
}

type InputMode = "code" | "github" | "onchain";
type FindingViewMode = "analysis" | "diff" | "poc";

const SEV_STYLE: Record<string, string> = {
  CRITICAL: "border-rose-500/40 bg-rose-500/10 text-rose-300",
  HIGH: "border-orange-500/40 bg-orange-500/10 text-orange-300",
  MEDIUM: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  LOW: "border-sky-500/40 bg-sky-500/10 text-sky-300",
  INFO: "border-teal-500/35 bg-teal-500/10 text-teal-300",
};

const SEV_TO_NUM: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

const INSPECT_PRESETS: Array<{ label: string; id: string; cluster: InspectCluster }> = [
  {
    label: "AEGIS v3 (Devnet)",
    id: "8AaU3VSHXHyKcVTe9JCA67oRR5djpjfAUgcM1cCtpe7p",
    cluster: "devnet",
  },
  {
    label: "Jupiter v6 (Mainnet)",
    id: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
    cluster: "mainnet-beta",
  },
  {
    label: "Token-2022 (Mainnet)",
    id: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
    cluster: "mainnet-beta",
  },
];

function downloadBlob(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function isValidBase58Pubkey(val: string): boolean {
  try {
    new PublicKey(val.trim());
    return true;
  } catch {
    return false;
  }
}

export function X402ScannerTab({
  onRefreshState,
  onEscalateFinding,
  externalCommand,
}: X402ScannerTabProps) {
  const { connection } = useConnection();
  const { publicKey, sendTransaction } = useWallet();

  const [inputMode, setInputMode] = useState<InputMode>("code");

  // Source Code & IDE Editor state
  const [targetName, setTargetName] = useState(CONTRACT_SAMPLES[0].label);
  const [targetProgramId, setTargetProgramId] = useState(CONTRACT_SAMPLES[0].programId);
  const [code, setCode] = useState(CONTRACT_SAMPLES[0].code);
  const [highlightedLine, setHighlightedLine] = useState<number | null>(null);
  const [activeFileTab, setActiveFileTab] = useState<string>("lib.rs");

  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const gutterRef = useRef<HTMLDivElement>(null);

  // GitHub Repo Scanner state
  const [repoUrl, setRepoUrl] = useState("https://github.com/coral-xyz/sealevel-attacks");
  const [fetchingRepo, setFetchingRepo] = useState(false);
  const [loadedRepoMeta, setLoadedRepoMeta] = useState<{
    repoUrl: string;
    branch: string;
    files: Array<{ path: string; lines: number }>;
    truncatedFileCount: number;
  } | null>(null);

  // Live On-Chain Program Inspector state
  const [inspectProgramId, setInspectProgramId] = useState(
    "8AaU3VSHXHyKcVTe9JCA67oRR5djpjfAUgcM1cCtpe7p"
  );
  const [inspectCluster, setInspectCluster] = useState<InspectCluster>("devnet");
  const [inspecting, setInspecting] = useState(false);
  const [inspection, setInspection] = useState<OnChainProgramInspection | null>(null);

  // x402 Wire Protocol state
  const [step, setStep] = useState<
    "idle" | "probing" | "402_received" | "paying" | "verifying" | "done"
  >("idle");
  const [paymentRequired, setPaymentRequired] = useState<X402PaymentRequiredPayload | null>(null);
  const [paymentReceipt, setPaymentReceipt] = useState<X402PaymentResponsePayload | null>(null);
  const [oracleAttestation, setOracleAttestation] = useState<OracleAttestationProof | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sealing, setSealing] = useState(false);
  const [sponsorRunning, setSponsorRunning] = useState(false);
  const [sealedTx, setSealedTx] = useState<string | null>(null);
  const [copiedCli, setCopiedCli] = useState(false);
  const [copiedPocId, setCopiedPocId] = useState<string | null>(null);
  const [copiedBadge, setCopiedBadge] = useState(false);
  const [findingTabs, setFindingTabs] = useState<Record<string, FindingViewMode>>({});

  const [originUrl, setOriginUrl] = useState("https://aegis-solana-gamma.vercel.app");
  useEffect(() => {
    setOriginUrl(window.location.origin);
  }, []);
  const agentCliCmd = `node scripts/x402-agent-demo.mjs ${originUrl}/api/x402/scan`;

  const codeLines = useMemo(() => code.split("\n"), [code]);

  // Map multi-file offsets inside combined `code` so file tabs & finding jump-to-line work accurately
  const fileLineOffsets = useMemo(() => {
    const map = new Map<string, number>();
    codeLines.forEach((ln, idx) => {
      if (ln.startsWith(MULTI_FILE_MARKER_PREFIX) && ln.endsWith(MULTI_FILE_MARKER_SUFFIX)) {
        const fpath = ln
          .slice(MULTI_FILE_MARKER_PREFIX.length, -MULTI_FILE_MARKER_SUFFIX.length)
          .trim();
        if (fpath) map.set(fpath, idx + 2); // 1-based line right below marker
      }
    });
    return map;
  }, [codeLines]);

  function jumpToEditorLine(targetLine1Based: number, filePath?: string) {
    let absLine = targetLine1Based;
    if (filePath && fileLineOffsets.has(filePath)) {
      absLine = (fileLineOffsets.get(filePath) || 1) + targetLine1Based - 1;
      setActiveFileTab(filePath);
    }
    setHighlightedLine(absLine);
    if (textareaRef.current) {
      const lineHeightPx = 19.5;
      const scrollTop = Math.max(0, (absLine - 4) * lineHeightPx);
      textareaRef.current.scrollTo({ top: scrollTop, behavior: "smooth" });
      textareaRef.current.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }

  function syncGutterScroll() {
    if (gutterRef.current && textareaRef.current) {
      gutterRef.current.scrollTop = textareaRef.current.scrollTop;
    }
  }

  function loadSample(idx: number) {
    const s = CONTRACT_SAMPLES[idx];
    setInputMode("code");
    setTargetName(s.label);
    setTargetProgramId(s.programId);
    setCode(s.code);
    setActiveFileTab("lib.rs");
    setHighlightedLine(null);
    setLoadedRepoMeta(null);
    setReport(null);
    setPaymentReceipt(null);
    setOracleAttestation(null);
    setSealedTx(null);
    setError(null);
    setStep("idle");
  }

  // Handle commands dispatched from Ctrl+K Command Palette
  useEffect(() => {
    if (!externalCommand) return;
    if (externalCommand.mode === "code" && typeof externalCommand.sampleIdx === "number") {
      loadSample(externalCommand.sampleIdx);
    } else if (externalCommand.mode === "github") {
      setInputMode("github");
    } else if (externalCommand.mode === "onchain") {
      setInputMode("onchain");
      if (externalCommand.presetId) {
        handleInspectProgram(externalCommand.presetId, externalCommand.cluster || "devnet");
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [externalCommand?.nonce]);

  async function handleFetchGithubRepo() {
    setError(null);
    setFetchingRepo(true);
    setReport(null);
    setPaymentReceipt(null);
    setOracleAttestation(null);
    setSealedTx(null);
    setHighlightedLine(null);
    setStep("idle");

    try {
      const res = await fetch("/api/scanner/github", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data?.error || "Failed to fetch Rust files from GitHub.");
        return;
      }
      setCode(data.combinedCode);
      setTargetName(`${data.owner}/${data.repo} (${data.files.length} files)`);
      if (data.detectedProgramId) {
        setTargetProgramId(data.detectedProgramId);
      }
      if (data.files?.[0]?.path) {
        setActiveFileTab(data.files[0].path);
      }
      setLoadedRepoMeta({
        repoUrl: data.repoUrl,
        branch: data.branch,
        files: data.files,
        truncatedFileCount: data.truncatedFileCount,
      });
    } catch (err: any) {
      setError(err?.message || "GitHub repository fetch failed.");
    } finally {
      setFetchingRepo(false);
    }
  }

  async function handleInspectProgram(overrideId?: string, overrideCluster?: InspectCluster) {
    const pid = (overrideId ?? inspectProgramId).trim();
    const cl = overrideCluster ?? inspectCluster;
    if (overrideId) setInspectProgramId(overrideId);
    if (overrideCluster) setInspectCluster(overrideCluster);

    setError(null);
    setInspecting(true);
    try {
      const res = await fetch("/api/solana/inspect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ programId: pid, cluster: cl }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data?.error || "Failed to inspect program on Solana RPC.");
        setInspection(null);
        return;
      }
      setInspection(data);
    } catch (err: any) {
      setError(err?.message || "Solana RPC inspection failed.");
    } finally {
      setInspecting(false);
    }
  }

  async function handleProbe402() {
    setError(null);
    setReport(null);
    setPaymentReceipt(null);
    setOracleAttestation(null);
    setSealedTx(null);
    setStep("probing");

    try {
      const res = await fetch("/api/x402/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, targetName, targetProgramId }),
      });

      if (res.status === 402) {
        const headerB64 = res.headers.get("payment-required");
        const body = await res.json();
        const decoded: X402PaymentRequiredPayload = headerB64
          ? JSON.parse(atob(headerB64))
          : body.x402;
        setPaymentRequired(decoded);
        setStep("402_received");
      } else {
        const body = await res.json();
        setError(body?.error || `Unexpected status ${res.status}`);
        setStep("idle");
      }
    } catch (err: any) {
      setError(err?.message || "Failed to contact /api/x402/scan");
      setStep("idle");
    }
  }

  async function handlePayAndScan() {
    if (!publicKey) {
      setError("Connect your Phantom or Solflare wallet on Solana Devnet first.");
      return;
    }
    if (!paymentRequired?.accepts?.[0]) {
      setError("Run Step 1 (Trigger HTTP 402) first.");
      return;
    }

    setError(null);
    setStep("paying");

    try {
      const req = paymentRequired.accepts[0];
      const lamports = Number(req.amount);

      const tx = new Transaction()
        .add(
          SystemProgram.transfer({
            fromPubkey: publicKey,
            toPubkey: new PublicKey(req.payTo),
            lamports,
          })
        )
        .add(buildMemoIx(req.extra.memoRequired, publicKey));

      const sig = await sendTransaction(tx, connection);
      await connection.confirmTransaction(sig, "confirmed");

      setStep("verifying");

      const paymentSignaturePayload = {
        x402Version: 2,
        resource: paymentRequired.resource,
        accepted: req,
        payload: {
          signature: sig,
          account: publicKey.toBase58(),
        },
      };
      const encodedSigHeader = btoa(JSON.stringify(paymentSignaturePayload));

      const paidRes = await fetch("/api/x402/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "PAYMENT-SIGNATURE": encodedSigHeader,
        },
        body: JSON.stringify({ code, targetName, targetProgramId }),
      });

      const paidJson = await paidRes.json();
      if (!paidRes.ok) {
        setError(paidJson?.reason || paidJson?.error || "x402 payment verification failed.");
        setStep("402_received");
        return;
      }

      setPaymentReceipt(paidJson.paymentReceipt);
      setOracleAttestation(paidJson.oracleAttestation || null);
      setReport(paidJson.report);
      setStep("done");
    } catch (err: any) {
      setError(err?.message || "Solana payment transaction was cancelled or failed.");
      setStep("402_received");
    }
  }

  async function handleSealAttestationOnChain() {
    if (!report || !paymentReceipt) return;
    if (!publicKey) {
      setError(
        "Connect your Solana Devnet wallet (top right) to seal this Ed25519 audit attestation on-chain."
      );
      return;
    }
    setError(null);

    let targetPubkey: PublicKey;
    try {
      targetPubkey = new PublicKey(targetProgramId.trim());
    } catch {
      setError("Invalid Target Program ID (must be a valid Solana Base58 public key).");
      return;
    }

    setSealing(true);
    try {
      const { ixs } = await buildRecordAuditAttestationIxs({
        auditor: publicKey,
        scanId: BigInt(report.scanId),
        targetProgramId: targetPubkey,
        sourceCodeHash: hexToBytes32(report.sourceCodeSha256),
        reportHash: hexToBytes32(report.reportHashHex),
        securityScore: report.securityScore,
        criticalCount: report.summary.critical,
        highCount: report.summary.high,
        x402PaymentSig: paymentReceipt.transaction,
        oracleProof:
          oracleAttestation && oracleAttestation.targetProgramId === targetPubkey.toBase58()
            ? oracleAttestation
            : null,
      });

      const tx = new Transaction();
      ixs.forEach((ix) => tx.add(ix));
      const sig = await sendTransaction(tx, connection);
      await connection.confirmTransaction(sig, "confirmed");
      setSealedTx(sig);
      await onRefreshState();
    } catch (err: any) {
      setError(err?.message || "Failed to seal attestation on-chain.");
    } finally {
      setSealing(false);
    }
  }

  async function handleSponsoredJudgeDemo() {
    setError(null);
    setSponsorRunning(true);
    setStep("paying");
    setReport(null);
    setPaymentReceipt(null);
    setOracleAttestation(null);
    setSealedTx(null);

    try {
      const res = await fetch("/api/x402/judge-demo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, targetName, targetProgramId }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data?.error || data?.reason || "Sponsored Devnet x402 TX failed.");
        setStep(paymentRequired ? "402_received" : "idle");
        return;
      }
      if (data.paymentRequired) setPaymentRequired(data.paymentRequired);
      setPaymentReceipt(data.paymentReceipt);
      setOracleAttestation(data.oracleAttestation || null);
      setReport(data.report);
      setStep("done");
    } catch (err: any) {
      setError(err?.message || "Failed to execute sponsored Devnet x402 TX.");
      setStep(paymentRequired ? "402_received" : "idle");
    } finally {
      setSponsorRunning(false);
    }
  }

  function handleExportSarif() {
    if (!report) return;
    const sarif = buildSarifReport(report);
    const slug = report.targetName.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 32);
    downloadBlob(`aegis-${slug}.sarif.json`, JSON.stringify(sarif, null, 2), "application/json");
  }

  function handleExportMarkdown() {
    if (!report) return;
    const lines = [
      `# AEGIS Security Audit Report — ${report.targetName}`,
      ``,
      `- **Score:** ${report.securityScore}/100 (Grade **${report.riskGrade}**)`,
      `- **Engine:** ${report.scannerVersion} (20 Inter-Procedural Sealevel Rules)`,
      `- **Target Program ID:** \`${report.targetProgramId || "N/A"}\``,
      `- **Code SHA-256:** \`0x${report.sourceCodeSha256}\``,
      `- **Report Hash:** \`0x${report.reportHashHex}\``,
      `- **x402 Settlement TX:** ${paymentReceipt?.explorerUrl || "N/A"}`,
      ``,
      `## Findings (${report.summary.total})`,
      ``,
      ...report.findings.map(
        (f) =>
          `### [${f.severity} · CVSS ${f.cvss.toFixed(1)}] ${f.ruleId}: ${f.title}\n- **Location:** \`${f.filePath}:${f.line}\`\n- **Category:** ${f.sealevelCategory} (${f.cwe})\n- **Exploit Scenario:** ${f.exploitScenario}\n- **Remediation:** ${f.remediation}\n\n\`\`\`diff\n${f.diffBefore}\n${f.diffAfter}\n\`\`\`\n\n\`\`\`ts\n${f.exploitPocTs}\n\`\`\`\n`
      ),
    ];
    const slug = report.targetName.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 32);
    downloadBlob(`aegis-audit-${slug}.md`, lines.join("\n"), "text/markdown");
  }

  function handleEscalate(f: SecurityFinding) {
    if (!onEscalateFinding) return;
    const compactSummary = `[${f.ruleId}] ${f.title} at ${f.filePath}:${f.line} (CVSS ${f.cvss.toFixed(1)})`.slice(
      0,
      160
    );
    const fullDetail = [
      `Rule: ${f.ruleId} (${f.severity} · CVSS ${f.cvss.toFixed(1)} · ${f.cwe})`,
      `Target: ${report?.targetName || targetName} (${targetProgramId})`,
      `Location: ${f.filePath}:${f.line}`,
      `Snippet: ${f.snippet}`,
      `Exploit Scenario: ${f.exploitScenario}`,
      `Anchor PoC:\n${f.exploitPocTs}`,
      `Patch:\n${f.diffBefore}\n${f.diffAfter}`,
    ].join("\n\n");

    onEscalateFinding({
      id: f.id,
      ruleId: f.ruleId,
      title: f.title,
      severityNum: SEV_TO_NUM[f.severity] || 2,
      pocSummary: compactSummary,
      detailedReport: fullDetail,
    });
  }

  function copyAgentCmd() {
    navigator.clipboard.writeText(agentCliCmd);
    setCopiedCli(true);
    setTimeout(() => setCopiedCli(false), 2000);
  }

  function copyBadgeMd(pid: string) {
    const md = `[![AEGIS On-Chain Audit](${originUrl}/api/badge/${pid})](https://explorer.solana.com/address/${pid}?cluster=devnet)`;
    navigator.clipboard.writeText(md);
    setCopiedBadge(true);
    setTimeout(() => setCopiedBadge(false), 2000);
  }

  const byteCount = useMemo(() => new TextEncoder().encode(code).length, [code]);

  return (
    <div className="space-y-5">
      {/* Mode Switcher + Quick Sample Presets */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="inline-flex rounded-xl border border-slate-800/90 bg-[#060a12] p-1">
          {(
            [
              { id: "code" as InputMode, label: "Source Code", icon: FileCode2 },
              { id: "github" as InputMode, label: "GitHub Repo", icon: GitBranch },
              { id: "onchain" as InputMode, label: "On-Chain Inspector", icon: Radar },
            ] as const
          ).map((m) => {
            const Icon = m.icon;
            const active = inputMode === m.id;
            return (
              <button
                key={m.id}
                type="button"
                onClick={() => {
                  setInputMode(m.id);
                  setError(null);
                }}
                className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                  active
                    ? "bg-slate-800/90 text-white shadow-sm"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <Icon className={`h-3.5 w-3.5 ${active ? "text-teal-300" : "text-slate-500"}`} />
                {m.label}
              </button>
            );
          })}
        </div>

        {inputMode !== "onchain" ? (
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="hidden text-xs font-medium tracking-[-0.01em] text-slate-400 sm:inline">
              x402 v2 · 20 inter-procedural rules · 0.001 SOL
            </span>
            {CONTRACT_SAMPLES.map((sample, idx) => (
              <button
                key={sample.id}
                onClick={() => loadSample(idx)}
                className="aegis-btn-secondary inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-medium"
              >
                <span
                  className={`h-1.5 w-1.5 rotate-45 ${idx === 0 ? "bg-rose-400" : "bg-teal-300"}`}
                />
                {idx === 0 ? "Vulnerable Sample" : "AEGIS Hardened"}
              </button>
            ))}
          </div>
        ) : (
          <div className="flex flex-wrap items-center gap-1.5">
            {INSPECT_PRESETS.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => handleInspectProgram(p.id, p.cluster)}
                className="aegis-btn-secondary rounded-lg px-2.5 py-1.5 text-xs font-medium"
              >
                {p.label}
              </button>
            ))}
          </div>
        )}
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-xl border border-rose-500/35 bg-rose-500/10 p-3.5 text-sm text-rose-200">
          <AlertOctagon className="h-4 w-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* MODE 3: LIVE ON-CHAIN SOLANA PROGRAM INSPECTOR */}
      {inputMode === "onchain" ? (
        <div className="space-y-5">
          <MachinedPanel variant="titanium" className="p-5">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
              <div className="flex-1">
                <label className="mb-1.5 block text-xs font-medium text-slate-400">
                  Live Solana Program ID (BPFLoaderUpgradeable + On-Chain Anchor IDL + AEGIS PDA)
                </label>
                <input
                  value={inspectProgramId}
                  onChange={(e) => setInspectProgramId(e.target.value)}
                  placeholder="Enter any Solana Devnet or Mainnet Program ID..."
                  className="w-full rounded-xl border border-slate-700/80 bg-[#05080f] px-3.5 py-2.5 font-mono text-xs text-white outline-none focus:border-teal-400/70"
                />
              </div>
              <div className="flex items-end gap-2 lg:pt-5">
                <select
                  value={inspectCluster}
                  onChange={(e) => setInspectCluster(e.target.value as InspectCluster)}
                  className="rounded-xl border border-slate-700/80 bg-[#05080f] px-3 py-2.5 text-xs font-medium text-slate-200 outline-none focus:border-teal-400"
                >
                  <option value="devnet">Solana Devnet</option>
                  <option value="mainnet-beta">Solana Mainnet</option>
                </select>
                <button
                  type="button"
                  onClick={() => handleInspectProgram()}
                  disabled={inspecting}
                  className="aegis-btn-primary inline-flex items-center gap-2 rounded-xl px-5 py-2.5 text-xs font-bold disabled:opacity-50"
                >
                  <Radar className="h-4 w-4" />
                  {inspecting ? "Inspecting RPC..." : "Inspect Live Program"}
                </button>
              </div>
            </div>
          </MachinedPanel>

          {inspection && (
            <div className="grid gap-5 lg:grid-cols-12">
              <MachinedPanel variant="steel" className="space-y-4 p-5 lg:col-span-5">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div>
                    <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400">
                      Live RPC Bytecode Telemetry · {inspection.cluster}
                    </div>
                    <h3 className="mt-0.5 font-display text-base font-semibold text-white">
                      {inspection.idlProgramName || "Deployed BPF Program"}
                    </h3>
                  </div>
                  <ScoreRingGauge score={inspection.surfaceScore} label="SURFACE" size={62} />
                </div>

                <div className="grid grid-cols-2 gap-2.5 text-xs">
                  <div className="aegis-subbox rounded-lg p-3">
                    <div className="text-[10.5px] font-medium uppercase tracking-wider text-slate-500">Loader</div>
                    <div className="mt-0.5 truncate font-medium text-slate-200">{inspection.loaderType}</div>
                  </div>
                  <div className="aegis-subbox rounded-lg p-3">
                    <div className="text-[10.5px] font-medium uppercase tracking-wider text-slate-500">Immutability</div>
                    <div className="mt-0.5 flex items-center gap-1.5">
                      {inspection.isImmutable === true ? (
                        <>
                          <Lock className="h-3.5 w-3.5 text-teal-300" />
                          <span className="font-semibold text-teal-300">Immutable</span>
                        </>
                      ) : inspection.isImmutable === false ? (
                        <>
                          <Unlock className="h-3.5 w-3.5 text-amber-300" />
                          <span className="font-semibold text-amber-300">Upgradeable</span>
                        </>
                      ) : (
                        <span className="text-slate-400">N/A</span>
                      )}
                    </div>
                  </div>
                  <div className="aegis-subbox rounded-lg p-3">
                    <div className="text-[10.5px] font-medium uppercase tracking-wider text-slate-500">ELF Binary Size</div>
                    <div className="mt-0.5 font-medium tabular-nums text-slate-200">
                      {inspection.binarySizeBytes
                        ? `${(inspection.binarySizeBytes / 1024).toFixed(1)} KB`
                        : "N/A"}
                    </div>
                  </div>
                  <div className="aegis-subbox rounded-lg p-3">
                    <div className="text-[10.5px] font-medium uppercase tracking-wider text-slate-500">Last Deploy Slot</div>
                    <div className="mt-0.5 font-medium tabular-nums text-slate-200">
                      {inspection.lastDeployedSlot
                        ? inspection.lastDeployedSlot.toLocaleString()
                        : "N/A"}
                    </div>
                  </div>
                </div>

                {inspection.upgradeAuthority && (
                  <div className="aegis-card-warn rounded-xl p-3 text-xs">
                    <div className="font-semibold text-amber-300">Active Upgrade Authority</div>
                    <div className="mt-0.5 break-all font-mono text-[11px] text-amber-100/90">
                      {inspection.upgradeAuthority}
                    </div>
                  </div>
                )}

                <div className="aegis-subbox space-y-2 rounded-xl p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[10.5px] font-semibold uppercase tracking-wider text-slate-400">
                      Live On-Chain SVG Trust Badge
                    </span>
                    <button
                      type="button"
                      onClick={() => copyBadgeMd(inspection.programId)}
                      className="inline-flex items-center gap-1 text-[11px] font-medium text-teal-300 hover:underline"
                    >
                      {copiedBadge ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                      {copiedBadge ? "Copied MD" : "Copy README MD"}
                    </button>
                  </div>
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img
                    src={`/api/badge/${inspection.programId}`}
                    alt="Live AEGIS On-Chain SVG Audit Badge"
                    className="h-6"
                  />
                </div>
              </MachinedPanel>

              <MachinedPanel variant="solana" className="space-y-4 p-5 lg:col-span-7">
                <div>
                  <h4 className="font-display text-sm font-semibold text-white">
                    On-Chain Security & Deployment Checks
                  </h4>
                  <div className="mt-2.5 space-y-2">
                    {inspection.riskChecks.map((rc) => (
                      <div key={rc.id} className="aegis-subbox rounded-xl p-3 text-xs">
                        <div className="flex items-center gap-2">
                          <span
                            className={`rounded border px-1.5 py-0.5 font-mono text-[10px] font-bold ${
                              SEV_STYLE[rc.severity] || SEV_STYLE.INFO
                            }`}
                          >
                            {rc.severity}
                          </span>
                          <span className="font-mono text-[11px] text-slate-400">{rc.id}</span>
                          <span className="font-medium text-white">{rc.title}</span>
                        </div>
                        <p className="mt-1.5 leading-relaxed text-slate-400">{rc.detail}</p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="border-t border-slate-800/80 pt-3.5">
                  <div className="flex items-center justify-between">
                    <h4 className="font-display text-sm font-semibold text-white">
                      On-Chain Anchor IDL Attack Surface{" "}
                      {inspection.idlFound
                        ? `(${inspection.idlInstructions.length} instructions inflated via zlib)`
                        : "(No On-Chain IDL Published)"}
                    </h4>
                    <span className="font-mono text-[10px] text-slate-500">
                      IDL PDA: {inspection.idlAddress.slice(0, 8)}...
                    </span>
                  </div>

                  {inspection.idlFound ? (
                    <div className="mt-2.5 max-h-64 space-y-2 overflow-y-auto pr-1">
                      {inspection.idlInstructions.map((ix) => (
                        <div
                          key={ix.name}
                          className={`rounded-lg border p-2.5 font-mono text-[11px] ${
                            ix.writableWithoutSigner
                              ? "border-rose-500/40 bg-rose-500/10"
                              : "border-slate-800/90 bg-[#05080f]"
                          }`}
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <span className="font-bold text-slate-100">{ix.name}()</span>
                            <div className="flex items-center gap-2 text-[10px]">
                              <span className="text-slate-400">{ix.accountCount} accts</span>
                              <span className="text-amber-300">{ix.writableCount} mut</span>
                              <span className="text-teal-300">{ix.signerCount} signer</span>
                              {ix.writableWithoutSigner && (
                                <span className="rounded bg-rose-500/20 px-1.5 py-0.5 text-rose-200">
                                  NO SIGNER
                                </span>
                              )}
                            </div>
                          </div>
                          <div className="mt-1.5 flex flex-wrap gap-1">
                            {ix.accounts.slice(0, 10).map((acc) => (
                              <span
                                key={`${ix.name}-${acc.name}`}
                                className={`rounded px-1.5 py-0.5 text-[10px] ${
                                  acc.signer
                                    ? "bg-teal-500/15 text-teal-200"
                                    : acc.writable
                                    ? "bg-amber-500/15 text-amber-200"
                                    : "bg-slate-800/80 text-slate-400"
                                }`}
                              >
                                {acc.name}
                                {acc.signer ? " [sig]" : ""}
                                {acc.writable ? " [mut]" : ""}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="mt-2 text-xs text-slate-400">
                      No compressed `anchor:idl` account exists for this program. Try{" "}
                      <button
                        type="button"
                        onClick={() =>
                          handleInspectProgram(
                            "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
                            "mainnet-beta"
                          )
                        }
                        className="font-mono text-teal-300 hover:underline"
                      >
                        Jupiter v6 (Mainnet)
                      </button>{" "}
                      to see live on-chain `zlib` IDL extraction in action.
                    </p>
                  )}
                </div>
              </MachinedPanel>
            </div>
          )}
        </div>
      ) : (
        /* MODES 1 & 2: IDE CODE FRAME + LIVE x402 WIRE INSPECTOR */
        <div className="grid gap-6 lg:grid-cols-12">
          <MachinedPanel variant="steel" delay={0.05} className="p-5 lg:col-span-7">
            {inputMode === "github" && (
              <div className="mb-4 space-y-2.5 rounded-xl border border-slate-800 bg-[#05080f] p-3.5">
                <div className="flex items-center justify-between">
                  <span className="inline-flex items-center gap-1.5 font-mono text-[11px] font-semibold text-teal-300">
                    <GitBranch className="h-3.5 w-3.5" />
                    GitHub Multi-File Rust Repository Fetcher (SSRF-Safe)
                  </span>
                  <button
                    type="button"
                    onClick={() => setRepoUrl("https://github.com/coral-xyz/sealevel-attacks")}
                    className="font-mono text-[10px] text-slate-400 hover:text-teal-300"
                  >
                    Load coral-xyz/sealevel-attacks
                  </button>
                </div>
                <div className="flex gap-2">
                  <input
                    value={repoUrl}
                    onChange={(e) => setRepoUrl(e.target.value)}
                    placeholder="https://github.com/owner/solana-repo"
                    className="flex-1 rounded-lg border border-slate-700/80 bg-black/50 px-3 py-2 font-mono text-xs text-white outline-none focus:border-teal-400"
                  />
                  <button
                    type="button"
                    onClick={handleFetchGithubRepo}
                    disabled={fetchingRepo}
                    className="aegis-btn-primary rounded-lg px-4 py-2 text-xs font-bold disabled:opacity-50"
                  >
                    {fetchingRepo ? "Fetching .rs..." : "Load Repo"}
                  </button>
                </div>
              </div>
            )}

            <div className="mb-3 space-y-2.5">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <FileCode2 className="h-4 w-4 text-teal-300" />
                  <span className="font-display text-sm font-semibold text-white">
                    Target Solana / Anchor Workspace
                  </span>
                </div>
                <span className="text-[11px] font-medium text-slate-500">
                  Solana BPF · Anchor Rust
                </span>
              </div>
              <div className="grid gap-2 sm:grid-cols-12">
                <div className="sm:col-span-5">
                  <label className="mb-1 block text-[10.5px] font-medium text-slate-500">
                    Target Name
                  </label>
                  <input
                    value={targetName}
                    onChange={(e) => setTargetName(e.target.value)}
                    placeholder="Target Name"
                    className="w-full rounded-lg border border-slate-800 bg-[#060910] px-3 py-1.5 text-xs font-medium text-white outline-none focus:border-teal-400/70"
                  />
                </div>
                <div className="sm:col-span-7">
                  <label className="mb-1 block text-[10.5px] font-medium text-slate-500">
                    Target Program ID (Base58)
                  </label>
                  <input
                    value={targetProgramId}
                    onChange={(e) => setTargetProgramId(e.target.value)}
                    placeholder="Target Program ID"
                    className="w-full rounded-lg border border-slate-800 bg-[#060910] px-3 py-1.5 font-mono text-[11px] text-slate-300 outline-none focus:border-teal-400/70"
                  />
                </div>
              </div>
            </div>

            {/* Precision IDE Frame with File Tabs + Synchronized Line-Number Gutter */}
            <div className="overflow-hidden rounded-xl border border-slate-800/95 bg-[#04070d]">
              {/* IDE Header Bar & File Tabs */}
              <div className="flex items-center justify-between border-b border-slate-800/90 bg-[#070b13] px-3 py-1.5">
                <div className="flex min-w-0 items-center gap-1.5 overflow-x-auto">
                  <div className="mr-1.5 flex shrink-0 items-center gap-1">
                    <span className="h-2 w-2 rounded-full bg-slate-700" />
                    <span className="h-2 w-2 rounded-full bg-slate-700" />
                    <span className="h-2 w-2 rounded-full bg-slate-700" />
                  </div>

                  {loadedRepoMeta && loadedRepoMeta.files.length > 0 ? (
                    loadedRepoMeta.files.map((f) => {
                      const shortName = f.path.split("/").slice(-2).join("/");
                      const isTabActive = activeFileTab === f.path;
                      return (
                        <button
                          key={f.path}
                          type="button"
                          onClick={() => {
                            setActiveFileTab(f.path);
                            jumpToEditorLine(1, f.path);
                          }}
                          className={`shrink-0 rounded-md px-2 py-0.5 font-mono text-[10.5px] transition ${
                            isTabActive
                              ? "border border-slate-700 bg-[#0d1422] text-teal-300"
                              : "text-slate-400 hover:text-slate-200"
                          }`}
                          title={f.path}
                        >
                          {shortName}
                        </button>
                      );
                    })
                  ) : (
                    <span className="rounded-md border border-slate-800 bg-[#0b101b] px-2 py-0.5 font-mono text-[10.5px] text-slate-200">
                      programs/target/src/lib.rs
                    </span>
                  )}
                </div>

                <span className="ml-2 shrink-0 text-[11px] font-medium tabular-nums text-slate-500">
                  Rust · {(byteCount / 1024).toFixed(1)} KB
                </span>
              </div>

              {/* Synchronized Gutter + Code Editor Surface */}
              <div className="relative flex h-[332px]">
                <div
                  ref={gutterRef}
                  aria-hidden="true"
                  className="w-11 shrink-0 select-none overflow-hidden border-r border-slate-800/80 bg-[#05080f] py-3 pr-2.5 text-right font-mono text-[11.5px] leading-[19.5px] text-slate-600"
                >
                  {codeLines.map((_, idx) => {
                    const lnNum = idx + 1;
                    const isHi = highlightedLine === lnNum;
                    return (
                      <div
                        key={lnNum}
                        className={isHi ? "bg-teal-400/15 font-bold text-teal-300" : undefined}
                      >
                        {lnNum}
                      </div>
                    );
                  })}
                </div>

                <textarea
                  ref={textareaRef}
                  value={code}
                  onChange={(e) => {
                    setCode(e.target.value);
                    setHighlightedLine(null);
                  }}
                  onScroll={syncGutterScroll}
                  spellCheck={false}
                  wrap="off"
                  className="h-full w-full resize-none overflow-auto bg-transparent px-3.5 py-3 font-mono text-[12px] leading-[19.5px] text-slate-200 outline-none"
                />
              </div>

              {/* IDE Status Footer */}
              <div className="flex items-center justify-between border-t border-slate-800/80 bg-[#060911] px-3 py-1.5 text-[11px] font-medium tabular-nums text-slate-500">
                <span>
                  {codeLines.length} lines ·{" "}
                  {highlightedLine ? (
                    <span className="text-teal-300">Focused Line {highlightedLine}</span>
                  ) : (
                    "20 Inter-Procedural Sealevel & CPI Detectors"
                  )}
                </span>
                <span>UTF-8 · Anchor / BPF</span>
              </div>
            </div>

            <div className="mt-3.5 flex items-center justify-end gap-3">
              <button
                onClick={handleProbe402}
                disabled={step === "probing" || step === "paying" || step === "verifying"}
                className="aegis-btn-primary inline-flex items-center gap-2 rounded-xl px-5 py-2.5 text-xs font-bold disabled:opacity-50"
              >
                <Zap className="h-4 w-4" />
                {step === "probing"
                  ? "Probing /api/x402/scan..."
                  : "1. Request Audit (Trigger HTTP 402)"}
              </button>
            </div>
          </MachinedPanel>

          {/* Right: Live x402 Protocol Inspector (Institutional Graphite Discipline) */}
          <MachinedPanel
            variant="solana"
            delay={0.1}
            className="flex flex-col justify-between p-5 lg:col-span-5"
          >
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Terminal className="h-4 w-4 text-teal-300" />
                  <h3 className="font-display text-sm font-semibold text-white">
                    Live x402 V2 Wire Inspector
                  </h3>
                </div>
                <span className="rounded border border-slate-800 bg-[#060911] px-2 py-0.5 font-mono text-[10px] text-slate-400">
                  POST /api/x402/scan
                </span>
              </div>

              <ProtocolStepper
                steps={[
                  {
                    title: "HTTP 402",
                    sub: paymentRequired ? "Quote Ready" : "Challenge",
                    status: paymentRequired || step === "done" ? "done" : "active",
                  },
                  {
                    title: "0.001 SOL",
                    sub: "SPL Memo TX",
                    status:
                      step === "done"
                        ? "done"
                        : paymentRequired || step === "paying" || step === "verifying"
                        ? "active"
                        : "idle",
                  },
                  {
                    title: "Ed25519",
                    sub: "Oracle Proof",
                    status: step === "done" ? "done" : "idle",
                  },
                ]}
              />

              <div className="space-y-3 text-xs">
                {paymentRequired ? (
                  <div className="aegis-card-warn rounded-xl p-3">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-amber-300">402 PAYMENT-REQUIRED</span>
                      <span className="font-mono text-[10px] text-amber-200/80">
                        {paymentRequired.accepts[0].extra.memoRequired}
                      </span>
                    </div>
                    <pre className="mt-2 max-h-32 overflow-auto rounded-lg border border-amber-500/15 bg-black/50 p-2 font-mono text-[10px] text-amber-200">
                      {JSON.stringify(
                        {
                          x402Version: paymentRequired.x402Version,
                          network: paymentRequired.accepts[0].network,
                          amount: "0.001 SOL (1,000,000 lamports)",
                          payTo: paymentRequired.accepts[0].payTo,
                          memoRequired: paymentRequired.accepts[0].extra.memoRequired,
                        },
                        null,
                        2
                      )}
                    </pre>
                  </div>
                ) : (
                  <div className="aegis-subbox flex items-center justify-between rounded-xl px-3.5 py-3">
                    <div className="flex items-center gap-2.5">
                      <span className="h-2 w-2 rounded-full bg-teal-400/80" />
                      <span className="font-medium text-slate-300">Pay-Per-Scan Endpoint Ready</span>
                    </div>
                    <span className="font-mono text-[11px] text-teal-300">0.001 SOL / scan</span>
                  </div>
                )}

                <div
                  className={`rounded-xl p-3.5 ${
                    step === "done"
                      ? "aegis-card-safe"
                      : paymentRequired
                      ? "border border-slate-700 bg-[#080d17]"
                      : "aegis-subbox"
                  }`}
                >
                  <div className="mb-2.5 flex items-center justify-between">
                    <span className="font-semibold text-slate-100">Execute Scan</span>
                    <span className="rounded bg-slate-900 px-2 py-0.5 font-mono text-[10px] text-slate-400">
                      {step === "done" ? "200 OK · VERIFIED" : "SPL MEMO ANTI-SNIPING"}
                    </span>
                  </div>
                  <button
                    onClick={handlePayAndScan}
                    disabled={
                      !paymentRequired ||
                      step === "paying" ||
                      step === "verifying" ||
                      sponsorRunning
                    }
                    className="aegis-btn-primary flex w-full items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-xs font-bold disabled:opacity-40"
                  >
                    <Sparkles className="h-3.5 w-3.5" />
                    {step === "paying" && !sponsorRunning
                      ? "Confirming 0.001 SOL + Memo..."
                      : step === "verifying"
                      ? "Verifying on Devnet..."
                      : "2. Pay 0.001 SOL + Memo with Wallet"}
                  </button>
                  <button
                    type="button"
                    onClick={handleSponsoredJudgeDemo}
                    disabled={sponsorRunning || step === "verifying"}
                    className="aegis-btn-secondary mt-2 flex w-full items-center justify-center gap-1.5 rounded-lg px-3 py-2 text-[11.5px] font-medium disabled:opacity-40"
                  >
                    <Zap className="h-3.5 w-3.5 text-teal-300" />
                    {sponsorRunning
                      ? "Broadcasting REAL Sponsored Devnet x402 TX..."
                      : "No Devnet SOL? Run Real Sponsored Devnet x402 TX"}
                  </button>
                </div>

                {paymentReceipt && (
                  <div className="aegis-card-safe rounded-xl p-3">
                    <div className="flex items-center justify-between">
                      <span className="inline-flex items-center gap-1.5 font-semibold text-teal-300">
                        <BadgeCheck className="h-3.5 w-3.5" />
                        {oracleAttestation ? "Ed25519 Oracle Proof Issued" : "Payment Settled"}
                      </span>
                      <a
                        href={paymentReceipt.explorerUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 text-[11px] font-medium text-teal-300 hover:underline"
                      >
                        Explorer <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                    <div className="mt-1 truncate font-mono text-[10.5px] text-teal-100/90">
                      {paymentReceipt.memoBound} · {paymentReceipt.transaction}
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="aegis-subbox mt-4 rounded-xl p-3">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] uppercase tracking-wider text-slate-400">
                    Headless AI Agent CLI
                  </span>
                  <a
                    href="/api/x402/scan"
                    target="_blank"
                    rel="noreferrer"
                    className="font-mono text-[10px] text-teal-300 hover:underline"
                  >
                    Discovery JSON ↗
                  </a>
                </div>
                <button
                  onClick={copyAgentCmd}
                  className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-white"
                >
                  {copiedCli ? (
                    <Check className="h-3 w-3 text-teal-300" />
                  ) : (
                    <Copy className="h-3 w-3" />
                  )}
                  {copiedCli ? "Copied" : "Copy"}
                </button>
              </div>
              <code className="mt-1 block truncate font-mono text-[11px] text-slate-300">
                {agentCliCmd}
              </code>
            </div>
          </MachinedPanel>
        </div>
      )}

      {/* Pentest Report Output */}
      {report && inputMode !== "onchain" && (
        <MachinedPanel variant="titanium" className="p-6">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div className="flex min-w-[280px] flex-1 items-center gap-4">
              <ScoreRingGauge
                score={report.securityScore}
                label={`GRADE ${report.riskGrade}`}
                size={68}
              />
              <div className="min-w-0 flex-1 max-w-md space-y-2">
                <div className="flex flex-wrap items-center gap-2.5">
                  <h3 className="font-display text-lg font-bold text-white">{report.targetName}</h3>
                  <span className="rounded border border-slate-800 bg-slate-900/80 px-2 py-0.5 font-mono text-[10.5px] text-slate-400">
                    0x{report.sourceCodeSha256.slice(0, 10)}…
                  </span>
                </div>
                <SeverityDistributionBar
                  critical={report.summary.critical}
                  high={report.summary.high}
                  medium={report.summary.medium}
                  low={report.summary.low}
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={handleExportSarif}
                className="aegis-btn-secondary inline-flex items-center gap-1.5 rounded-xl px-3 py-2 font-mono text-xs"
              >
                <Download className="h-3.5 w-3.5 text-teal-300" />
                SARIF 2.1
              </button>
              <button
                type="button"
                onClick={handleExportMarkdown}
                className="aegis-btn-secondary inline-flex items-center gap-1.5 rounded-xl px-3 py-2 font-mono text-xs"
              >
                <Download className="h-3.5 w-3.5 text-slate-400" />
                Report .md
              </button>
              {isValidBase58Pubkey(targetProgramId) && (
                <button
                  type="button"
                  onClick={() => copyBadgeMd(targetProgramId.trim())}
                  className="aegis-btn-secondary inline-flex items-center gap-1.5 rounded-xl px-3 py-2 font-mono text-xs"
                >
                  {copiedBadge ? (
                    <Check className="h-3.5 w-3.5 text-teal-300" />
                  ) : (
                    <Copy className="h-3.5 w-3.5 text-slate-400" />
                  )}
                  {copiedBadge ? "Badge Copied" : "SVG Badge"}
                </button>
              )}

              {sealedTx ? (
                <a
                  href={`https://explorer.solana.com/tx/${sealedTx}?cluster=devnet`}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-2 rounded-xl border border-teal-500/50 bg-teal-500/15 px-4 py-2 text-xs font-bold text-teal-300"
                >
                  <CheckCircle2 className="h-4 w-4" />
                  {oracleAttestation ? "Ed25519 Sealed! View TX" : "Self-Attested! View TX"}
                  <ExternalLink className="h-3.5 w-3.5" />
                </a>
              ) : (
                <button
                  onClick={handleSealAttestationOnChain}
                  disabled={sealing}
                  className="aegis-btn-primary inline-flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-bold disabled:opacity-50"
                >
                  <ShieldCheck className="h-4 w-4" />
                  {sealing
                    ? "Verifying Ed25519 & Sealing..."
                    : oracleAttestation
                    ? "Seal Ed25519 Audit On-Chain"
                    : "Seal Audit On-Chain"}
                </button>
              )}
            </div>
          </div>

          {/* Inter-Procedural Instruction <-> Context<T> <-> CPI Attack-Surface Graph */}
          {report.attackSurface && report.attackSurface.length > 0 && (
            <div className="mt-5 rounded-xl border border-slate-800/90 bg-[#05080f] p-4">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-slate-300">
                  Inter-Procedural Call & Account Graph ({report.attackSurface.length} instructions mapped)
                </span>
                <span className="font-mono text-[10px] text-slate-500">
                  pub fn ↔ Context&lt;Accounts&gt; ↔ Outbound CPIs
                </span>
              </div>
              <div className="grid gap-2.5 md:grid-cols-2">
                {report.attackSurface.map((node) => (
                  <div
                    key={`${node.filePath}:${node.instruction}:${node.line}`}
                    onClick={() => jumpToEditorLine(node.line, node.filePath)}
                    className="cursor-pointer rounded-lg border border-slate-800/80 bg-[#080d17] p-3 font-mono text-[11px] transition hover:border-slate-600"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-bold text-white">
                        {node.instruction}
                        <span className="font-normal text-slate-400">
                          (Context&lt;{node.contextStruct}&gt;)
                        </span>
                      </span>
                      <span
                        className={`rounded border px-1.5 py-0.5 text-[9px] font-bold ${
                          node.riskLevel === "CRITICAL"
                            ? "border-rose-500/40 bg-rose-500/10 text-rose-300"
                            : node.riskLevel === "HIGH"
                            ? "border-amber-500/40 bg-amber-500/10 text-amber-300"
                            : "border-teal-500/35 bg-teal-500/10 text-teal-300"
                        }`}
                      >
                        {node.riskLevel}
                      </span>
                    </div>
                    <div className="mt-1.5 flex flex-wrap gap-1.5 text-[10px]">
                      <span className="rounded bg-teal-500/10 px-1.5 py-0.5 text-teal-200">
                        sig: {node.signers.length > 0 ? node.signers.join(", ") : "NONE"}
                      </span>
                      <span className="rounded bg-slate-800 px-1.5 py-0.5 text-slate-300">
                        mut: {node.mutableAccounts.length > 0 ? node.mutableAccounts.join(", ") : "none"}
                      </span>
                      {node.uncheckedAccounts.length > 0 && (
                        <span className="rounded bg-rose-500/15 px-1.5 py-0.5 text-rose-200">
                          unchecked: {node.uncheckedAccounts.join(", ")}
                        </span>
                      )}
                      {node.cpiTargets.map((cpi) => (
                        <span
                          key={cpi}
                          className="rounded border border-slate-700/80 bg-slate-900 px-1.5 py-0.5 text-slate-300"
                        >
                          CPI → {cpi}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {report.findings.length === 0 ? (
            <div className="aegis-card-safe mt-5 flex items-center gap-3.5 rounded-xl p-5 text-sm text-teal-100">
              <ShieldCheck className="h-6 w-6 shrink-0 text-teal-300" />
              <div>
                <div className="font-display font-bold text-white">Zero Vulnerabilities Detected!</div>
                <div className="mt-0.5 text-xs text-slate-300">
                  Passed all 20 Inter-Procedural Sealevel, Token-2022, Oracle & Anchor security detectors.
                </div>
              </div>
            </div>
          ) : (
            <div className="mt-5 space-y-3.5">
              {report.findings.map((f, idx) => {
                const mode: FindingViewMode = findingTabs[f.id] || "analysis";
                return (
                  <motion.div
                    key={f.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{
                      duration: 0.2,
                      delay: Math.min(idx * 0.035, 0.3),
                      ease: [0.16, 1, 0.3, 1],
                    }}
                    className="aegis-subbox rounded-xl p-4"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`rounded border px-2 py-0.5 font-mono text-[10px] font-bold ${
                            SEV_STYLE[f.severity] || SEV_STYLE.MEDIUM
                          }`}
                        >
                          {f.severity} · CVSS {f.cvss.toFixed(1)}
                        </span>
                        <span className="font-mono text-xs text-slate-300">{f.ruleId}</span>
                        <h4 className="font-display text-sm font-semibold text-white">{f.title}</h4>
                      </div>

                      <div className="flex flex-wrap items-center gap-2">
                        <button
                          type="button"
                          onClick={() => jumpToEditorLine(f.line, f.filePath)}
                          className="rounded border border-slate-800 bg-[#060911] px-2 py-0.5 font-mono text-[11px] text-slate-300 transition hover:border-teal-400/50 hover:text-teal-300"
                          title="Jump to line in IDE editor"
                        >
                          {f.filePath}:{f.line} ↵
                        </button>
                        {onEscalateFinding && (
                          <button
                            type="button"
                            onClick={() => handleEscalate(f)}
                            className="aegis-btn-secondary inline-flex items-center gap-1 rounded-lg px-2.5 py-1 font-mono text-[10px] font-semibold"
                          >
                            Escalate to Vault
                            <ArrowUpRight className="h-3 w-3 text-teal-300" />
                          </button>
                        )}
                      </div>
                    </div>

                    <pre className="mt-2.5 overflow-x-auto rounded-lg border border-slate-800/90 bg-black/55 px-3 py-2 font-mono text-xs text-rose-200/95">
                      {f.snippet}
                    </pre>

                    <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
                      <div className="inline-flex rounded-lg border border-slate-800 bg-[#05080f] p-0.5 font-mono text-[11px]">
                        <button
                          type="button"
                          onClick={() => setFindingTabs((p) => ({ ...p, [f.id]: "analysis" }))}
                          className={`rounded-md px-2.5 py-1 transition ${
                            mode === "analysis"
                              ? "bg-slate-800 text-white"
                              : "text-slate-400 hover:text-slate-200"
                          }`}
                        >
                          Exploit & Patch
                        </button>
                        <button
                          type="button"
                          onClick={() => setFindingTabs((p) => ({ ...p, [f.id]: "diff" }))}
                          className={`inline-flex items-center gap-1 rounded-md px-2.5 py-1 transition ${
                            mode === "diff"
                              ? "bg-slate-800 text-teal-300"
                              : "text-slate-400 hover:text-slate-200"
                          }`}
                        >
                          <FileDiff className="h-3 w-3" /> Patch Diff
                        </button>
                        <button
                          type="button"
                          onClick={() => setFindingTabs((p) => ({ ...p, [f.id]: "poc" }))}
                          className={`inline-flex items-center gap-1 rounded-md px-2.5 py-1 transition ${
                            mode === "poc"
                              ? "bg-slate-800 text-rose-300"
                              : "text-slate-400 hover:text-slate-200"
                          }`}
                        >
                          <Code2 className="h-3 w-3" /> Exploit PoC (TS)
                        </button>
                      </div>

                      {mode === "poc" && (
                        <button
                          type="button"
                          onClick={() => {
                            navigator.clipboard.writeText(f.exploitPocTs);
                            setCopiedPocId(f.id);
                            setTimeout(() => setCopiedPocId(null), 1800);
                          }}
                          className="inline-flex items-center gap-1 font-mono text-[11px] text-slate-400 hover:text-white"
                        >
                          {copiedPocId === f.id ? (
                            <Check className="h-3 w-3 text-teal-300" />
                          ) : (
                            <Copy className="h-3 w-3" />
                          )}
                          {copiedPocId === f.id ? "Copied PoC" : "Copy Anchor Test"}
                        </button>
                      )}
                    </div>

                    {mode === "analysis" && (
                      <div className="mt-2.5 grid gap-3 text-xs md:grid-cols-2">
                        <div className="aegis-card-danger rounded-xl p-3.5">
                          <div className="mb-1.5 flex items-center gap-1.5 font-display text-[11px] font-bold uppercase tracking-wider text-rose-300">
                            <ShieldAlert className="h-3.5 w-3.5 shrink-0" />
                            Exploit Scenario · {f.sealevelCategory}
                          </div>
                          <p className="leading-relaxed text-slate-300">{f.exploitScenario}</p>
                        </div>
                        <div className="aegis-card-safe rounded-xl p-3.5">
                          <div className="mb-1.5 flex items-center gap-1.5 font-display text-[11px] font-bold uppercase tracking-wider text-teal-300">
                            <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
                            Recommended Anchor Patch · {f.cwe}
                          </div>
                          <p className="leading-relaxed text-slate-300">{f.remediation}</p>
                        </div>
                      </div>
                    )}

                    {mode === "diff" && (
                      <div className="mt-2.5 overflow-x-auto rounded-xl border border-slate-800 bg-[#04070d] p-3 font-mono text-xs leading-relaxed">
                        {f.diffBefore.split("\n").map((ln, i) => (
                          <div key={`b-${i}`} className="bg-rose-500/10 px-2 text-rose-300">
                            {ln}
                          </div>
                        ))}
                        {f.diffAfter.split("\n").map((ln, i) => (
                          <div key={`a-${i}`} className="bg-teal-500/10 px-2 text-teal-300">
                            {ln}
                          </div>
                        ))}
                      </div>
                    )}

                    {mode === "poc" && (
                      <pre className="mt-2.5 overflow-x-auto rounded-xl border border-slate-800 bg-[#04070d] p-3.5 font-mono text-xs leading-relaxed text-slate-200">
                        {f.exploitPocTs}
                      </pre>
                    )}
                  </motion.div>
                );
              })}
            </div>
          )}
        </MachinedPanel>
      )}
    </div>
  );
}
