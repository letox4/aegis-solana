"use client";

import React, { useEffect, useState } from "react";
import { useConnection, useWallet } from "@solana/wallet-adapter-react";
import { LAMPORTS_PER_SOL, PublicKey, Transaction } from "@solana/web3.js";
import { MachinedPanel } from "@/components/MachinedPanel";
import { EscrowCapacityBar, ProtocolStepper } from "@/components/VisualPrimitives";
import type { EscalatedFindingDraft } from "@/app/page";
import {
  AegisEncryptedEnvelope,
  AegisEncryptionBundle,
  decryptPocEnvelope,
  encryptPocEnvelope,
  generateSecureSalt,
} from "@/lib/crypto/pocVault";
import {
  Shield,
  Lock,
  Plus,
  Send,
  CheckCircle2,
  ExternalLink,
  Hash,
  Coins,
  AlertTriangle,
  RefreshCw,
  Eye,
  XCircle,
  Download,
  ShieldOff,
  KeyRound,
  Unlock,
  Sparkles,
  Copy,
  Check,
} from "lucide-react";
import {
  buildApproveAndPayoutIx,
  buildCloseBountyIx,
  buildCreateBountyIx,
  buildRaiseDisputeIx,
  buildRejectFindingIx,
  buildRevealFindingIx,
  buildSubmitFindingCommitIx,
  buildTopUpBountyIx,
  bytesToHex,
  OnChainBountyVault,
  OnChainFindingReport,
  sha256Text,
  SOLANA_RENT_EXEMPT_MIN_LAMPORTS,
} from "@/lib/solana/aegisProgram";

interface BountyVaultsTabProps {
  bounties: OnChainBountyVault[];
  findings: OnChainFindingReport[];
  onRefresh: () => Promise<void>;
  escalatedFinding?: EscalatedFindingDraft | null;
  onClearEscalation?: () => void;
}

interface LocalCommitReceipt {
  findingAddress: string;
  bountyAddress: string;
  pocSummary: string;
  salt: string;
  commitHashHex: string;
  aegisUri?: string;
  decryptionKeyB64?: string;
  savedAt: string;
}

const RECEIPTS_STORAGE_KEY = "aegis_commit_receipts_v2";

const SEVERITY_LABELS: Record<number, { label: string; color: string }> = {
  1: { label: "LOW", color: "text-sky-300 bg-sky-500/10 border-sky-500/30" },
  2: { label: "MEDIUM", color: "text-amber-300 bg-amber-500/10 border-amber-500/30" },
  3: { label: "HIGH", color: "text-orange-300 bg-orange-500/10 border-orange-500/30" },
  4: { label: "CRITICAL", color: "text-rose-300 bg-rose-500/10 border-rose-500/30" },
};

function loadReceipts(): Record<string, LocalCommitReceipt> {
  if (typeof window === "undefined") return {};
  try {
    return JSON.parse(localStorage.getItem(RECEIPTS_STORAGE_KEY) || "{}");
  } catch {
    return {};
  }
}

function saveReceipt(receipt: LocalCommitReceipt) {
  if (typeof window === "undefined") return;
  const all = loadReceipts();
  all[receipt.findingAddress] = receipt;
  localStorage.setItem(RECEIPTS_STORAGE_KEY, JSON.stringify(all));
}

function triggerJsonDownload(filename: string, data: unknown) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function BountyVaultsTab({
  bounties,
  findings,
  onRefresh,
  escalatedFinding,
  onClearEscalation,
}: BountyVaultsTabProps) {
  const { connection } = useConnection();
  const { publicKey, sendTransaction } = useWallet();

  const activeBounties = bounties.filter((b) => b.isActive);

  // Create Bounty form
  const [targetName, setTargetName] = useState("Solana DeFi Vault v2");
  const [scopeUri, setScopeUri] = useState("https://github.com/aegis/target-scope");
  const [rewardSol, setRewardSol] = useState("0.05");
  const [maxPayoutSol, setMaxPayoutSol] = useState("0.03");

  // Commit-Reveal + E2E AES-256-GCM Finding form
  const [selectedBounty, setSelectedBounty] = useState<string>("");
  const [pocSecret, setPocSecret] = useState(
    "CRITICAL: Missing signer check in withdraw_vault allows arbitrary authority spoofing."
  );
  const [detailedReport, setDetailedReport] = useState(
    "Full reproduction steps & Anchor exploit PoC encrypted client-side via WebCrypto AES-256-GCM."
  );
  const [salt, setSalt] = useState("aegis-salt-2026");
  const [liveHashHex, setLiveHashHex] = useState("");
  const [severity, setSeverity] = useState(4);
  const [encryptedUri, setEncryptedUri] = useState("aegis-aes256://pending-client-encryption");
  const [handle, setHandle] = useState("whitehat_cl");

  // E2E Encryption state
  const [e2eBundle, setE2eBundle] = useState<AegisEncryptionBundle | null>(null);
  const [encrypting, setEncrypting] = useState(false);
  const [copiedKey, setCopiedKey] = useState(false);

  // Live Decryption Verifier drawer
  const [verifierOpen, setVerifierOpen] = useState(false);
  const [verifyEnvelopeJson, setVerifyEnvelopeJson] = useState("");
  const [verifyKeyInput, setVerifyKeyInput] = useState("");
  const [decryptedPreview, setDecryptedPreview] = useState<{
    pocSummary: string;
    detailedReport: string;
    salt: string;
    sealedAt: string;
    integrityVerified: boolean;
  } | null>(null);
  const [decryptErr, setDecryptErr] = useState<string | null>(null);

  // Per-finding interactive state (custom payout + inline reveal modal)
  const [payoutInputs, setPayoutInputs] = useState<Record<string, string>>({});
  const [revealOpenFor, setRevealOpenFor] = useState<string | null>(null);
  const [revealPoc, setRevealPoc] = useState("");
  const [revealSalt, setRevealSalt] = useState("");
  const [savedReceipts, setSavedReceipts] = useState<Record<string, LocalCommitReceipt>>({});

  // Feedback
  const [busy, setBusy] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<{
    type: "ok" | "err";
    text: string;
    tx?: string;
    receipt?: LocalCommitReceipt;
  } | null>(null);

  useEffect(() => {
    setSavedReceipts(loadReceipts());
  }, []);

  // Pre-populate when escalated directly from the x402 Security Scanner
  useEffect(() => {
    if (!escalatedFinding) return;
    setPocSecret(escalatedFinding.pocSummary.slice(0, 160));
    setDetailedReport(escalatedFinding.detailedReport);
    setSeverity(escalatedFinding.severityNum);
    setSalt(generateSecureSalt());
    setE2eBundle(null);
    setEncryptedUri("aegis-aes256://pending-client-encryption");
  }, [escalatedFinding]);

  useEffect(() => {
    if (
      (!selectedBounty || !activeBounties.some((b) => b.address === selectedBounty)) &&
      activeBounties.length > 0
    ) {
      setSelectedBounty(activeBounties[0].address);
    }
  }, [bounties, selectedBounty]);

  useEffect(() => {
    let active = true;
    sha256Text(`${pocSecret}||${salt}`).then((bytes) => {
      if (active) setLiveHashHex(bytesToHex(bytes));
    });
    return () => {
      active = false;
    };
  }, [pocSecret, salt]);

  async function handleEncryptClientSide() {
    setEncrypting(true);
    setStatusMsg(null);
    try {
      const freshSalt = salt.trim() || generateSecureSalt();
      if (!salt.trim()) setSalt(freshSalt);

      const bundle = await encryptPocEnvelope({
        pocSummary: pocSecret.trim(),
        detailedReport: detailedReport.trim(),
        salt: freshSalt,
        targetBounty: selectedBounty || "unassigned",
        researcherHandle: handle.trim() || "whitehat",
        severity,
      });
      setE2eBundle(bundle);
      setEncryptedUri(bundle.envelope.aegisUri);
      // Preload verifier drawer so judges can verify live decryption in 1 click
      setVerifyEnvelopeJson(JSON.stringify(bundle.envelope, null, 2));
      setVerifyKeyInput(bundle.decryptionKeyB64);
      setDecryptedPreview(null);
      setDecryptErr(null);
    } catch (err: any) {
      setStatusMsg({
        type: "err",
        text: err?.message || "WebCrypto AES-256-GCM encryption failed.",
      });
    } finally {
      setEncrypting(false);
    }
  }

  async function handleVerifyDecrypt() {
    setDecryptErr(null);
    setDecryptedPreview(null);
    try {
      const env = JSON.parse(verifyEnvelopeJson) as AegisEncryptedEnvelope;
      const result = await decryptPocEnvelope(env, verifyKeyInput);
      setDecryptedPreview(result);
    } catch (err: any) {
      setDecryptErr(err?.message || "Decryption failed (wrong AES-256 key or corrupted envelope).");
    }
  }

  async function handleCreateBounty(e: React.FormEvent) {
    e.preventDefault();
    if (!publicKey) {
      setStatusMsg({ type: "err", text: "Connect your Solana Devnet wallet first (top right)." });
      return;
    }
    const rewardLamports = Math.round(Number(rewardSol) * LAMPORTS_PER_SOL);
    const maxPayoutLamports = Math.round(Number(maxPayoutSol) * LAMPORTS_PER_SOL);
    if (!Number.isFinite(rewardLamports) || !Number.isFinite(maxPayoutLamports)) {
      setStatusMsg({ type: "err", text: "Enter valid numeric SOL amounts." });
      return;
    }
    if (rewardLamports < SOLANA_RENT_EXEMPT_MIN_LAMPORTS) {
      setStatusMsg({
        type: "err",
        text: `Minimum deposit is ${(SOLANA_RENT_EXEMPT_MIN_LAMPORTS / LAMPORTS_PER_SOL).toFixed(4)} SOL (Solana rent-exempt minimum).`,
      });
      return;
    }
    if (maxPayoutLamports <= 0 || maxPayoutLamports > rewardLamports) {
      setStatusMsg({
        type: "err",
        text: "Max payout per bug must be greater than 0 and <= total escrow deposit.",
      });
      return;
    }

    setBusy("create");
    setStatusMsg(null);
    try {
      const bountyId = BigInt(Date.now());
      const { ix, bountyPda } = await buildCreateBountyIx({
        authority: publicKey,
        bountyId,
        targetName: targetName.trim(),
        scopeUri: scopeUri.trim(),
        rewardLamports,
        maxPayoutPerFinding: maxPayoutLamports,
      });

      const tx = new Transaction().add(ix);
      const sig = await sendTransaction(tx, connection);
      await connection.confirmTransaction(sig, "confirmed");

      setSelectedBounty(bountyPda.toBase58());
      setStatusMsg({
        type: "ok",
        text: `Rent-safe Bounty Vault PDA created & funded with ${rewardSol} SOL on Solana Devnet!`,
        tx: sig,
      });
      await onRefresh();
    } catch (err: any) {
      setStatusMsg({ type: "err", text: err?.message || "Failed to create bounty vault." });
    } finally {
      setBusy(null);
    }
  }

  async function handleSubmitCommit(e: React.FormEvent) {
    e.preventDefault();
    if (!publicKey) {
      setStatusMsg({ type: "err", text: "Connect your Solana Devnet wallet first." });
      return;
    }
    if (!selectedBounty) {
      setStatusMsg({ type: "err", text: "Create or select an active Bounty Vault first." });
      return;
    }
    setBusy("commit");
    setStatusMsg(null);
    try {
      const trimmedPoc = pocSecret.trim();
      const trimmedSalt = salt.trim();

      // Auto-encrypt via AES-256-GCM if researcher hasn't clicked Encrypt yet
      let activeBundle = e2eBundle;
      let uriToCommit = encryptedUri.trim();
      if (!activeBundle || uriToCommit.includes("pending-client-encryption")) {
        activeBundle = await encryptPocEnvelope({
          pocSummary: trimmedPoc,
          detailedReport: detailedReport.trim(),
          salt: trimmedSalt,
          targetBounty: selectedBounty,
          researcherHandle: handle.trim() || "whitehat",
          severity,
        });
        setE2eBundle(activeBundle);
        uriToCommit = activeBundle.envelope.aegisUri;
        setEncryptedUri(uriToCommit);
        setVerifyEnvelopeJson(JSON.stringify(activeBundle.envelope, null, 2));
        setVerifyKeyInput(activeBundle.decryptionKeyB64);
      }

      const commitHash = await sha256Text(`${trimmedPoc}||${trimmedSalt}`);
      const findingId = BigInt(Date.now());

      const { ix, findingPda } = await buildSubmitFindingCommitIx({
        researcher: publicKey,
        bountyPda: new PublicKey(selectedBounty),
        findingId,
        commitHash,
        severity,
        encryptedReportUri: uriToCommit,
        researcherHandle: handle.trim() || "whitehat",
      });

      const tx = new Transaction().add(ix);
      const sig = await sendTransaction(tx, connection);
      await connection.confirmTransaction(sig, "confirmed");

      const receipt: LocalCommitReceipt = {
        findingAddress: findingPda.toBase58(),
        bountyAddress: selectedBounty,
        pocSummary: trimmedPoc,
        salt: trimmedSalt,
        commitHashHex: bytesToHex(commitHash),
        aegisUri: uriToCommit,
        decryptionKeyB64: activeBundle?.decryptionKeyB64,
        savedAt: new Date().toISOString(),
      };
      saveReceipt(receipt);
      setSavedReceipts(loadReceipts());
      if (onClearEscalation) onClearEscalation();

      setStatusMsg({
        type: "ok",
        text: `AES-256-GCM Encrypted PoC + SHA-256 Commit sealed on-chain! Receipt saved locally for reveal.`,
        tx: sig,
        receipt,
      });
      await onRefresh();
    } catch (err: any) {
      setStatusMsg({ type: "err", text: err?.message || "Failed to submit commit-reveal finding." });
    } finally {
      setBusy(null);
    }
  }

  function openRevealPanel(finding: OnChainFindingReport) {
    const rec = savedReceipts[finding.address];
    setRevealPoc(rec?.pocSummary || pocSecret);
    setRevealSalt(rec?.salt || salt);
    setRevealOpenFor(finding.address);
  }

  async function handleRevealOnChain(finding: OnChainFindingReport) {
    if (!publicKey) return;
    setBusy(`reveal-${finding.address}`);
    setStatusMsg(null);
    try {
      const ix = await buildRevealFindingIx({
        researcher: publicKey,
        findingPda: new PublicKey(finding.address),
        pocSummary: revealPoc.trim(),
        salt: revealSalt.trim(),
      });
      const tx = new Transaction().add(ix);
      const sig = await sendTransaction(tx, connection);
      await connection.confirmTransaction(sig, "confirmed");

      setRevealOpenFor(null);
      setStatusMsg({
        type: "ok",
        text: `On-chain SHA-256 verification PASSED! Finding transitioned from Committed → Revealed.`,
        tx: sig,
      });
      await onRefresh();
    } catch (err: any) {
      setStatusMsg({
        type: "err",
        text: err?.message || "Reveal failed (SHA-256 mismatch or wrong researcher wallet).",
      });
    } finally {
      setBusy(null);
    }
  }

  async function handleApproveFinding(finding: OnChainFindingReport, bounty: OnChainBountyVault) {
    if (!publicKey) {
      setStatusMsg({ type: "err", text: "Connect the vault authority wallet to approve payout." });
      return;
    }
    const defaultSol = Math.min(bounty.maxPayoutPerFinding, bounty.remainingPool) / LAMPORTS_PER_SOL;
    const requestedSol = Number(payoutInputs[finding.address] ?? defaultSol.toFixed(4));
    const payoutLamports = Math.round(requestedSol * LAMPORTS_PER_SOL);
    const remAfter = bounty.remainingPool - payoutLamports;
    if (!Number.isFinite(payoutLamports) || payoutLamports <= 0) {
      setStatusMsg({ type: "err", text: "Enter a valid payout amount > 0 SOL." });
      return;
    }
    if (remAfter > 0 && remAfter < SOLANA_RENT_EXEMPT_MIN_LAMPORTS) {
      setStatusMsg({
        type: "err",
        text: `Rent-exemption guard: remaining vault balance (${(remAfter / LAMPORTS_PER_SOL).toFixed(5)} SOL) must be either 0 SOL or >= 0.000891 SOL.`,
      });
      return;
    }

    setBusy(`approve-${finding.address}`);
    setStatusMsg(null);
    try {
      const ix = await buildApproveAndPayoutIx({
        authority: publicKey,
        bountyPda: new PublicKey(bounty.address),
        findingPda: new PublicKey(finding.address),
        researcher: new PublicKey(finding.researcher),
        payoutLamports,
      });

      const tx = new Transaction().add(ix);
      const sig = await sendTransaction(tx, connection);
      await connection.confirmTransaction(sig, "confirmed");

      setStatusMsg({
        type: "ok",
        text: `Approved! Released ${(payoutLamports / LAMPORTS_PER_SOL).toFixed(4)} SOL from PDA Escrow to researcher.`,
        tx: sig,
      });
      await onRefresh();
    } catch (err: any) {
      setStatusMsg({
        type: "err",
        text: err?.message || "Approval failed (check rent-exemption remainder or authority).",
      });
    } finally {
      setBusy(null);
    }
  }

  async function handleRejectFinding(finding: OnChainFindingReport, bounty: OnChainBountyVault) {
    if (!publicKey) return;
    setBusy(`reject-${finding.address}`);
    setStatusMsg(null);
    try {
      const ix = await buildRejectFindingIx({
        authority: publicKey,
        bountyPda: new PublicKey(bounty.address),
        findingPda: new PublicKey(finding.address),
      });
      const tx = new Transaction().add(ix);
      const sig = await sendTransaction(tx, connection);
      await connection.confirmTransaction(sig, "confirmed");

      setStatusMsg({
        type: "ok",
        text:
          finding.status === "Revealed"
            ? "Finding rejected — 24h Anti-Poaching Cooldown activated on vault so researcher may raise arbitration."
            : "Finding marked Rejected on-chain and pending_findings decremented.",
        tx: sig,
      });
      await onRefresh();
    } catch (err: any) {
      setStatusMsg({ type: "err", text: err?.message || "Reject failed." });
    } finally {
      setBusy(null);
    }
  }

  async function handleRaiseDispute(finding: OnChainFindingReport, bounty: OnChainBountyVault) {
    if (!publicKey) return;
    setBusy(`dispute-${finding.address}`);
    setStatusMsg(null);
    try {
      const { ix } = await buildRaiseDisputeIx({
        researcher: publicKey,
        bountyPda: new PublicKey(bounty.address),
        findingPda: new PublicKey(finding.address),
        reasonUri: `aegis-dispute://finding/${finding.address.slice(0, 12)}`,
      });
      const tx = new Transaction().add(ix);
      const sig = await sendTransaction(tx, connection);
      await connection.confirmTransaction(sig, "confirmed");

      setStatusMsg({
        type: "ok",
        text: "Dispute raised on-chain! Escrow pool re-locked pending independent AEGIS Oracle arbitration.",
        tx: sig,
      });
      await onRefresh();
    } catch (err: any) {
      setStatusMsg({
        type: "err",
        text: err?.message || "Failed to raise dispute (must be researcher within 7-day window).",
      });
    } finally {
      setBusy(null);
    }
  }

  async function handleCloseBounty(bounty: OnChainBountyVault) {
    if (!publicKey) return;
    setBusy(`close-${bounty.address}`);
    setStatusMsg(null);
    try {
      const ix = await buildCloseBountyIx({
        authority: publicKey,
        bountyPda: new PublicKey(bounty.address),
      });
      const tx = new Transaction().add(ix);
      const sig = await sendTransaction(tx, connection);
      await connection.confirmTransaction(sig, "confirmed");

      setStatusMsg({
        type: "ok",
        text: `Vault closed cleanly and 100% of remaining escrow SOL swept back to authority!`,
        tx: sig,
      });
      await onRefresh();
    } catch (err: any) {
      setStatusMsg({
        type: "err",
        text: err?.message || "Close failed (resolve all pending findings first).",
      });
    } finally {
      setBusy(null);
    }
  }

  async function handleTopUp(bounty: OnChainBountyVault) {
    if (!publicKey) {
      setStatusMsg({ type: "err", text: "Connect your wallet to top up this vault." });
      return;
    }
    setBusy(`topup-${bounty.address}`);
    setStatusMsg(null);
    try {
      const amount = Math.round(0.02 * LAMPORTS_PER_SOL);
      const ix = await buildTopUpBountyIx({
        funder: publicKey,
        bountyPda: new PublicKey(bounty.address),
        amountLamports: amount,
      });
      const tx = new Transaction().add(ix);
      const sig = await sendTransaction(tx, connection);
      await connection.confirmTransaction(sig, "confirmed");
      setStatusMsg({
        type: "ok",
        text: `Topped up ${bounty.targetName} with +0.02 SOL on Devnet!`,
        tx: sig,
      });
      await onRefresh();
    } catch (err: any) {
      setStatusMsg({ type: "err", text: err?.message || "Top-up failed." });
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-6">
      {escalatedFinding && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-teal-400/35 bg-teal-500/[0.08] px-4 py-3 text-xs text-teal-100">
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 shrink-0 text-teal-300" />
            <span>
              Escalated from x402 Scanner:{" "}
              <strong className="font-mono text-white">{escalatedFinding.ruleId}</strong> —{" "}
              {escalatedFinding.title}. Ready to encrypt with AES-256-GCM & seal on-chain.
            </span>
          </div>
          {onClearEscalation && (
            <button
              type="button"
              onClick={onClearEscalation}
              className="font-mono text-[11px] text-slate-400 hover:text-white"
            >
              Dismiss
            </button>
          )}
        </div>
      )}

      {statusMsg && (
        <div
          className={`flex flex-wrap items-center justify-between gap-3 rounded-xl border p-4 text-sm ${
            statusMsg.type === "ok"
              ? "border-teal-500/40 bg-teal-500/10 text-teal-100"
              : "border-rose-500/40 bg-rose-500/10 text-rose-200"
          }`}
        >
          <div className="flex items-center gap-2">
            {statusMsg.type === "ok" ? (
              <CheckCircle2 className="h-4 w-4 shrink-0 text-teal-300" />
            ) : (
              <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
            )}
            <span>{statusMsg.text}</span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {statusMsg.receipt && (
              <button
                onClick={() =>
                  triggerJsonDownload(
                    `aegis-commit-receipt-${statusMsg.receipt!.findingAddress.slice(0, 8)}.json`,
                    statusMsg.receipt
                  )
                }
                className="inline-flex items-center gap-1 rounded-md border border-slate-500/50 bg-slate-900 px-2.5 py-1 font-mono text-xs text-slate-200 hover:border-teal-400"
              >
                <Download className="h-3 w-3" /> Save Secret Receipt (.json)
              </button>
            )}
            {statusMsg.tx && (
              <a
                href={`https://explorer.solana.com/tx/${statusMsg.tx}?cluster=devnet`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 rounded-md border border-teal-500/40 bg-teal-950/60 px-2.5 py-1 font-mono text-xs text-teal-300 hover:underline"
              >
                Solana Explorer
                <ExternalLink className="h-3 w-3" />
              </a>
            )}
          </div>
        </div>
      )}

      <ProtocolStepper
        steps={[
          {
            title: "AES-256-GCM",
            sub: e2eBundle ? "Payload Sealed" : "Browser Encrypt",
            status: e2eBundle ? "done" : "active",
          },
          {
            title: "SHA-256 Commit",
            sub: "Zero-Knowledge Lock",
            status: e2eBundle ? "active" : "idle",
          },
          {
            title: "On-Chain Escrow",
            sub: "24h Anti-Poach Guard",
            status: "done",
          },
        ]}
      />

      {/* Action Forms Grid */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Form 1: Create Bounty Vault */}
        <MachinedPanel variant="steel" className="p-5">
          <form onSubmit={handleCreateBounty}>
            <div className="mb-4 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="rounded-lg border border-slate-600/30 bg-slate-800/60 p-2 text-slate-200">
                  <Lock className="h-4 w-4" />
                </div>
                <h3 className="font-display font-semibold text-white">1. Launch Bounty Vault</h3>
              </div>
              <span className="rounded border border-slate-600/40 bg-slate-800/50 px-2 py-0.5 font-mono text-[10px] text-slate-300">
                create_bounty
              </span>
            </div>

            <div className="space-y-3">
              <div>
                <label className="mb-1 block text-xs font-medium text-slate-300">
                  Protocol / Target Name
                </label>
                <input
                  value={targetName}
                  onChange={(e) => setTargetName(e.target.value)}
                  required
                  maxLength={64}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-teal-400"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-slate-300">
                  Scope Repository / Docs URL
                </label>
                <input
                  value={scopeUri}
                  onChange={(e) => setScopeUri(e.target.value)}
                  required
                  maxLength={200}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-teal-400"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block text-xs font-medium text-slate-300">
                    Escrow Deposit (SOL)
                  </label>
                  <input
                    type="number"
                    step="0.005"
                    min="0.002"
                    value={rewardSol}
                    onChange={(e) => setRewardSol(e.target.value)}
                    required
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-white outline-none focus:border-teal-400"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-slate-300">
                    Max Payout / Bug (SOL)
                  </label>
                  <input
                    type="number"
                    step="0.005"
                    min="0.001"
                    value={maxPayoutSol}
                    onChange={(e) => setMaxPayoutSol(e.target.value)}
                    required
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-white outline-none focus:border-teal-400"
                  />
                </div>
              </div>
              <button
                type="submit"
                disabled={busy === "create"}
                className="mt-2 flex w-full items-center justify-center gap-2 rounded-xl border border-slate-400/25 bg-gradient-to-r from-slate-200 to-slate-300 px-4 py-2.5 text-sm font-bold text-slate-950 transition hover:brightness-105 disabled:opacity-50"
              >
                <Plus className="h-4 w-4" />
                {busy === "create" ? "Locking SOL in PDA Escrow..." : "Deploy Bounty Vault on Devnet"}
              </button>
            </div>
          </form>

          {/* Live E2E AES-256-GCM Decryption & SHA-256 Verifier Drawer */}
          <div className="mt-5 border-t border-slate-800/80 pt-4">
            <button
              type="button"
              onClick={() => setVerifierOpen((v) => !v)}
              className="flex w-full items-center justify-between text-left text-xs font-medium text-slate-300 hover:text-white"
            >
              <span className="inline-flex items-center gap-2">
                <Unlock className="h-3.5 w-3.5 text-teal-300" />
                Zero-Trust AES-256-GCM Envelope Decryption Verifier
              </span>
              <span className="font-mono text-[10px] text-slate-500">
                {verifierOpen ? "HIDE" : "OPEN"}
              </span>
            </button>

            {verifierOpen && (
              <div className="mt-3 space-y-2.5 rounded-xl border border-slate-800 bg-[#05080f] p-3">
                <textarea
                  rows={4}
                  value={verifyEnvelopeJson}
                  onChange={(e) => setVerifyEnvelopeJson(e.target.value)}
                  placeholder="Paste .aegis.enc.json encrypted envelope..."
                  className="w-full rounded-lg border border-slate-800 bg-black/50 p-2 font-mono text-[10px] text-slate-300 outline-none focus:border-teal-400"
                />
                <div className="flex gap-2">
                  <input
                    value={verifyKeyInput}
                    onChange={(e) => setVerifyKeyInput(e.target.value)}
                    placeholder="Base64 256-bit AES-GCM decryption key"
                    className="flex-1 rounded-lg border border-slate-800 bg-black/50 px-2.5 py-1.5 font-mono text-[11px] text-teal-200 outline-none focus:border-teal-400"
                  />
                  <button
                    type="button"
                    onClick={handleVerifyDecrypt}
                    className="rounded-lg bg-teal-400 px-3 py-1.5 font-mono text-[11px] font-bold text-slate-950 hover:bg-teal-300"
                  >
                    Decrypt & Verify
                  </button>
                </div>

                {decryptErr && (
                  <div className="rounded-lg border border-rose-500/35 bg-rose-500/10 px-2.5 py-1.5 font-mono text-[11px] text-rose-200">
                    {decryptErr}
                  </div>
                )}

                {decryptedPreview && (
                  <div className="aegis-card-safe space-y-1 rounded-lg p-2.5 font-mono text-[11px]">
                    <div className="flex items-center justify-between text-teal-300">
                      <span className="font-bold">AES-256-GCM DECRYPTED</span>
                      <span>
                        {decryptedPreview.integrityVerified
                          ? "SHA-256 COMMIT MATCH ✓"
                          : "COMMIT MISMATCH"}
                      </span>
                    </div>
                    <div className="text-slate-200">{decryptedPreview.pocSummary}</div>
                    <div className="text-[10px] text-slate-400">
                      Salt: {decryptedPreview.salt} · Sealed: {decryptedPreview.sealedAt}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </MachinedPanel>

        {/* Form 2: Submit Finding (AES-256-GCM E2E + SHA-256 Commit-Reveal) */}
        <MachinedPanel variant="mint" delay={0.07} className="p-5">
          <form onSubmit={handleSubmitCommit}>
            <div className="mb-4 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="rounded-lg border border-teal-400/25 bg-teal-400/10 p-2 text-teal-300">
                  <Hash className="h-4 w-4" />
                </div>
                <h3 className="font-display font-semibold text-white">
                  2. Seal Vulnerability Commit
                </h3>
              </div>
              <span className="rounded border border-teal-400/25 bg-teal-400/10 px-2 py-0.5 font-mono text-[10px] text-teal-300">
                AES-GCM · SHA-256
              </span>
            </div>

            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block text-xs font-medium text-slate-300">
                    Target Vault
                  </label>
                  <select
                    value={selectedBounty}
                    onChange={(e) => setSelectedBounty(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white outline-none focus:border-teal-400"
                  >
                    {activeBounties.length === 0 && (
                      <option value="">No active vaults — create one left</option>
                    )}
                    {activeBounties.map((b) => (
                      <option key={b.address} value={b.address}>
                        {b.targetName} ({(b.remainingPool / LAMPORTS_PER_SOL).toFixed(3)} SOL)
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-slate-300">
                    Whitehat Handle & Severity
                  </label>
                  <div className="flex gap-2">
                    <input
                      value={handle}
                      onChange={(e) => setHandle(e.target.value)}
                      placeholder="handle"
                      maxLength={32}
                      className="w-1/2 rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-2 font-mono text-xs text-white outline-none focus:border-teal-400"
                    />
                    <select
                      value={severity}
                      onChange={(e) => setSeverity(Number(e.target.value))}
                      className="w-1/2 rounded-lg border border-slate-700 bg-slate-950 px-2 py-2 text-xs text-white outline-none focus:border-teal-400"
                    >
                      <option value={4}>Critical (120 pts)</option>
                      <option value={3}>High (60 pts)</option>
                      <option value={2}>Medium (25 pts)</option>
                      <option value={1}>Low (10 pts)</option>
                    </select>
                  </div>
                </div>
              </div>

              <div>
                <div className="mb-1 flex items-center justify-between">
                  <label className="text-xs font-medium text-slate-300">PoC Summary</label>
                  <span className="text-[10px] text-slate-500">{pocSecret.length}/160</span>
                </div>
                <textarea
                  rows={2}
                  maxLength={160}
                  value={pocSecret}
                  onChange={(e) => {
                    setPocSecret(e.target.value);
                    setE2eBundle(null);
                  }}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-teal-400"
                />
              </div>

              <div>
                <label className="mb-1 block text-xs font-medium text-slate-300">
                  Exploit Payload (AES-256-GCM)
                </label>
                <textarea
                  rows={2}
                  value={detailedReport}
                  onChange={(e) => {
                    setDetailedReport(e.target.value);
                    setE2eBundle(null);
                  }}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-[11px] text-slate-300 outline-none focus:border-teal-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="mb-1 flex items-center justify-between">
                    <label className="text-xs font-medium text-slate-300">CSPRNG Salt</label>
                    <button
                      type="button"
                      onClick={() => {
                        setSalt(generateSecureSalt());
                        setE2eBundle(null);
                      }}
                      className="font-mono text-[10px] text-teal-300 hover:underline"
                    >
                      Randomize
                    </button>
                  </div>
                  <input
                    value={salt}
                    maxLength={64}
                    onChange={(e) => {
                      setSalt(e.target.value);
                      setE2eBundle(null);
                    }}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-xs text-slate-300 outline-none focus:border-teal-400"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-slate-300">
                    Content-Addressed Encrypted URI
                  </label>
                  <input
                    value={encryptedUri}
                    onChange={(e) => setEncryptedUri(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 font-mono text-[11px] text-teal-200 outline-none focus:border-teal-400"
                  />
                </div>
              </div>

              {/* Client-side AES-256-GCM Encryption Controls */}
              <div className="aegis-subbox space-y-2 rounded-lg p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    <div className="text-[10px] uppercase tracking-wider text-slate-400">
                      On-Chain SHA-256 Commit Digest
                    </div>
                    <div className="truncate font-mono text-xs text-teal-300">
                      0x{liveHashHex || "..."}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={handleEncryptClientSide}
                    disabled={encrypting}
                    className="aegis-btn-secondary inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-mono text-[11px] font-semibold disabled:opacity-50"
                  >
                    <KeyRound className="h-3.5 w-3.5 text-teal-300" />
                    {encrypting
                      ? "Encrypting..."
                      : e2eBundle
                      ? "Re-Encrypt AES-256-GCM"
                      : "Encrypt PoC (AES-256-GCM)"}
                  </button>
                </div>

                {e2eBundle && (
                  <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-800 pt-2 font-mono text-[10px]">
                    <span className="text-teal-300">
                      Encrypted · SHA256: {e2eBundle.envelope.envelopeSha256.slice(0, 14)}...
                    </span>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() =>
                          triggerJsonDownload(
                            `aegis-poc-${e2eBundle.envelope.envelopeSha256.slice(0, 8)}.aegis.enc.json`,
                            e2eBundle.envelope
                          )
                        }
                        className="inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-900 px-2 py-0.5 text-slate-200 hover:border-teal-400"
                      >
                        <Download className="h-2.5 w-2.5" /> .enc.json
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          navigator.clipboard.writeText(e2eBundle.decryptionKeyB64);
                          setCopiedKey(true);
                          setTimeout(() => setCopiedKey(false), 1800);
                        }}
                        className="inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-900 px-2 py-0.5 text-violet-200 hover:border-violet-400"
                      >
                        {copiedKey ? (
                          <Check className="h-2.5 w-2.5 text-teal-300" />
                        ) : (
                          <Copy className="h-2.5 w-2.5" />
                        )}
                        {copiedKey ? "Key Copied" : "Copy AES Key"}
                      </button>
                      <button
                        type="button"
                        onClick={() => setVerifierOpen(true)}
                        className="rounded border border-teal-500/35 bg-teal-500/10 px-2 py-0.5 text-teal-300 hover:bg-teal-500/20"
                      >
                        Test Decrypt ↗
                      </button>
                    </div>
                  </div>
                )}
              </div>

              <button
                type="submit"
                disabled={busy === "commit" || activeBounties.length === 0}
                className="flex w-full items-center justify-center gap-2 rounded-xl bg-teal-400 px-4 py-2.5 text-sm font-bold text-slate-950 transition hover:bg-teal-300 disabled:opacity-50"
              >
                <Send className="h-4 w-4" />
                {busy === "commit"
                  ? "Encrypting & Sealing Commit on Solana..."
                  : "Seal Encrypted Vulnerability Commit On-Chain"}
              </button>
            </div>
          </form>
        </MachinedPanel>
      </div>

      {/* Live On-Chain Vaults & Full Lifecycle Controls */}
      <MachinedPanel variant="titanium" delay={0.12} className="p-5">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-teal-300" />
            <h3 className="font-display text-base font-semibold text-white">
              Live On-Chain Bounty Vaults ({bounties.length})
            </h3>
          </div>
          <button
            onClick={() => onRefresh()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-300 hover:border-slate-500 hover:text-white"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Sync Devnet
          </button>
        </div>

        {bounties.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-800 p-8 text-center text-sm text-slate-400">
            No live v2 Bounty Vault PDAs found yet. Launch a vault above!
          </div>
        ) : (
          <div className="space-y-4">
            {bounties.map((b) => {
              const vaultFindings = findings.filter((f) => f.bounty === b.address);
              const isAuthority = publicKey && publicKey.toBase58() === b.authority;
              const cooldownActive =
                Boolean(b.cooldownUnlockAt) && (b.cooldownUnlockAt || 0) * 1000 > Date.now();
              const canClose = b.isActive && isAuthority && b.pendingFindings === 0 && !cooldownActive;

              return (
                <div key={b.address} className="aegis-subbox rounded-xl p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <h4 className="font-display font-semibold text-white">{b.targetName}</h4>
                        <span
                          className={`rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold ${
                            b.isActive
                              ? "bg-teal-500/15 text-teal-300"
                              : "bg-slate-700/40 text-slate-400"
                          }`}
                        >
                          {b.isActive ? "ACTIVE ESCROW" : "CLOSED"}
                        </span>
                        {b.pendingFindings > 0 && (
                          <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] text-amber-300">
                            ANTI-RUG LOCK ({b.pendingFindings} PENDING)
                          </span>
                        )}
                        {cooldownActive && (
                          <span className="rounded-full border border-rose-500/35 bg-rose-500/10 px-2 py-0.5 font-mono text-[10px] text-rose-200">
                            24H ANTI-POACH COOLDOWN
                          </span>
                        )}
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-3 font-mono text-[11px] text-slate-400">
                        <a
                          href={`https://explorer.solana.com/address/${b.address}?cluster=devnet`}
                          target="_blank"
                          rel="noreferrer"
                          className="hover:text-teal-300 hover:underline"
                        >
                          Vault PDA: {b.address.slice(0, 8)}...{b.address.slice(-6)}
                        </a>
                        <span>·</span>
                        <a
                          href={`https://explorer.solana.com/address/${b.escrowAddress}?cluster=devnet`}
                          target="_blank"
                          rel="noreferrer"
                          className="hover:text-violet-300 hover:underline"
                        >
                          SOL Escrow: {b.escrowAddress.slice(0, 8)}...{b.escrowAddress.slice(-6)}
                        </a>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2.5">
                      <div className="text-right">
                        <div className="font-mono text-lg font-bold text-teal-300">
                          {(b.remainingPool / LAMPORTS_PER_SOL).toFixed(4)} SOL
                        </div>
                        <div className="text-[11px] text-slate-400">
                          Max/bug: {(b.maxPayoutPerFinding / LAMPORTS_PER_SOL).toFixed(3)} SOL
                        </div>
                      </div>
                      {b.isActive && (
                        <button
                          onClick={() => handleTopUp(b)}
                          disabled={busy === `topup-${b.address}`}
                          className="aegis-btn-secondary inline-flex items-center gap-1 rounded-lg px-2.5 py-1.5 text-xs font-medium disabled:opacity-50"
                        >
                          <Coins className="h-3.5 w-3.5 text-teal-300" />
                          +0.02 SOL
                        </button>
                      )}
                      {b.isActive && isAuthority && (
                        <button
                          onClick={() => handleCloseBounty(b)}
                          disabled={!canClose || busy === `close-${b.address}`}
                          title={
                            b.pendingFindings > 0
                              ? `Blocked by anti-rug-pull guard: resolve ${b.pendingFindings} pending finding(s) before closing.`
                              : "Close vault and sweep 100% of remaining SOL back to authority"
                          }
                          className="inline-flex items-center gap-1 rounded-lg border border-rose-500/35 bg-rose-500/10 px-2.5 py-1.5 text-xs font-medium text-rose-200 hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:opacity-40"
                        >
                          <ShieldOff className="h-3.5 w-3.5" />
                          {b.pendingFindings > 0 ? "Close Locked" : "Close Vault"}
                        </button>
                      )}
                    </div>
                  </div>

                  <EscrowCapacityBar
                    remainingLamports={b.remainingPool}
                    totalLamports={b.totalDeposited}
                  />

                  {/* Findings inside this vault */}
                  {vaultFindings.length > 0 && (
                    <div className="mt-4 space-y-2.5 border-t border-slate-800/80 pt-3">
                      <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                        Vulnerability Reports ({vaultFindings.length})
                      </div>
                      {vaultFindings.map((f) => {
                        const sev = SEVERITY_LABELS[f.severity] || SEVERITY_LABELS[2];
                        const isResearcher = publicKey && publicKey.toBase58() === f.researcher;
                        const isPending =
                          f.status === "Committed" ||
                          f.status === "Revealed" ||
                          f.status === "Disputed";
                        const defaultPaySol = (
                          Math.min(b.maxPayoutPerFinding, b.remainingPool) / LAMPORTS_PER_SOL
                        ).toFixed(4);

                        return (
                          <div
                            key={f.address}
                            className="rounded-lg border border-slate-800 bg-slate-900/70 p-3"
                          >
                            <div className="flex flex-wrap items-center justify-between gap-3">
                              <div className="min-w-0 flex-1">
                                <div className="flex flex-wrap items-center gap-2">
                                  <span
                                    className={`rounded border px-1.5 py-0.5 font-mono text-[10px] font-bold ${sev.color}`}
                                  >
                                    {sev.label}
                                  </span>
                                  <span className="font-mono text-xs text-slate-200">
                                    Commit: 0x{f.commitHashHex.slice(0, 18)}...
                                  </span>
                                  <span
                                    className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold ${
                                      f.status === "Approved"
                                        ? "bg-teal-500/15 text-teal-300"
                                        : f.status === "Revealed"
                                        ? "bg-violet-500/20 text-violet-200"
                                        : f.status === "Disputed"
                                        ? "border border-amber-400/40 bg-amber-500/15 text-amber-200"
                                        : f.status === "Rejected"
                                        ? "bg-rose-500/15 text-rose-300"
                                        : "bg-amber-500/15 text-amber-300"
                                    }`}
                                  >
                                    {f.status.toUpperCase()}
                                  </span>
                                </div>
                                <div className="mt-1 font-mono text-[11px] text-slate-400">
                                  Whitehat: {f.researcher.slice(0, 8)}...{f.researcher.slice(-6)} ·{" "}
                                  {f.encryptedReportUri}
                                </div>
                                {f.revealedSummary && (
                                  <div className="mt-1.5 rounded border border-violet-500/25 bg-violet-950/25 px-2.5 py-1.5 font-mono text-[11px] text-violet-200">
                                    SHA-256 Verified On-Chain Reveal: &ldquo;{f.revealedSummary}&rdquo;
                                  </div>
                                )}
                              </div>

                              <div className="flex flex-wrap items-center gap-2">
                                {f.status === "Committed" && isResearcher && (
                                  <button
                                    onClick={() => openRevealPanel(f)}
                                    className="inline-flex items-center gap-1 rounded-lg border border-violet-400/50 bg-violet-500/15 px-2.5 py-1.5 text-xs font-semibold text-violet-200 hover:bg-violet-500/25"
                                  >
                                    <Eye className="h-3.5 w-3.5" />
                                    Reveal PoC
                                  </button>
                                )}

                                {f.status === "Rejected" && f.revealedSummary && isResearcher && (
                                  <button
                                    onClick={() => handleRaiseDispute(f, b)}
                                    disabled={busy === `dispute-${f.address}`}
                                    className="inline-flex items-center gap-1 rounded-lg border border-amber-400/50 bg-amber-500/15 px-2.5 py-1.5 text-xs font-semibold text-amber-200 hover:bg-amber-500/25 disabled:opacity-50"
                                  >
                                    <AlertTriangle className="h-3.5 w-3.5" />
                                    {busy === `dispute-${f.address}`
                                      ? "Freezing Escrow..."
                                      : "Raise Arbitration Dispute"}
                                  </button>
                                )}

                                {isPending && isAuthority && (
                                  <>
                                    <input
                                      type="number"
                                      step="0.001"
                                      min="0.001"
                                      value={payoutInputs[f.address] ?? defaultPaySol}
                                      onChange={(e) =>
                                        setPayoutInputs((prev) => ({
                                          ...prev,
                                          [f.address]: e.target.value,
                                        }))
                                      }
                                      className="w-24 rounded-lg border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-xs text-white outline-none focus:border-teal-400"
                                      title="Custom payout amount in SOL"
                                    />
                                    <button
                                      onClick={() => handleApproveFinding(f, b)}
                                      disabled={busy === `approve-${f.address}`}
                                      className="rounded-lg bg-teal-400 px-3 py-1.5 text-xs font-bold text-slate-950 hover:bg-teal-300 disabled:opacity-50"
                                    >
                                      {busy === `approve-${f.address}` ? "Paying..." : "Approve & Pay"}
                                    </button>
                                    <button
                                      onClick={() => handleRejectFinding(f, b)}
                                      disabled={busy === `reject-${f.address}`}
                                      className="inline-flex items-center gap-1 rounded-lg border border-rose-500/40 bg-rose-500/10 px-2.5 py-1.5 text-xs font-semibold text-rose-200 hover:bg-rose-500/20 disabled:opacity-50"
                                    >
                                      <XCircle className="h-3.5 w-3.5" />
                                      Reject
                                    </button>
                                  </>
                                )}

                                {f.status === "Approved" && (
                                  <span className="font-mono text-xs font-semibold text-teal-300">
                                    Paid {(f.payoutLamports / LAMPORTS_PER_SOL).toFixed(4)} SOL
                                  </span>
                                )}
                              </div>
                            </div>

                            {/* Inline On-Chain SHA-256 Reveal Form */}
                            {revealOpenFor === f.address && (
                              <div className="mt-3 space-y-2 rounded-lg border border-violet-500/35 bg-slate-950/90 p-3">
                                <div className="font-mono text-[11px] font-semibold text-violet-300">
                                  Cryptographic On-Chain Reveal (`reveal_finding` verifies SHA-256 inside Solana runtime)
                                </div>
                                <input
                                  value={revealPoc}
                                  onChange={(e) => setRevealPoc(e.target.value)}
                                  placeholder="Exact PoC Summary committed earlier"
                                  className="w-full rounded border border-slate-700 bg-black/50 px-2.5 py-1.5 font-mono text-xs text-white"
                                />
                                <div className="flex gap-2">
                                  <input
                                    value={revealSalt}
                                    onChange={(e) => setRevealSalt(e.target.value)}
                                    placeholder="Exact Salt"
                                    className="flex-1 rounded border border-slate-700 bg-black/50 px-2.5 py-1.5 font-mono text-xs text-white"
                                  />
                                  <button
                                    onClick={() => handleRevealOnChain(f)}
                                    disabled={busy === `reveal-${f.address}`}
                                    className="aegis-btn-primary rounded-lg px-3.5 py-1.5 text-xs font-bold disabled:opacity-50"
                                  >
                                    {busy === `reveal-${f.address}`
                                      ? "Verifying SHA-256..."
                                      : "Verify & Reveal On-Chain"}
                                  </button>
                                  <button
                                    onClick={() => setRevealOpenFor(null)}
                                    className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-400 hover:text-white"
                                  >
                                    Cancel
                                  </button>
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </MachinedPanel>
    </div>
  );
}
