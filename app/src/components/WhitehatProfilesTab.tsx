"use client";

import React, { useState } from "react";
import { LAMPORTS_PER_SOL } from "@solana/web3.js";
import {
  Award,
  ShieldCheck,
  ExternalLink,
  UserCheck,
  BadgeCheck,
  ShieldAlert,
  Copy,
  Check,
} from "lucide-react";
import { MachinedPanel } from "@/components/MachinedPanel";
import type {
  OnChainAuditAttestation,
  OnChainWhitehatProfile,
} from "@/lib/solana/aegisProgram";

interface WhitehatProfilesTabProps {
  whitehats: OnChainWhitehatProfile[];
  attestations: OnChainAuditAttestation[];
}

export function WhitehatProfilesTab({ whitehats, attestations }: WhitehatProfilesTabProps) {
  const [copiedBadgeId, setCopiedBadgeId] = useState<string | null>(null);

  function copyBadgeMarkdown(programId: string) {
    const origin =
      typeof window !== "undefined" ? window.location.origin : "https://aegis-solana.vercel.app";
    const md = `[![AEGIS On-Chain Audit](${origin}/api/badge/${programId})](https://explorer.solana.com/address/${programId}?cluster=devnet)`;
    navigator.clipboard.writeText(md);
    setCopiedBadgeId(programId);
    setTimeout(() => setCopiedBadgeId(null), 2000);
  }

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      {/* On-Chain Whitehat Reputation Leaderboard */}
      <MachinedPanel variant="solana" className="p-5">
        <div className="mb-4 flex items-center gap-2.5">
          <div className="rounded-lg bg-amber-500/15 p-2 text-amber-300">
            <Award className="h-4 w-4" />
          </div>
          <div>
            <h3 className="font-display font-semibold text-white">On-Chain Whitehat Leaderboard</h3>
            <p className="text-xs text-slate-400">
              Anti-Sybil Solana PDAs tracking approved bugs & earned SOL
            </p>
          </div>
        </div>

        {whitehats.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-800 p-8 text-center text-xs text-slate-400">
            No WhitehatProfile PDAs recorded yet. Submit a vulnerability commit in the Bounty Vaults
            tab to mint your on-chain researcher identity!
          </div>
        ) : (
          <div className="space-y-3">
            {whitehats.map((w, idx) => (
              <div
                key={w.address}
                className="aegis-subbox flex items-center justify-between rounded-xl p-3.5"
              >
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-violet-500/30 bg-violet-500/10 font-mono text-sm font-bold text-violet-300">
                    #{idx + 1}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <UserCheck className="h-3.5 w-3.5 text-teal-300" />
                      <span className="font-mono text-sm font-bold text-white">@{w.handle}</span>
                    </div>
                    <a
                      href={`https://explorer.solana.com/address/${w.address}?cluster=devnet`}
                      target="_blank"
                      rel="noreferrer"
                      className="font-mono text-[11px] text-slate-400 hover:text-teal-300 hover:underline"
                    >
                      {w.researcher.slice(0, 8)}...{w.researcher.slice(-6)} ·{" "}
                      {w.approvedFindings}/{w.totalSubmissions} approved
                    </a>
                  </div>
                </div>
                <div className="text-right">
                  <div className="font-mono text-sm font-bold text-teal-300">
                    {w.reputationScore} REP
                  </div>
                  <div className="font-mono text-[11px] text-slate-400">
                    {(w.totalEarnedLamports / LAMPORTS_PER_SOL).toFixed(4)} SOL
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </MachinedPanel>

      {/* Verified On-Chain x402 Audit Attestations + Live Embeddable SVG Badges */}
      <MachinedPanel variant="mint" delay={0.07} className="p-5">
        <div className="mb-4 flex items-center gap-2.5">
          <div className="rounded-lg bg-teal-500/15 p-2 text-teal-300">
            <ShieldCheck className="h-4 w-4" />
          </div>
          <div>
            <h3 className="font-display font-semibold text-white">
              On-Chain x402 Audit Attestations
            </h3>
            <p className="text-xs text-slate-400">
              Ed25519Program Sysvar verified · Live SVG badges readable by any GitHub README
            </p>
          </div>
        </div>

        {attestations.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-800 p-8 text-center text-xs text-slate-400">
            No v2 AuditAttestation PDAs sealed yet. Run a scan in the Audit Scanner tab and seal it
            on-chain!
          </div>
        ) : (
          <div className="space-y-3">
            {attestations.map((a) => (
              <div key={a.address} className="aegis-subbox rounded-xl p-3.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`rounded-lg px-2 py-0.5 font-mono text-xs font-black ${
                        a.securityScore >= 85
                          ? "bg-teal-500/15 text-teal-300"
                          : a.securityScore >= 60
                          ? "bg-amber-500/15 text-amber-300"
                          : "bg-rose-500/15 text-rose-300"
                      }`}
                    >
                      SCORE {a.securityScore}/100
                    </span>
                    {a.isVerifiedOracle ? (
                      <span className="inline-flex items-center gap-1 rounded-md border border-teal-400/40 bg-teal-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-teal-200">
                        <BadgeCheck className="h-3 w-3 text-teal-300" />
                        ED25519 ORACLE VERIFIED
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] text-amber-300">
                        <ShieldAlert className="h-3 w-3" />
                        SELF-ATTESTED
                      </span>
                    )}
                  </div>
                  <a
                    href={`https://explorer.solana.com/address/${a.address}?cluster=devnet`}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 font-mono text-[11px] text-violet-300 hover:underline"
                  >
                    PDA <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
                <div className="mt-2 font-mono text-[11px] text-slate-300">
                  Target: {a.targetProgramId.slice(0, 10)}...{a.targetProgramId.slice(-8)}
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-3 font-mono text-[10px] text-slate-400">
                  <span>Code: 0x{a.sourceCodeHashHex.slice(0, 12)}...</span>
                  <span>Report: 0x{a.reportHashHex.slice(0, 12)}...</span>
                  <span className="text-rose-300">{a.criticalCount} Crit</span>
                  <span className="text-orange-300">{a.highCount} High</span>
                  <a
                    href={`https://explorer.solana.com/tx/${a.x402PaymentSig}?cluster=devnet`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-teal-300 hover:underline"
                  >
                    x402 Payment TX ↗
                  </a>
                </div>

                {/* Live On-Chain SVG Trust Badge + README Markdown Copy */}
                <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-slate-800/80 pt-2.5">
                  <a
                    href={`/api/badge/${a.targetProgramId}`}
                    target="_blank"
                    rel="noreferrer"
                    title="Open live on-chain SVG badge"
                  >
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                      src={`/api/badge/${a.targetProgramId}`}
                      alt={`AEGIS on-chain audit badge for ${a.targetProgramId}`}
                      className="h-6"
                    />
                  </a>
                  <button
                    type="button"
                    onClick={() => copyBadgeMarkdown(a.targetProgramId)}
                    className="inline-flex items-center gap-1 rounded-md border border-slate-700/80 bg-slate-900/80 px-2 py-1 font-mono text-[10px] text-slate-300 transition hover:border-teal-400/50 hover:text-white"
                  >
                    {copiedBadgeId === a.targetProgramId ? (
                      <>
                        <Check className="h-3 w-3 text-teal-300" /> Copied README MD
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" /> Copy SVG Badge MD
                      </>
                    )}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </MachinedPanel>
    </div>
  );
}
