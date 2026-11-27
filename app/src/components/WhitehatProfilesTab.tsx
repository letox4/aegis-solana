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
import { ScoreRingGauge } from "@/components/VisualPrimitives";
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
      typeof window !== "undefined" ? window.location.origin : "https://aegis-solana-gamma.vercel.app";
    const md = `[![AEGIS On-Chain Audit](${origin}/api/badge/${programId})](https://explorer.solana.com/address/${programId}?cluster=devnet)`;
    navigator.clipboard.writeText(md);
    setCopiedBadgeId(programId);
    setTimeout(() => setCopiedBadgeId(null), 2000);
  }

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      {/* On-Chain Whitehat Reputation Leaderboard */}
      <MachinedPanel variant="solana" className="p-5">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="rounded-lg bg-amber-500/15 p-2 text-amber-300">
              <Award className="h-4 w-4" />
            </div>
            <h3 className="font-display font-semibold text-white">On-Chain Whitehat Leaderboard</h3>
          </div>
          <span className="rounded border border-slate-800 bg-slate-900/80 px-2 py-0.5 text-[10.5px] font-medium text-slate-400">
            Anti-Sybil PDAs
          </span>
        </div>

        {whitehats.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-800 p-8 text-center text-xs text-slate-400">
            No WhitehatProfile PDAs recorded yet.
          </div>
        ) : (
          <div className="space-y-3">
            {whitehats.map((w, idx) => {
              const maxRep = Math.max(150, whitehats[0]?.reputationScore || 150);
              const pct = Math.max(6, Math.min(100, Math.round((w.reputationScore / maxRep) * 100)));
              return (
                <div key={w.address} className="aegis-subbox space-y-2.5 rounded-xl p-3.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div
                        className={`flex h-9 w-9 items-center justify-center rounded-lg border font-display text-sm font-bold ${
                          idx === 0
                            ? "border-amber-400/40 bg-amber-500/10 text-amber-300"
                            : idx === 1
                            ? "border-slate-500/40 bg-slate-700/20 text-slate-200"
                            : "border-slate-700 bg-slate-900 text-slate-400"
                        }`}
                      >
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
                          {w.researcher.slice(0, 8)}…{w.researcher.slice(-6)} ·{" "}
                          {w.approvedFindings}/{w.totalSubmissions} approved
                        </a>
                      </div>
                    </div>
                    <div className="text-right tabular-nums">
                      <div className="font-display text-sm font-bold text-teal-300">
                        {w.reputationScore} REP
                      </div>
                      <div className="font-mono text-[11px] text-slate-400">
                        {(w.totalEarnedLamports / LAMPORTS_PER_SOL).toFixed(4)} SOL
                      </div>
                    </div>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800/90">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-teal-500 to-teal-300"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </MachinedPanel>

      {/* Verified On-Chain x402 Audit Attestations + Live Embeddable SVG Badges */}
      <MachinedPanel variant="mint" delay={0.07} className="p-5">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="rounded-lg bg-teal-500/15 p-2 text-teal-300">
              <ShieldCheck className="h-4 w-4" />
            </div>
            <h3 className="font-display font-semibold text-white">On-Chain Audit Attestations</h3>
          </div>
          <span className="rounded border border-teal-500/25 bg-teal-500/10 px-2 py-0.5 text-[10.5px] font-medium text-teal-300">
            Ed25519 Sysvar
          </span>
        </div>

        {attestations.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-800 p-8 text-center text-xs text-slate-400">
            No AuditAttestation PDAs sealed yet.
          </div>
        ) : (
          <div className="space-y-3">
            {attestations.map((a) => (
              <div key={a.address} className="aegis-subbox rounded-xl p-3.5">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <ScoreRingGauge score={a.securityScore} size={46} />
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        {a.isVerifiedOracle ? (
                          <span className="inline-flex items-center gap-1 rounded-md border border-teal-400/40 bg-teal-500/10 px-2 py-0.5 text-[10px] font-semibold text-teal-200">
                            <BadgeCheck className="h-3 w-3 text-teal-300" />
                            ED25519 VERIFIED
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-300">
                            <ShieldAlert className="h-3 w-3" />
                            SELF-ATTESTED
                          </span>
                        )}
                        <a
                          href={`https://explorer.solana.com/tx/${a.x402PaymentSig}?cluster=devnet`}
                          target="_blank"
                          rel="noreferrer"
                          className="text-[11px] font-medium text-teal-300 hover:underline"
                        >
                          x402 TX ↗
                        </a>
                      </div>
                      <div className="mt-1 font-mono text-[11px] text-slate-300">
                        {a.targetProgramId.slice(0, 10)}…{a.targetProgramId.slice(-8)}
                      </div>
                    </div>
                  </div>
                  <a
                    href={`https://explorer.solana.com/address/${a.address}?cluster=devnet`}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-400 hover:text-white"
                  >
                    PDA <ExternalLink className="h-3 w-3" />
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
