"use client";

import React from "react";

interface ProtocolStatusBarProps {
  programId: string;
  programDeployed: boolean;
  rpcLatencyMs: number | null;
}

const ONCHAIN_IDL_ADDRESS = "4eqNqueh9JDD7j614TynsRPCtXSBRvzCs4XVdHXbjNa9";

export function ProtocolStatusBar({
  programId,
  programDeployed,
  rpcLatencyMs,
}: ProtocolStatusBarProps) {
  return (
    <footer className="mt-12 border-t border-slate-400/10 bg-[#04060a]/95">
      <div className="mx-auto flex min-h-[34px] max-w-[1460px] flex-wrap items-center justify-between gap-3 px-5 py-1.5 font-mono text-[11px] text-slate-500 sm:px-8">
        <div className="flex flex-wrap items-center gap-3">
          <span className="inline-flex items-center gap-1.5 text-slate-300">
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                programDeployed ? "bg-teal-400" : "bg-amber-400"
              }`}
            />
            {programDeployed ? "SOLANA DEVNET · OPERATIONAL" : "CONNECTING TO DEVNET"}
          </span>
          {rpcLatencyMs !== null && (
            <>
              <span className="text-slate-800">|</span>
              <span>RPC {rpcLatencyMs}ms</span>
            </>
          )}
          <span className="hidden text-slate-800 sm:inline">|</span>
          <span className="hidden sm:inline">AEGIS ENGINE v3.0 · 20 INTER-PROCEDURAL RULES</span>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <a
            href={`https://explorer.solana.com/address/${ONCHAIN_IDL_ADDRESS}?cluster=devnet`}
            target="_blank"
            rel="noreferrer"
            className="transition hover:text-slate-200"
          >
            On-Chain IDL ({ONCHAIN_IDL_ADDRESS.slice(0, 6)}…) ↗
          </a>
          <span className="text-slate-800">|</span>
          <a
            href="/api/x402/scan"
            target="_blank"
            rel="noreferrer"
            className="transition hover:text-slate-200"
          >
            x402 Discovery ↗
          </a>
          <span className="text-slate-800">|</span>
          <a
            href={`/api/badge/${programId}`}
            target="_blank"
            rel="noreferrer"
            className="text-teal-300/90 transition hover:text-teal-200"
          >
            Trust Badge SVG ↗
          </a>
        </div>
      </div>
    </footer>
  );
}
