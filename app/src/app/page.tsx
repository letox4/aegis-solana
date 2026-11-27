"use client";

import React, { useCallback, useEffect, useState } from "react";
import { LAMPORTS_PER_SOL } from "@solana/web3.js";
import { AnimatePresence, motion } from "framer-motion";
import { Header, AppTabId } from "@/components/Header";
import { CommandPalette, QuickCommandAction } from "@/components/CommandPalette";
import { ProtocolStatusBar } from "@/components/ProtocolStatusBar";
import { HexBackground } from "@/components/HexBackground";
import { MachinedPanel } from "@/components/MachinedPanel";
import { BountyVaultsTab } from "@/components/BountyVaultsTab";
import { X402ScannerTab, ScannerExternalCommand } from "@/components/X402ScannerTab";
import { LifiBridgeTab } from "@/components/LifiBridgeTab";
import { WhitehatProfilesTab } from "@/components/WhitehatProfilesTab";
import type {
  OnChainAuditAttestation,
  OnChainBountyVault,
  OnChainFindingReport,
  OnChainWhitehatProfile,
} from "@/lib/solana/aegisProgram";

export interface EscalatedFindingDraft {
  id: string;
  ruleId: string;
  title: string;
  severityNum: number;
  pocSummary: string;
  detailedReport: string;
}

interface OnChainStateResponse {
  programId: string;
  programDeployed: boolean;
  treasuryAddress: string;
  bounties: OnChainBountyVault[];
  findings: OnChainFindingReport[];
  whitehats: OnChainWhitehatProfile[];
  attestations: OnChainAuditAttestation[];
}

export default function HomePage() {
  const [activeTab, setActiveTab] = useState<AppTabId>("scanner");
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [scannerCmd, setScannerCmd] = useState<ScannerExternalCommand | null>(null);
  const [escalatedFinding, setEscalatedFinding] = useState<EscalatedFindingDraft | null>(null);
  const [rpcLatencyMs, setRpcLatencyMs] = useState<number | null>(null);

  const [state, setState] = useState<OnChainStateResponse>({
    programId:
      process.env.NEXT_PUBLIC_AEGIS_PROGRAM_ID ||
      "8AaU3VSHXHyKcVTe9JCA67oRR5djpjfAUgcM1cCtpe7p",
    programDeployed: false,
    treasuryAddress: "",
    bounties: [],
    findings: [],
    whitehats: [],
    attestations: [],
  });

  const refreshOnChainState = useCallback(async () => {
    const t0 = typeof performance !== "undefined" ? performance.now() : Date.now();
    try {
      const res = await fetch("/api/solana/state", { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        const elapsed = Math.max(
          12,
          Math.round((typeof performance !== "undefined" ? performance.now() : Date.now()) - t0)
        );
        setRpcLatencyMs(elapsed);
        setState(data);
      }
    } catch {
      // Keep previous state silently if RPC hiccups
    }
  }, []);

  useEffect(() => {
    refreshOnChainState();
  }, [refreshOnChainState]);

  // Global Ctrl+K / Cmd+K shortcut for Institutional Command Palette
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((prev) => !prev);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  function handleRunQuickCommand(action: QuickCommandAction) {
    if (action.type === "tab") {
      setActiveTab(action.tab);
    } else if (action.type === "scanner-mode") {
      setActiveTab("scanner");
      setScannerCmd({
        nonce: Date.now(),
        mode: action.mode,
        presetId: action.presetId,
        cluster: action.cluster,
        sampleIdx: action.sampleIdx,
      });
    } else if (action.type === "copy-program-id") {
      navigator.clipboard.writeText(state.programId);
    } else if (action.type === "open-url") {
      window.open(action.url, "_blank", "noopener,noreferrer");
    }
  }

  const totalEscrowedSol =
    state.bounties.reduce((sum, b) => sum + b.remainingPool, 0) / LAMPORTS_PER_SOL;

  const kpis = [
    { label: "Escrowed", value: totalEscrowedSol.toFixed(3), unit: "SOL", highlight: true },
    { label: "Vaults", value: String(state.bounties.length), unit: "active", highlight: false },
    { label: "Audits", value: String(state.attestations.length), unit: "sealed", highlight: false },
    { label: "Researchers", value: String(state.whitehats.length), unit: "ranked", highlight: false },
  ];

  return (
    <div className="relative min-h-screen">
      <HexBackground />

      <div className="relative z-10 flex min-h-screen flex-col">
        <Header
          programId={state.programId}
          programDeployed={state.programDeployed}
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          onOpenCommandPalette={() => setPaletteOpen(true)}
        />

        <main className="mx-auto w-full max-w-[1460px] flex-1 px-5 pt-6 sm:px-8">
          {/* Executive Hero Banner + Monochrome Telemetry Dock */}
          <MachinedPanel variant="titanium" className="mb-6 px-6 py-5 sm:px-7">
            <div className="flex flex-col justify-between gap-6 xl:flex-row xl:items-center">
              <div className="max-w-2xl">
                <div className="mb-2.5 inline-flex items-center gap-2 rounded-md border border-teal-400/20 bg-teal-400/[0.06] px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.11em] text-teal-300">
                  <span className="h-1.5 w-1.5 rotate-45 bg-teal-300" />
                  Offensive Security · Solana Devnet Protocol
                </div>
                <h1 className="font-display text-2xl font-semibold leading-tight tracking-[-0.025em] text-white sm:text-4xl">
                  Zero-Trust Bug Bounties &{" "}
                  <span className="bg-gradient-to-r from-slate-100 via-teal-200 to-teal-400 bg-clip-text text-transparent">
                    Pay-Per-Scan Audits
                  </span>
                </h1>
                <p className="mt-2.5 text-sm leading-relaxed text-slate-400">
                  Escrow SOL inside hardened Anchor PDAs, timestamp confidential vulnerability PoCs
                  with SHA-256 commit-reveal, unlock automated Sealevel audits via{" "}
                  <span className="font-medium text-slate-200">HTTP 402 (x402 V2)</span>, and route
                  cross-chain bounty liquidity with{" "}
                  <span className="font-medium text-slate-200">LI.FI</span>.
                </p>
              </div>

              {/* Clean Monochrome Telemetry Dock */}
              <div className="grid shrink-0 grid-cols-2 divide-y divide-slate-800/80 overflow-hidden rounded-xl border border-slate-800/90 bg-[#05080f] sm:grid-cols-4 sm:divide-x sm:divide-y-0">
                {kpis.map((kpi) => (
                  <div key={kpi.label} className="min-w-[128px] px-4 py-3.5">
                    <div className="text-[11px] font-medium text-slate-500">{kpi.label}</div>
                    <div className="mt-1 flex items-baseline gap-1.5">
                      <span
                        className={`font-display text-xl font-semibold tracking-tight tabular-nums ${
                          kpi.highlight ? "text-teal-300" : "text-slate-100"
                        }`}
                      >
                        {kpi.value}
                      </span>
                      <span className="text-[11px] text-slate-500">{kpi.unit}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </MachinedPanel>

          {/* Animated Workspace View */}
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.14, ease: [0.16, 1, 0.3, 1] }}
            >
              {activeTab === "scanner" && (
                <X402ScannerTab
                  onRefreshState={refreshOnChainState}
                  externalCommand={scannerCmd}
                  onEscalateFinding={(draft) => {
                    setEscalatedFinding(draft);
                    setActiveTab("vaults");
                  }}
                />
              )}
              {activeTab === "vaults" && (
                <BountyVaultsTab
                  bounties={state.bounties}
                  findings={state.findings}
                  onRefresh={refreshOnChainState}
                  escalatedFinding={escalatedFinding}
                  onClearEscalation={() => setEscalatedFinding(null)}
                />
              )}
              {activeTab === "lifi" && <LifiBridgeTab bounties={state.bounties} />}
              {activeTab === "profiles" && (
                <WhitehatProfilesTab
                  whitehats={state.whitehats}
                  attestations={state.attestations}
                />
              )}
            </motion.div>
          </AnimatePresence>
        </main>

        <ProtocolStatusBar
          programId={state.programId}
          programDeployed={state.programDeployed}
          rpcLatencyMs={rpcLatencyMs}
        />
      </div>

      <CommandPalette
        open={paletteOpen}
        programId={state.programId}
        onClose={() => setPaletteOpen(false)}
        onRunCommand={handleRunQuickCommand}
      />
    </div>
  );
}
