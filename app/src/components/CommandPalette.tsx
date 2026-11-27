"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  Search,
  Zap,
  Shield,
  Globe,
  Award,
  Radar,
  GitBranch,
  FileCode2,
  ExternalLink,
  Copy,
} from "lucide-react";
import type { AppTabId } from "./Header";

export type QuickCommandAction =
  | { type: "tab"; tab: AppTabId }
  | { type: "scanner-mode"; mode: "code" | "github" | "onchain"; presetId?: string; cluster?: "devnet" | "mainnet-beta"; sampleIdx?: number }
  | { type: "copy-program-id" }
  | { type: "open-url"; url: string };

interface CommandItem {
  id: string;
  group: string;
  label: string;
  hint: string;
  icon: React.ComponentType<{ className?: string }>;
  action: QuickCommandAction;
}

interface CommandPaletteProps {
  open: boolean;
  programId: string;
  onClose: () => void;
  onRunCommand: (action: QuickCommandAction) => void;
}

export function CommandPalette({
  open,
  programId,
  onClose,
  onRunCommand,
}: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [selectedIdx, setSelectedIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const items: CommandItem[] = useMemo(
    () => [
      {
        id: "insp-aegis",
        group: "Live On-Chain Inspector",
        label: "Inspect AEGIS v3 Protocol (Solana Devnet)",
        hint: "BPFLoaderUpgradeable + zlib Anchor IDL",
        icon: Radar,
        action: {
          type: "scanner-mode",
          mode: "onchain",
          presetId: programId,
          cluster: "devnet",
        },
      },
      {
        id: "insp-jup",
        group: "Live On-Chain Inspector",
        label: "Inspect Jupiter v6 Aggregator (Solana Mainnet)",
        hint: "Inflate 21 live Mainnet IDL instructions",
        icon: Radar,
        action: {
          type: "scanner-mode",
          mode: "onchain",
          presetId: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
          cluster: "mainnet-beta",
        },
      },
      {
        id: "scan-gh",
        group: "Audit Suite",
        label: "Scan GitHub Repository (coral-xyz/sealevel-attacks)",
        hint: "Multi-file Rust fetcher",
        icon: GitBranch,
        action: { type: "scanner-mode", mode: "github" },
      },
      {
        id: "scan-vuln",
        group: "Audit Suite",
        label: "Load Vulnerable DeFi Vault Sample",
        hint: "20 Inter-Procedural Rules",
        icon: FileCode2,
        action: { type: "scanner-mode", mode: "code", sampleIdx: 0 },
      },
      {
        id: "scan-safe",
        group: "Audit Suite",
        label: "Load AEGIS Hardened Vault Self-Audit",
        hint: "Grade A+ · 100/100",
        icon: Shield,
        action: { type: "scanner-mode", mode: "code", sampleIdx: 1 },
      },
      {
        id: "nav-scanner",
        group: "Navigation",
        label: "Go to Audit Scanner",
        hint: "x402 V2",
        icon: Zap,
        action: { type: "tab", tab: "scanner" },
      },
      {
        id: "nav-vaults",
        group: "Navigation",
        label: "Go to Bounty Vaults & AES-256-GCM PoC Encryption",
        hint: "Commit-Reveal + Arbitration",
        icon: Shield,
        action: { type: "tab", tab: "vaults" },
      },
      {
        id: "nav-lifi",
        group: "Navigation",
        label: "Go to Cross-Chain Treasury & Payout Router",
        hint: "LI.FI",
        icon: Globe,
        action: { type: "tab", tab: "lifi" },
      },
      {
        id: "nav-registry",
        group: "Navigation",
        label: "Go to Whitehat Leaderboard & On-Chain SVG Badges",
        hint: "Ed25519 Verified",
        icon: Award,
        action: { type: "tab", tab: "profiles" },
      },
      {
        id: "copy-pid",
        group: "Protocol",
        label: "Copy Deployed Solana Program ID",
        hint: `${programId.slice(0, 8)}…`,
        icon: Copy,
        action: { type: "copy-program-id" },
      },
      {
        id: "open-explorer",
        group: "Protocol",
        label: "Open Program in Solana Explorer (Devnet)",
        hint: "explorer.solana.com",
        icon: ExternalLink,
        action: {
          type: "open-url",
          url: `https://explorer.solana.com/address/${programId}?cluster=devnet`,
        },
      },
    ],
    [programId]
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter(
      (i) =>
        i.label.toLowerCase().includes(q) ||
        i.group.toLowerCase().includes(q) ||
        i.hint.toLowerCase().includes(q)
    );
  }, [items, query]);

  useEffect(() => {
    if (open) {
      setQuery("");
      setSelectedIdx(0);
      setTimeout(() => inputRef.current?.focus(), 10);
    }
  }, [open]);

  useEffect(() => {
    setSelectedIdx(0);
  }, [query]);

  if (!open) return null;

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIdx((prev) => (filtered.length > 0 ? (prev + 1) % filtered.length : 0));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIdx((prev) =>
        filtered.length > 0 ? (prev - 1 + filtered.length) % filtered.length : 0
      );
    } else if (e.key === "Enter" && filtered[selectedIdx]) {
      e.preventDefault();
      onRunCommand(filtered[selectedIdx].action);
      onClose();
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/75 px-4 pt-[13vh]"
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
        className="aegis-box w-full max-w-xl overflow-hidden rounded-2xl shadow-2xl"
      >
        <div className="flex items-center gap-3 border-b border-slate-800/90 px-4 py-3">
          <Search className="h-4 w-4 shrink-0 text-teal-300" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Type a command, program, or module…"
            className="w-full bg-transparent text-sm text-white placeholder-slate-500 outline-none"
          />
          <kbd className="rounded border border-slate-800 bg-[#060911] px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
            ESC
          </kbd>
        </div>

        <div className="max-h-80 overflow-y-auto p-2">
          {filtered.length === 0 ? (
            <div className="py-8 text-center text-xs text-slate-500">No matching actions found.</div>
          ) : (
            filtered.map((item, idx) => {
              const Icon = item.icon;
              const selected = idx === selectedIdx;
              return (
                <button
                  key={item.id}
                  type="button"
                  onMouseEnter={() => setSelectedIdx(idx)}
                  onClick={() => {
                    onRunCommand(item.action);
                    onClose();
                  }}
                  className={`flex w-full items-center justify-between gap-3 rounded-xl px-3 py-2.5 text-left transition ${
                    selected ? "bg-slate-800/85 text-white" : "text-slate-300 hover:bg-slate-900/60"
                  }`}
                >
                  <div className="flex min-w-0 items-center gap-2.5">
                    <Icon
                      className={`h-4 w-4 shrink-0 ${
                        selected ? "text-teal-300" : "text-slate-500"
                      }`}
                    />
                    <span className="truncate text-xs font-medium">{item.label}</span>
                  </div>
                  <span className="shrink-0 font-mono text-[10px] text-slate-500">{item.hint}</span>
                </button>
              );
            })
          )}
        </div>

        <div className="flex items-center justify-between border-t border-slate-800/80 bg-[#05080f] px-4 py-2 font-mono text-[10px] text-slate-500">
          <span>↑↓ Navigate · ↵ Execute</span>
          <span>AEGIS Institutional Shell v3.0</span>
        </div>
      </div>
    </div>
  );
}
