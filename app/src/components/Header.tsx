"use client";

import React from "react";
import dynamic from "next/dynamic";
import { motion } from "framer-motion";
import { ArrowUpRight, Search, Zap, Shield, Globe, Award } from "lucide-react";

const WalletMultiButton = dynamic(
  async () => (await import("@solana/wallet-adapter-react-ui")).WalletMultiButton,
  { ssr: false }
);

export type AppTabId = "scanner" | "vaults" | "lifi" | "profiles";

interface HeaderProps {
  programId: string;
  programDeployed: boolean;
  activeTab: AppTabId;
  onSelectTab: (tab: AppTabId) => void;
  onOpenCommandPalette: () => void;
}

const NAV_ITEMS: Array<{ id: AppTabId; label: string; icon: React.ComponentType<{ className?: string }> }> = [
  { id: "scanner", label: "Audit Scanner", icon: Zap },
  { id: "vaults", label: "Bounty Vaults", icon: Shield },
  { id: "lifi", label: "Cross-Chain", icon: Globe },
  { id: "profiles", label: "Registry", icon: Award },
];

function AegisMark() {
  return (
    <svg
      width="28"
      height="28"
      viewBox="0 0 32 32"
      fill="none"
      aria-hidden="true"
      className="shrink-0"
    >
      <path
        d="M16 2.5L27.7 9.25V22.75L16 29.5L4.3 22.75V9.25L16 2.5Z"
        stroke="rgba(226,232,240,0.45)"
        strokeWidth="1.15"
      />
      <path
        d="M10.4 21.8L16 8.8L21.6 21.8"
        stroke="#f8fafc"
        strokeWidth="1.55"
        strokeLinecap="square"
        strokeLinejoin="miter"
      />
      <line x1="12.8" y1="18.1" x2="23.2" y2="18.1" stroke="#5eead4" strokeWidth="1.35" />
    </svg>
  );
}

function StatusRhombus({ active }: { active: boolean }) {
  const id = active ? "rhombus-active" : "rhombus-pending";
  return (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true" className="shrink-0">
      <defs>
        <linearGradient id={`${id}-o`} x1="2" y1="1" x2="14" y2="15" gradientUnits="userSpaceOnUse">
          {active ? (
            <>
              <stop offset="0%" stopColor="#e2e8f0" />
              <stop offset="50%" stopColor="#5eead4" />
              <stop offset="100%" stopColor="#0f766e" />
            </>
          ) : (
            <>
              <stop offset="0%" stopColor="#fde68a" />
              <stop offset="100%" stopColor="#b45309" />
            </>
          )}
        </linearGradient>
      </defs>
      <polygon
        points="8,1.2 14.8,8 8,14.8 1.2,8"
        fill={active ? "rgba(45,212,191,0.22)" : "rgba(245,158,11,0.22)"}
        stroke={`url(#${id}-o)`}
        strokeWidth="1.2"
      />
      <polygon points="8,5 11,8 8,11 5,8" fill={active ? "#99f6e4" : "#fcd34d"} />
    </svg>
  );
}

export function Header({
  programId,
  programDeployed,
  activeTab,
  onSelectTab,
  onOpenCommandPalette,
}: HeaderProps) {
  const shortPid = `${programId.slice(0, 6)}…${programId.slice(-4)}`;

  return (
    <header className="sticky top-0 z-40 border-b border-slate-400/10 bg-[#05070b]/95">
      <div className="mx-auto flex max-w-[1460px] flex-wrap items-center justify-between gap-3 px-5 py-2.5 sm:px-8">
        {/* Left: Brand Identity */}
        <div className="flex items-center gap-6">
          <button
            type="button"
            onClick={() => onSelectTab("scanner")}
            className="flex items-center gap-2.5 text-left"
          >
            <AegisMark />
            <span className="font-display text-[16px] font-medium tracking-[0.26em] text-slate-100">
              AEGIS
            </span>
          </button>

          {/* Integrated Production App Navigation */}
          <nav className="hidden items-center gap-1 rounded-xl border border-slate-800/90 bg-[#080c14] p-1 lg:flex">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              const active = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => onSelectTab(item.id)}
                  className={`relative flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[12.5px] font-medium transition-colors ${
                    active ? "text-white" : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {active && (
                    <motion.span
                      layoutId="aegis-header-nav-pill"
                      transition={{ type: "spring", stiffness: 540, damping: 40, mass: 0.7 }}
                      className="aegis-tab-pill"
                    />
                  )}
                  <Icon
                    className={`relative z-10 h-3.5 w-3.5 ${
                      active ? "text-teal-300" : "text-slate-500"
                    }`}
                  />
                  <span className="relative z-10">{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Right: Quick Command Trigger + Devnet Contract + Wallet */}
        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={onOpenCommandPalette}
            className="hidden items-center gap-2.5 rounded-lg border border-slate-800 bg-[#090d16] px-2.5 py-1.5 text-xs text-slate-400 transition hover:border-slate-700 hover:text-slate-200 sm:inline-flex"
            title="Open Command Palette (Ctrl + K)"
          >
            <Search className="h-3.5 w-3.5 text-slate-500" />
            <span>Quick actions…</span>
            <kbd className="rounded border border-slate-700/80 bg-[#05080f] px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
              Ctrl K
            </kbd>
          </button>

          <a
            href={`https://explorer.solana.com/address/${programId}?cluster=devnet`}
            target="_blank"
            rel="noreferrer"
            className="hidden items-center gap-1.5 rounded-lg border border-slate-800/80 bg-[#090d16] px-2.5 py-1.5 font-mono text-[11px] text-slate-300 transition hover:border-slate-700 hover:text-white xl:flex"
            title="Inspect deployed Solana Devnet smart contract"
          >
            <StatusRhombus active={programDeployed} />
            <span>{shortPid}</span>
            <ArrowUpRight className="h-3 w-3 text-slate-500" />
          </a>

          <a
            href="https://faucet.solana.com/"
            target="_blank"
            rel="noreferrer"
            className="hidden px-1.5 text-xs font-medium text-slate-400 transition hover:text-slate-100 md:inline"
          >
            Faucet
          </a>

          <WalletMultiButton />
        </div>
      </div>

      {/* Responsive mobile nav bar below header on small screens */}
      <div className="flex gap-1 overflow-x-auto border-t border-slate-800/60 px-4 py-1.5 lg:hidden">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const active = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => onSelectTab(item.id)}
              className={`flex shrink-0 items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium ${
                active
                  ? "border border-slate-700 bg-slate-800/80 text-white"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <Icon className={`h-3.5 w-3.5 ${active ? "text-teal-300" : "text-slate-500"}`} />
              {item.label}
            </button>
          );
        })}
      </div>
    </header>
  );
}
