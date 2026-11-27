"use client";

import React from "react";
import { Check } from "lucide-react";

/**
 * Radial SVG Arc Gauge for Security & Surface Scores (0..100).
 * Pure vector, zero JS animation loop, 144Hz+ native fluidity.
 */
export function ScoreRingGauge({
  score,
  label,
  size = 64,
}: {
  score: number;
  label?: string;
  size?: number;
}) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const stroke = 4.5;
  const r = (size - stroke * 2) / 2;
  const c = 2 * Math.PI * r;
  // Minimum 6% arc so score=0 still shows a visible critical arc segment
  const pct = clamped === 0 ? 0.06 : clamped / 100;
  const dashOffset = c * (1 - pct);

  const tone =
    clamped >= 80
      ? { stroke: "#2dd4bf", text: "text-teal-300", sub: "text-teal-400/80" }
      : clamped >= 55
      ? { stroke: "#fbbf24", text: "text-amber-300", sub: "text-amber-400/80" }
      : { stroke: "#fb7185", text: "text-rose-300", sub: "text-rose-400/80" };

  return (
    <div
      className="relative inline-flex shrink-0 items-center justify-center"
      style={{ width: size, height: size }}
    >
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="rgba(5, 8, 15, 0.75)"
          stroke="rgba(51, 65, 85, 0.45)"
          strokeWidth={stroke}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={tone.stroke}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={dashOffset}
          style={{ transition: "stroke-dashoffset 420ms cubic-bezier(0.16, 1, 0.3, 1)" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center tabular-nums">
        <span className={`font-display text-base font-bold leading-none ${tone.text}`}>
          {clamped}
        </span>
        {label && (
          <span className={`mt-0.5 text-[8.5px] font-semibold uppercase tracking-wider ${tone.sub}`}>
            {label}
          </span>
        )}
      </div>
    </div>
  );
}

/**
 * Horizontal Segmented Severity Spectrum Bar.
 */
export function SeverityDistributionBar({
  critical,
  high,
  medium,
  low,
}: {
  critical: number;
  high: number;
  medium: number;
  low: number;
}) {
  const total = critical + high + medium + low;
  if (total === 0) {
    return (
      <div className="space-y-1.5">
        <div className="h-2 w-full overflow-hidden rounded-full bg-teal-500/20">
          <div className="h-full w-full rounded-full bg-teal-400" />
        </div>
        <div className="text-[11px] font-medium text-teal-300">0 Vulnerabilities Detected</div>
      </div>
    );
  }

  const segs = [
    { key: "Crit", count: critical, bar: "bg-rose-500", dot: "bg-rose-400", text: "text-rose-300" },
    { key: "High", count: high, bar: "bg-orange-400", dot: "bg-orange-400", text: "text-orange-300" },
    { key: "Med", count: medium, bar: "bg-amber-400", dot: "bg-amber-400", text: "text-amber-300" },
    { key: "Low", count: low, bar: "bg-sky-400", dot: "bg-sky-400", text: "text-sky-300" },
  ].filter((s) => s.count > 0);

  return (
    <div className="space-y-1.5">
      <div className="flex h-2 w-full gap-0.5 overflow-hidden rounded-full bg-slate-900 p-0.5">
        {segs.map((s) => (
          <div
            key={s.key}
            className={`h-full rounded-full ${s.bar}`}
            style={{ width: `${Math.max(8, (s.count / total) * 100)}%` }}
          />
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-3 text-[11px] font-medium tabular-nums">
        {segs.map((s) => (
          <span key={s.key} className={`inline-flex items-center gap-1.5 ${s.text}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
            {s.count} {s.key}
          </span>
        ))}
      </div>
    </div>
  );
}

/**
 * Connected Horizontal Visual Stepper (replaces repetitive explanatory paragraphs).
 */
export function ProtocolStepper({
  steps,
}: {
  steps: Array<{
    title: string;
    sub?: string;
    status: "idle" | "active" | "done";
  }>;
}) {
  return (
    <div className="grid grid-cols-3 gap-2 rounded-xl border border-slate-800/90 bg-[#05080f] p-2.5">
      {steps.map((s, idx) => {
        const isDone = s.status === "done";
        const isActive = s.status === "active";
        return (
          <div
            key={s.title}
            className={`relative flex items-center gap-2 rounded-lg px-2.5 py-2 transition ${
              isDone
                ? "border border-teal-500/30 bg-teal-500/[0.08]"
                : isActive
                ? "border border-amber-400/35 bg-amber-400/[0.07]"
                : "border border-transparent bg-slate-900/40 opacity-65"
            }`}
          >
            <div
              className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] font-bold tabular-nums ${
                isDone
                  ? "bg-teal-400 text-slate-950"
                  : isActive
                  ? "border border-amber-300 text-amber-300"
                  : "border border-slate-700 text-slate-500"
              }`}
            >
              {isDone ? <Check className="h-3 w-3 stroke-[2.8]" /> : idx + 1}
            </div>
            <div className="min-w-0">
              <div
                className={`truncate text-[11px] font-semibold leading-tight ${
                  isDone ? "text-teal-200" : isActive ? "text-amber-200" : "text-slate-400"
                }`}
              >
                {s.title}
              </div>
              {s.sub && (
                <div className="truncate text-[10px] text-slate-500">{s.sub}</div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

/**
 * Visual SOL Escrow Pool Capacity Meter for Bounty Vault Cards.
 */
export function EscrowCapacityBar({
  remainingLamports,
  totalLamports,
}: {
  remainingLamports: number;
  totalLamports: number;
}) {
  const denom = Math.max(1, totalLamports);
  const pct = Math.max(4, Math.min(100, Math.round((remainingLamports / denom) * 100)));
  return (
    <div className="mt-2.5 flex items-center gap-2.5">
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-slate-800/90">
        <div
          className="h-full rounded-full bg-gradient-to-r from-teal-500 to-teal-300"
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="shrink-0 text-[10.5px] font-medium tabular-nums text-slate-500">
        {pct}% funded
      </span>
    </div>
  );
}

/**
 * Clean Minimalist Geometric Chain Emblems (Arbitrum, Base, Polygon, Ethereum, Solana).
 */
export function ChainGlyph({
  chain,
  size = 20,
}: {
  chain: string;
  size?: number;
}) {
  const key = chain.toUpperCase();

  if (key.includes("SOL")) {
    return (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className="shrink-0">
        <rect width="24" height="24" rx="6" fill="#0b1520" stroke="rgba(94,234,212,0.35)" />
        <path d="M6.5 8.5H16.2L17.5 7H7.8L6.5 8.5Z" fill="#5eead4" />
        <path d="M6.5 12.75H16.2L17.5 11.25H7.8L6.5 12.75Z" fill="#2dd4bf" />
        <path d="M7.8 17H17.5L16.2 15.5H6.5L7.8 17Z" fill="#99f6e4" />
      </svg>
    );
  }

  if (key.includes("ARB")) {
    return (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className="shrink-0">
        <rect width="24" height="24" rx="6" fill="#0b1628" stroke="rgba(56,189,248,0.35)" />
        <path d="M12 5.2L18 8.6V15.4L12 18.8L6 15.4V8.6L12 5.2Z" stroke="#38bdf8" strokeWidth="1.4" />
        <path d="M9.5 15.2L12 8.8L14.5 15.2" stroke="#e0f2fe" strokeWidth="1.5" strokeLinecap="round" />
      </svg>
    );
  }

  if (key.includes("BASE")) {
    return (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className="shrink-0">
        <rect width="24" height="24" rx="6" fill="#09152b" stroke="rgba(96,165,250,0.4)" />
        <circle cx="12" cy="12" r="5.5" stroke="#60a5fa" strokeWidth="1.8" />
        <line x1="6.5" y1="12" x2="12.5" y2="12" stroke="#dbeafe" strokeWidth="1.8" />
      </svg>
    );
  }

  if (key.includes("POL") || key.includes("MATIC")) {
    return (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className="shrink-0">
        <rect width="24" height="24" rx="6" fill="#140f26" stroke="rgba(167,139,250,0.35)" />
        <path
          d="M9.2 9.2L12 7.6L14.8 9.2V12.4L12 14L9.2 12.4V9.2Z"
          stroke="#a78bfa"
          strokeWidth="1.5"
        />
        <path
          d="M12 11.6L14.8 10L17.2 11.4V14.6L14.8 16L12 14.4"
          stroke="#ddd6fe"
          strokeWidth="1.3"
        />
      </svg>
    );
  }

  // Default: Ethereum diamond
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className="shrink-0">
      <rect width="24" height="24" rx="6" fill="#101522" stroke="rgba(148,163,184,0.35)" />
      <path d="M12 5.5L16.2 12.2L12 14.6L7.8 12.2L12 5.5Z" stroke="#e2e8f0" strokeWidth="1.3" />
      <path d="M12 18.5L16.2 13.5L12 15.8L7.8 13.5L12 18.5Z" stroke="#94a3b8" strokeWidth="1.3" />
    </svg>
  );
}
