"use client";

import React from "react";

export type PanelVariant = "titanium" | "mint" | "steel" | "solana";

interface MachinedPanelProps {
  variant?: PanelVariant;
  className?: string;
  delay?: number;
  children: React.ReactNode;
}

const VARIANT_CLASS: Record<PanelVariant, string> = {
  titanium: "aegis-box",
  mint: "aegis-box-accent",
  steel: "aegis-box-steel",
  solana: "aegis-box-indigo",
};

const TOP_GLINT: Record<PanelVariant, string> = {
  titanium: "from-transparent via-white/25 to-transparent",
  mint: "from-transparent via-teal-300/50 to-transparent",
  steel: "from-transparent via-sky-200/30 to-transparent",
  solana: "from-transparent via-slate-300/30 to-transparent",
};

/**
 * Pure Native DOM Specular Panel (Zero Framer Motion JS overhead, Zero permanent will-change layers).
 * Locked 144Hz/240Hz scroll & tab performance.
 */
export function MachinedPanel({
  variant = "titanium",
  className = "",
  children,
}: MachinedPanelProps) {
  return (
    <div className={`${VARIANT_CLASS[variant]} overflow-hidden rounded-2xl ${className}`}>
      <div
        aria-hidden="true"
        className={`pointer-events-none absolute inset-x-10 top-0 z-10 h-px bg-gradient-to-r ${TOP_GLINT[variant]}`}
      />
      <div className="relative z-[3]">{children}</div>
    </div>
  );
}
