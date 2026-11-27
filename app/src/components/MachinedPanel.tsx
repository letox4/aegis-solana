"use client";

import React from "react";
import { motion } from "framer-motion";

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
  titanium: "from-transparent via-white/30 to-transparent",
  mint: "from-transparent via-teal-300/55 to-transparent",
  steel: "from-transparent via-sky-200/35 to-transparent",
  solana: "from-transparent via-violet-300/50 to-transparent",
};

/**
 * Hairline 1px Directional Specular Panel (Linear / Swiss Hardware aesthetic).
 * Razor-clean 1px frosted bevel + subtle top catchlight + crisp Framer Motion physics.
 */
export function MachinedPanel({
  variant = "titanium",
  className = "",
  delay = 0,
  children,
}: MachinedPanelProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.18, delay, ease: [0.16, 1, 0.3, 1] }}
      style={{ willChange: "transform, opacity" }}
      className={`${VARIANT_CLASS[variant]} overflow-hidden rounded-2xl ${className}`}
    >
      {/* Subtle 1px specular catchlight along the top edge */}
      <div
        aria-hidden="true"
        className={`pointer-events-none absolute inset-x-10 top-0 z-10 h-px bg-gradient-to-r ${TOP_GLINT[variant]}`}
      />
      <div className="relative z-[3]">{children}</div>
    </motion.div>
  );
}
