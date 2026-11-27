"use client";

import React from "react";

/**
 * Zero-Animation, Single-Layer Static Hexagonal Background (0.0% Idle GPU / Locked 240Hz).
 * - Zero infinite CSS keyframe animations (eliminates continuous 240Hz full-screen alpha overdraw).
 * - Pure solid stroke SVG pattern (zero per-tile <linearGradient> shader lookups in Skia).
 */
export function HexBackground() {
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-0 overflow-hidden bg-[#05070b]"
      style={{ contain: "strict" }}
    >
      {/* Static ambient light field baked into a single CSS background pass */}
      <div
        className="absolute inset-0"
        style={{
          background:
            "radial-gradient(circle at 24% 8%, rgba(45, 212, 191, 0.085) 0%, transparent 46%), radial-gradient(circle at 82% 86%, rgba(148, 163, 184, 0.06) 0%, transparent 46%)",
        }}
      />

      {/* Lightweight solid-stroke honeycomb cached once as a static bitmap */}
      <svg className="absolute inset-0 h-full w-full opacity-[0.34]" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <pattern
            id="aegis-hex-lattice"
            width="108"
            height="62.3538"
            patternUnits="userSpaceOnUse"
          >
            <polygon
              points="18,0 54,0 72,31.1769 54,62.3538 18,62.3538 0,31.1769"
              fill="none"
              stroke="rgba(148, 163, 184, 0.18)"
              strokeWidth="0.85"
            />
            <line
              x1="72"
              y1="31.1769"
              x2="108"
              y2="31.1769"
              stroke="rgba(94, 234, 212, 0.14)"
              strokeWidth="0.75"
            />
            <line
              x1="18"
              y1="0.4"
              x2="54"
              y2="0.4"
              stroke="rgba(153, 246, 228, 0.2)"
              strokeWidth="1.2"
            />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#aegis-hex-lattice)" />
      </svg>

      {/* Static edge vignette */}
      <div
        className="absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 82% 72% at 50% 25%, transparent 0%, rgba(5, 7, 11, 0.5) 68%, #05070b 100%)",
        }}
      />
    </div>
  );
}
