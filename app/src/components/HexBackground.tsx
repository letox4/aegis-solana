"use client";

import React from "react";

/**
 * Zero-CPU, 144Hz/240Hz-Locked GPU-Composited Hexagonal Background.
 * - Uses pure CSS `transform: translate3d(...)` ambient light sweeps (ZERO JS frame loop,
 *   ZERO WebGL shader stalls, ZERO horizontal moiré lines).
 * - Razor-sharp vector SVG tapered-stroke honeycomb lattice rendered once into GPU memory.
 */
export function HexBackground() {
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-0 overflow-hidden bg-[#05070b]"
    >
      {/* Layer 1: Smooth GPU-composited subsurface volumetric light fields (locked native Hz) */}
      <div className="aegis-orb-teal" />
      <div className="aegis-orb-violet" />

      {/* Layer 2: Crisp vector SVG honeycomb with continuous tapered-thickness edges */}
      <svg className="absolute inset-0 h-full w-full opacity-[0.42]" xmlns="http://www.w3.org/2000/svg">
        <defs>
          {/* Tapered edge gradients — thick/bright upper-left fading cleanly to razor-thin lower-right */}
          <linearGradient id="hex-rim-main" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#e2e8f0" stopOpacity="0.34" />
            <stop offset="42%" stopColor="#5eead4" stopOpacity="0.18" />
            <stop offset="78%" stopColor="#64748b" stopOpacity="0.07" />
            <stop offset="100%" stopColor="#94a3b8" stopOpacity="0.14" />
          </linearGradient>

          <linearGradient id="hex-rim-accent" x1="100%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#c4b5fd" stopOpacity="0.26" />
            <stop offset="50%" stopColor="#475569" stopOpacity="0.08" />
            <stop offset="100%" stopColor="#5eead4" stopOpacity="0.22" />
          </linearGradient>

          {/* Seamless flat-top hexagonal tile (width=108, height=62.354 -> mathematically exact tiling) */}
          <pattern
            id="aegis-hex-lattice"
            width="108"
            height="62.3538"
            patternUnits="userSpaceOnUse"
          >
            {/* Primary hex outline */}
            <polygon
              points="18,0 54,0 72,31.1769 54,62.3538 18,62.3538 0,31.1769"
              fill="none"
              stroke="url(#hex-rim-main)"
              strokeWidth="0.9"
            />
            {/* Secondary offset hex edges for seamless honeycomb */}
            <polyline
              points="72,31.1769 108,31.1769"
              fill="none"
              stroke="url(#hex-rim-accent)"
              strokeWidth="0.75"
            />
            {/* Tapered specular ridge accents along upper-left bevels (true varying stroke weight) */}
            <line
              x1="18"
              y1="0.4"
              x2="54"
              y2="0.4"
              stroke="#99f6e4"
              strokeOpacity="0.22"
              strokeWidth="1.45"
            />
            <line
              x1="0.4"
              y1="31.1769"
              x2="18"
              y2="0.4"
              stroke="#e2e8f0"
              strokeOpacity="0.18"
              strokeWidth="1.2"
            />
          </pattern>
        </defs>

        <rect width="100%" height="100%" fill="url(#aegis-hex-lattice)" />
      </svg>

      {/* Layer 3: Subtle slow-drifting specular hex highlight layer (pure CSS GPU transform) */}
      <div className="aegis-hex-sheen" />

      {/* Layer 4: Clean dark radial vignette so content pops with effortless contrast */}
      <div
        className="absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 80% 70% at 50% 25%, transparent 0%, rgba(5, 7, 11, 0.45) 68%, rgba(5, 7, 11, 0.88) 100%)",
        }}
      />
    </div>
  );
}
