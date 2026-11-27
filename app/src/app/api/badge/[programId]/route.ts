import { NextRequest, NextResponse } from "next/server";
import { Connection, PublicKey } from "@solana/web3.js";
import { AEGIS_PROGRAM_ID, fetchAttestationsByTargetProgram } from "@/lib/solana/aegisProgram";
import { SOLANA_RPC_URL } from "@/lib/x402/protocol";

export const dynamic = "force-dynamic";

function escapeXml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function gradeFromScore(score: number): string {
  if (score >= 96) return "A+";
  if (score >= 86) return "A";
  if (score >= 72) return "B";
  if (score >= 55) return "C";
  if (score >= 35) return "D";
  return "F";
}

function buildBadgeSvg(leftText: string, rightText: string, accentHex: string, bgRightHex: string): string {
  const safeLeft = escapeXml(leftText);
  const safeRight = escapeXml(rightText);
  const leftWidth = Math.max(88, leftText.length * 6.8 + 26);
  const rightWidth = Math.max(124, rightText.length * 6.4 + 22);
  const totalWidth = Math.round(leftWidth + rightWidth);

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="24" role="img" aria-label="${safeLeft}: ${safeRight}">
  <title>${safeLeft}: ${safeRight}</title>
  <defs>
    <linearGradient id="bg" x2="0" y2="100%">
      <stop offset="0" stop-color="#ffffff" stop-opacity="0.06"/>
      <stop offset="1" stop-color="#000000" stop-opacity="0.18"/>
    </linearGradient>
    <clipPath id="round">
      <rect width="${totalWidth}" height="24" rx="5" fill="#fff"/>
    </clipPath>
  </defs>
  <g clip-path="url(#round)">
    <rect width="${Math.round(leftWidth)}" height="24" fill="#0b111c"/>
    <rect x="${Math.round(leftWidth)}" width="${Math.round(rightWidth)}" height="24" fill="${bgRightHex}"/>
    <rect width="${totalWidth}" height="24" fill="url(#bg)"/>
    <rect x="0.5" y="0.5" width="${totalWidth - 1}" height="23" rx="4.5" fill="none" stroke="${accentHex}" stroke-opacity="0.45"/>
  </g>
  <polygon points="10,6 15,9 15,15 10,18 5,15 5,9" fill="none" stroke="${accentHex}" stroke-width="1.35"/>
  <circle cx="10" cy="12" r="1.6" fill="${accentHex}"/>
  <g fill="#e2e8f0" font-family="ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace" font-size="10.5" font-weight="600">
    <text x="22" y="15.5" letter-spacing="0.4">${safeLeft}</text>
  </g>
  <g fill="${accentHex}" text-anchor="middle" font-family="ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace" font-size="10.5" font-weight="700">
    <text x="${Math.round(leftWidth + rightWidth / 2)}" y="15.5">${safeRight}</text>
  </g>
</svg>`;
}

/**
 * GET /api/badge/[programId]
 * Live dynamic SVG Trust Badge reading real AEGIS AuditAttestation PDAs on Solana Devnet.
 * Embed directly in any GitHub README: ![AEGIS Audit](https://.../api/badge/<PROGRAM_ID>)
 */
export async function GET(
  _req: NextRequest,
  context: { params: { programId: string } }
) {
  const rawId = context.params.programId?.trim() || "";

  let pubkey: PublicKey;
  try {
    pubkey = new PublicKey(rawId);
  } catch {
    const svg = buildBadgeSvg("AEGIS", "INVALID PROGRAM ID", "#f43f5e", "#271019");
    return new NextResponse(svg, {
      status: 400,
      headers: {
        "Content-Type": "image/svg+xml; charset=utf-8",
        "Cache-Control": "no-store",
      },
    });
  }

  try {
    const connection = new Connection(SOLANA_RPC_URL, "confirmed");
    const matches = await fetchAttestationsByTargetProgram(connection, pubkey, AEGIS_PROGRAM_ID);

    const best = matches[0];
    let svg: string;

    if (best && best.isVerifiedOracle) {
      const grade = gradeFromScore(best.securityScore);
      const color =
        best.securityScore >= 85 ? "#2dd4bf" : best.securityScore >= 60 ? "#fbbf24" : "#fb7185";
      const bg =
        best.securityScore >= 85 ? "#082422" : best.securityScore >= 60 ? "#241b0a" : "#260f16";
      svg = buildBadgeSvg(
        "AEGIS AUDIT",
        `ED25519 VERIFIED · ${best.securityScore}/100 (${grade})`,
        color,
        bg
      );
    } else if (best) {
      const grade = gradeFromScore(best.securityScore);
      svg = buildBadgeSvg(
        "AEGIS AUDIT",
        `SELF-ATTESTED · ${best.securityScore}/100 (${grade})`,
        "#fbbf24",
        "#241b0a"
      );
    } else {
      svg = buildBadgeSvg("AEGIS AUDIT", "UNAUDITED ON-CHAIN", "#94a3b8", "#111827");
    }

    return new NextResponse(svg, {
      status: 200,
      headers: {
        "Content-Type": "image/svg+xml; charset=utf-8",
        "Cache-Control": "public, max-age=60, s-maxage=60, stale-while-revalidate=300",
      },
    });
  } catch {
    const svg = buildBadgeSvg("AEGIS AUDIT", "RPC UNAVAILABLE", "#94a3b8", "#111827");
    return new NextResponse(svg, {
      status: 200,
      headers: {
        "Content-Type": "image/svg+xml; charset=utf-8",
        "Cache-Control": "no-store",
      },
    });
  }
}
