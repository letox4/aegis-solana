import { NextRequest, NextResponse } from "next/server";
import { PublicKey } from "@solana/web3.js";
import { InspectCluster, inspectSolanaProgramOnChain } from "@/lib/solana/programInspector";

export const dynamic = "force-dynamic";

function parseCluster(raw?: string | null): InspectCluster {
  return raw === "mainnet-beta" || raw === "mainnet" ? "mainnet-beta" : "devnet";
}

export async function GET(req: NextRequest) {
  const programId = req.nextUrl.searchParams.get("programId")?.trim();
  const cluster = parseCluster(req.nextUrl.searchParams.get("cluster"));

  if (!programId) {
    return NextResponse.json(
      { error: "Missing ?programId=<Base58> query parameter." },
      { status: 400 }
    );
  }

  try {
    new PublicKey(programId);
  } catch {
    return NextResponse.json(
      { error: "Invalid Solana Program ID (must be valid Base58 public key)." },
      { status: 400 }
    );
  }

  try {
    const inspection = await inspectSolanaProgramOnChain(programId, cluster);
    return NextResponse.json(inspection, { status: 200 });
  } catch (err: any) {
    return NextResponse.json(
      { error: err?.message || "Failed to inspect program on Solana RPC." },
      { status: 502 }
    );
  }
}

export async function POST(req: NextRequest) {
  let body: { programId?: string; cluster?: string } = {};
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const programId = body.programId?.trim();
  if (!programId) {
    return NextResponse.json({ error: "Provide a Solana Program ID to inspect." }, { status: 400 });
  }

  try {
    new PublicKey(programId);
  } catch {
    return NextResponse.json(
      { error: "Invalid Solana Program ID (must be valid Base58 public key)." },
      { status: 400 }
    );
  }

  const cluster = parseCluster(body.cluster);

  try {
    const inspection = await inspectSolanaProgramOnChain(programId, cluster);
    return NextResponse.json(inspection, { status: 200 });
  } catch (err: any) {
    return NextResponse.json(
      { error: err?.message || "Failed to inspect program on Solana RPC." },
      { status: 502 }
    );
  }
}
