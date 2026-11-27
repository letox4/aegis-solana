import { NextResponse } from "next/server";
import { Connection } from "@solana/web3.js";
import { AEGIS_PROGRAM_ID, fetchAllAegisOnChainState } from "@/lib/solana/aegisProgram";
import { DEFAULT_TREASURY_ADDRESS, SOLANA_RPC_URL } from "@/lib/x402/protocol";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

export async function GET() {
  try {
    const connection = new Connection(SOLANA_RPC_URL, "confirmed");
    const state = await fetchAllAegisOnChainState(connection, AEGIS_PROGRAM_ID);
    const programInfo = await connection.getAccountInfo(AEGIS_PROGRAM_ID);

    return NextResponse.json({
      cluster: "devnet",
      rpcUrl: SOLANA_RPC_URL,
      programId: AEGIS_PROGRAM_ID.toBase58(),
      programDeployed: Boolean(programInfo?.executable),
      treasuryAddress: DEFAULT_TREASURY_ADDRESS,
      ...state,
    });
  } catch (err: any) {
    return NextResponse.json(
      {
        error: err?.message || "Failed to fetch Solana Devnet state",
        programId: AEGIS_PROGRAM_ID.toBase58(),
      },
      { status: 503 }
    );
  }
}
