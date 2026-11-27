import { NextRequest, NextResponse } from "next/server";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import { analyzeSolanaContract, MAX_SCAN_CODE_BYTES } from "@/lib/scanner/solanaRules";
import {
  buildPaymentRequired,
  computeMemoBinding,
  DEFAULT_TREASURY_ADDRESS,
  encodeBase64Json,
  SCAN_PRICE_LAMPORTS,
  signOracleAuditAttestation,
  SOLANA_DEVNET_CAIP2,
  SOLANA_RPC_URL,
  SPL_MEMO_PROGRAM_ID,
  verifySolanaDevnetPayment,
  X402PaymentResponsePayload,
} from "@/lib/x402/protocol";

export const dynamic = "force-dynamic";

// Lightweight per-IP rate limiter (max 5 sponsored Devnet scans / 10 min per IP)
const ipUsage = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const rec = ipUsage.get(ip);
  if (!rec || now > rec.resetAt) {
    ipUsage.set(ip, { count: 1, resetAt: now + 10 * 60_000 });
    return true;
  }
  if (rec.count >= 5) return false;
  rec.count += 1;
  return true;
}

/**
 * POST /api/x402/judge-demo
 * Executes a 100% REAL on-chain Solana Devnet x402 V2 payment (0.001 SOL + SPL Memo)
 * from a dedicated funded Devnet sponsor wallet so hackathon judges without Phantom or
 * Devnet SOL can test the complete authentic x402 V2 + Ed25519 Oracle flow in 1 click!
 */
export async function POST(req: NextRequest) {
  const secretB64 = process.env.AEGIS_DEMO_SPONSOR_SECRET;
  if (!secretB64) {
    return NextResponse.json(
      { error: "Sponsored Devnet demo wallet is not configured on this server." },
      { status: 503 }
    );
  }

  const clientIp =
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("x-real-ip") ||
    "local";
  if (!checkRateLimit(clientIp)) {
    return NextResponse.json(
      { error: "Rate limit reached (5 sponsored scans per 10 minutes). Connect your own Devnet wallet to continue." },
      { status: 429 }
    );
  }

  let body: { code?: string; targetName?: string; targetProgramId?: string } = {};
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const sourceCode = body.code?.trim();
  if (!sourceCode || sourceCode.length < 20) {
    return NextResponse.json({ error: "Provide at least 20 characters of source code." }, { status: 400 });
  }
  if (Buffer.byteLength(sourceCode, "utf-8") > MAX_SCAN_CODE_BYTES) {
    return NextResponse.json({ error: "Source code exceeds 100KB limit." }, { status: 413 });
  }

  try {
    const sponsorKp = Keypair.fromSecretKey(Uint8Array.from(Buffer.from(secretB64, "base64")));
    const connection = new Connection(SOLANA_RPC_URL, "confirmed");
    const memoRequired = computeMemoBinding(sourceCode);
    const paymentRequired = buildPaymentRequired(
      `${req.nextUrl.origin}/api/x402/scan`,
      DEFAULT_TREASURY_ADDRESS,
      memoRequired
    );

    // Broadcast a REAL 0.001 SOL + SPL Memo transaction on Solana Devnet
    const tx = new Transaction()
      .add(
        SystemProgram.transfer({
          fromPubkey: sponsorKp.publicKey,
          toPubkey: new PublicKey(DEFAULT_TREASURY_ADDRESS),
          lamports: SCAN_PRICE_LAMPORTS,
        })
      )
      .add(
        new TransactionInstruction({
          programId: new PublicKey(SPL_MEMO_PROGRAM_ID),
          keys: [{ pubkey: sponsorKp.publicKey, isSigner: true, isWritable: false }],
          data: Buffer.from(memoRequired, "utf-8"),
        })
      );

    const txSig = await sendAndConfirmTransaction(connection, tx, [sponsorKp], {
      commitment: "confirmed",
    });

    // Run through the EXACT same on-chain x402 verification logic as regular wallet payments
    const verification = await verifySolanaDevnetPayment(
      txSig,
      DEFAULT_TREASURY_ADDRESS,
      memoRequired,
      SCAN_PRICE_LAMPORTS
    );
    if (!verification.valid) {
      return NextResponse.json(
        { error: "Sponsored Devnet TX failed x402 verification", reason: verification.error },
        { status: 500 }
      );
    }

    const report = analyzeSolanaContract(
      sourceCode,
      body.targetName || "Solana Program Audit",
      body.targetProgramId
    );

    const oracleAttestation = body.targetProgramId
      ? signOracleAuditAttestation({
          targetProgramId: body.targetProgramId,
          sourceCodeSha256: report.sourceCodeSha256,
          reportHashHex: report.reportHashHex,
          securityScore: report.securityScore,
          criticalCount: report.summary.critical,
          highCount: report.summary.high,
          x402PaymentSig: txSig,
        })
      : null;

    const paymentReceipt: X402PaymentResponsePayload = {
      x402Version: 2,
      success: true,
      network: SOLANA_DEVNET_CAIP2,
      transaction: txSig,
      payer: sponsorKp.publicKey.toBase58(),
      payTo: DEFAULT_TREASURY_ADDRESS,
      amountLamports: String(SCAN_PRICE_LAMPORTS),
      memoBound: memoRequired,
      settledAt: new Date().toISOString(),
      explorerUrl: `https://explorer.solana.com/tx/${txSig}?cluster=devnet`,
    };

    return NextResponse.json(
      {
        protocol: "x402-v2-sponsored-devnet",
        paymentRequired,
        paymentReceipt,
        report,
        oracleAttestation,
      },
      {
        status: 200,
        headers: {
          "PAYMENT-RESPONSE": encodeBase64Json(paymentReceipt),
          "Access-Control-Expose-Headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE",
        },
      }
    );
  } catch (err: any) {
    return NextResponse.json(
      { error: `Sponsored Devnet x402 TX failed: ${err?.message || "RPC error"}` },
      { status: 500 }
    );
  }
}
