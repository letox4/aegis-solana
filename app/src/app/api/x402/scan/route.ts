import { NextRequest, NextResponse } from "next/server";
import { analyzeSolanaContract, MAX_SCAN_CODE_BYTES } from "@/lib/scanner/solanaRules";
import {
  buildPaymentRequired,
  computeMemoBinding,
  decodeBase64Json,
  DEFAULT_TREASURY_ADDRESS,
  encodeBase64Json,
  SCAN_PRICE_LAMPORTS,
  signOracleAuditAttestation,
  SOLANA_DEVNET_CAIP2,
  verifySolanaDevnetPayment,
  X402PaymentResponsePayload,
  X402PaymentSignaturePayload,
} from "@/lib/x402/protocol";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

const EXPOSE_HEADERS =
  "PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-PAYMENT-REQUIRED, X-PAYMENT-RESPONSE";

export async function GET(req: NextRequest) {
  const resourceUrl = req.nextUrl.toString();
  const sampleMemo = "aegis:<sha256(code)[0..16]>";
  const paymentRequired = buildPaymentRequired(resourceUrl, DEFAULT_TREASURY_ADDRESS, sampleMemo);

  return NextResponse.json(
    {
      service: "AEGIS Solana Security Scanner API",
      version: "3.0.0",
      protocol: "x402 V2 (Solana Devnet + SPL Memo Binding + Ed25519 Oracle Attestation)",
      status: "operational",
      rulesCount: 20,
      maxCodeBytes: MAX_SCAN_CODE_BYTES,
      endpoints: {
        x402Scan: "POST /api/x402/scan",
        sponsoredJudgeDemo: "POST /api/x402/judge-demo",
        githubRepoFetcher: "POST /api/scanner/github",
        liveOnChainProgramInspector: "GET|POST /api/solana/inspect",
        dynamicOnChainSvgBadge: "GET /api/badge/:programId",
        solanaProgramState: "GET /api/solana/state",
      },
      howItWorks: [
        "1. POST /api/x402/scan with { code, targetName, targetProgramId } (supports single-file or multi-file GitHub payloads)",
        "2. Server returns HTTP 402 + PAYMENT-REQUIRED with payTo, 0.001 SOL, and anti-sniping memoRequired",
        "3. Client sends 0.001 SOL + SPL Memo(memoRequired) on Solana Devnet",
        "4. Client retries POST with Base64 PAYMENT-SIGNATURE header",
        "5. Server verifies transfer & memo atomically on Devnet, runs 20 Inter-Procedural Sealevel, Token-2022 & CPI detectors with visual patch diffs & Anchor TS exploit PoCs, and signs an Ed25519 oracle attestation",
      ],
      paymentRequired,
    },
    { status: 200 }
  );
}

export async function POST(req: NextRequest) {
  // Guard against oversized payloads / DoS before parsing JSON
  const contentLength = Number(req.headers.get("content-length") || "0");
  if (contentLength > MAX_SCAN_CODE_BYTES + 16_384) {
    return NextResponse.json(
      { error: `Payload too large. Max source code size is ${MAX_SCAN_CODE_BYTES} bytes.` },
      { status: 413 }
    );
  }

  let body: { code?: string; targetName?: string; targetProgramId?: string } = {};
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { error: "Invalid JSON body. Expected { code, targetName?, targetProgramId? }" },
      { status: 400 }
    );
  }

  const sourceCode = body.code?.trim();
  if (!sourceCode || sourceCode.length < 20) {
    return NextResponse.json(
      { error: "Provide at least 20 characters of Solana/Rust source code to scan." },
      { status: 400 }
    );
  }
  if (Buffer.byteLength(sourceCode, "utf-8") > MAX_SCAN_CODE_BYTES) {
    return NextResponse.json(
      { error: `Source code exceeds ${MAX_SCAN_CODE_BYTES} byte limit.` },
      { status: 413 }
    );
  }

  const resourceUrl = req.nextUrl.toString();
  const memoRequired = computeMemoBinding(sourceCode);
  const paymentRequired = buildPaymentRequired(
    resourceUrl,
    DEFAULT_TREASURY_ADDRESS,
    memoRequired
  );
  const paymentRequiredB64 = encodeBase64Json(paymentRequired);

  const corsHeaders = {
    "PAYMENT-REQUIRED": paymentRequiredB64,
    "X-PAYMENT-REQUIRED": paymentRequiredB64,
    "Access-Control-Expose-Headers": EXPOSE_HEADERS,
  };

  const rawPaymentHeader =
    req.headers.get("payment-signature") || req.headers.get("x-payment");

  if (!rawPaymentHeader) {
    return NextResponse.json(
      {
        error: "Payment Required (x402 V2)",
        message: `Settle 0.001 SOL with SPL Memo "${memoRequired}" on Solana Devnet and retry with PAYMENT-SIGNATURE header.`,
        x402: paymentRequired,
      },
      { status: 402, headers: corsHeaders }
    );
  }

  const decoded = decodeBase64Json<X402PaymentSignaturePayload>(rawPaymentHeader);
  const txSignature =
    decoded?.payload?.signature ||
    (typeof (decoded as unknown as { signature?: string })?.signature === "string"
      ? (decoded as unknown as { signature: string }).signature
      : "");

  if (!txSignature) {
    return NextResponse.json(
      {
        error: "Malformed PAYMENT-SIGNATURE header",
        expectedFormat: "Base64-encoded x402 V2 PaymentPayload containing payload.signature",
        x402: paymentRequired,
      },
      { status: 402, headers: corsHeaders }
    );
  }

  // Validate `accepted` fields if client supplied them
  if (decoded?.accepted) {
    if (decoded.accepted.network && decoded.accepted.network !== SOLANA_DEVNET_CAIP2) {
      return NextResponse.json(
        {
          error: "x402 Network Mismatch",
          reason: `Expected ${SOLANA_DEVNET_CAIP2}, got ${decoded.accepted.network}`,
          x402: paymentRequired,
        },
        { status: 402, headers: corsHeaders }
      );
    }
    if (decoded.accepted.payTo && decoded.accepted.payTo !== DEFAULT_TREASURY_ADDRESS) {
      return NextResponse.json(
        {
          error: "x402 Recipient Mismatch",
          reason: `Expected payTo ${DEFAULT_TREASURY_ADDRESS}`,
          x402: paymentRequired,
        },
        { status: 402, headers: corsHeaders }
      );
    }
    if (decoded.accepted.amount) {
      try {
        if (BigInt(decoded.accepted.amount) < BigInt(SCAN_PRICE_LAMPORTS)) {
          return NextResponse.json(
            {
              error: "x402 Amount Below Minimum",
              reason: `Expected >= ${SCAN_PRICE_LAMPORTS} lamports, got ${decoded.accepted.amount}`,
              x402: paymentRequired,
            },
            { status: 402, headers: corsHeaders }
          );
        }
      } catch {
        return NextResponse.json(
          { error: "Invalid accepted.amount format", x402: paymentRequired },
          { status: 402, headers: corsHeaders }
        );
      }
    }
  }

  // Atomic Solana Devnet payment + Memo verification (anti-TOCTOU, anti-replay, anti-sniping)
  const verification = await verifySolanaDevnetPayment(
    txSignature,
    DEFAULT_TREASURY_ADDRESS,
    memoRequired,
    SCAN_PRICE_LAMPORTS
  );

  if (!verification.valid) {
    return NextResponse.json(
      {
        error: "x402 Payment Verification Failed",
        reason: verification.error,
        x402: paymentRequired,
      },
      { status: 402, headers: corsHeaders }
    );
  }

  const report = analyzeSolanaContract(
    sourceCode,
    body.targetName || "Solana Program Audit",
    body.targetProgramId
  );

  // Produce cryptographic Ed25519 Oracle Attestation Proof verifiable by our Solana smart contract
  const oracleAttestation = body.targetProgramId
    ? signOracleAuditAttestation({
        targetProgramId: body.targetProgramId,
        sourceCodeSha256: report.sourceCodeSha256,
        reportHashHex: report.reportHashHex,
        securityScore: report.securityScore,
        criticalCount: report.summary.critical,
        highCount: report.summary.high,
        x402PaymentSig: txSignature,
      })
    : null;

  const paymentResponse: X402PaymentResponsePayload = {
    x402Version: 2,
    success: true,
    network: SOLANA_DEVNET_CAIP2,
    transaction: txSignature,
    payer: verification.payer || "verified-payer",
    payTo: DEFAULT_TREASURY_ADDRESS,
    amountLamports: String(verification.amountLamports || SCAN_PRICE_LAMPORTS),
    memoBound: memoRequired,
    settledAt: new Date().toISOString(),
    explorerUrl: `https://explorer.solana.com/tx/${txSignature}?cluster=devnet`,
  };

  const paymentResponseB64 = encodeBase64Json(paymentResponse);

  return NextResponse.json(
    {
      protocol: "x402-v2",
      paymentReceipt: paymentResponse,
      report,
      oracleAttestation,
    },
    {
      status: 200,
      headers: {
        "PAYMENT-RESPONSE": paymentResponseB64,
        "X-PAYMENT-RESPONSE": paymentResponseB64,
        "Access-Control-Expose-Headers": EXPOSE_HEADERS,
      },
    }
  );
}
