import { NextRequest, NextResponse } from "next/server";
import { PublicKey } from "@solana/web3.js";
import {
  EVM_CHAINS,
  formatTokenUnits,
  LIFI_SOLANA_CHAIN_ID,
  LifiNormalizedQuote,
  SOL_NATIVE_ADDRESS,
  SOL_USDC_ADDRESS,
  toBaseUnits,
} from "@/lib/lifi/client";
import { DEFAULT_TREASURY_ADDRESS } from "@/lib/x402/protocol";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

const EVM_ADDR_RE = /^0x[a-fA-F0-9]{40}$/;

/**
 * GET /api/lifi/quote
 * Queries live LI.FI REST API (https://li.quest/v1/quote) for real executable cross-chain routing:
 * - mode=fund   : EVM Chain (ARB/BASE/POL/ETH USDC) -> Solana (SOL or USDC)
 * - mode=payout : Solana (SOL or USDC) -> EVM Chain (ARB/BASE/POL/ETH USDC)
 * Returns the complete, un-truncated `transactionRequest` ready for Solana VersionedTransaction or EVM wallet execution.
 */
export async function GET(req: NextRequest) {
  const { searchParams } = req.nextUrl;
  const mode = searchParams.get("mode") === "payout" ? "payout" : "fund";
  const evmChainKey = (searchParams.get("evmChain") || "ARB").toUpperCase();
  const solToken = (searchParams.get("solToken") || "SOL").toUpperCase();
  const amountHuman = searchParams.get("amount") || (mode === "fund" ? "50" : "0.5");
  const solAddress = (searchParams.get("solAddress") || DEFAULT_TREASURY_ADDRESS).trim();
  const evmAddress = (
    searchParams.get("evmAddress") || "0x552008c0f6870c2f77e5cC1d2eb9bdff03e30Ea0"
  ).trim();

  // Strict address validation before hitting upstream LI.FI
  if (!EVM_ADDR_RE.test(evmAddress)) {
    return NextResponse.json(
      { error: "Invalid EVM address format (expected 0x followed by 40 hex chars)." },
      { status: 400 }
    );
  }
  try {
    new PublicKey(solAddress);
  } catch {
    return NextResponse.json(
      { error: "Invalid Solana Base58 address format." },
      { status: 400 }
    );
  }

  const evmChain = EVM_CHAINS.find((c) => c.id === evmChainKey) || EVM_CHAINS[0];
  const isSolNative = solToken === "SOL";
  const solTokenAddress = isSolNative ? SOL_NATIVE_ADDRESS : SOL_USDC_ADDRESS;
  const solDecimals = isSolNative ? 9 : 6;

  const fromChain = mode === "fund" ? evmChain.lifiId : LIFI_SOLANA_CHAIN_ID;
  const toChain = mode === "fund" ? LIFI_SOLANA_CHAIN_ID : evmChain.lifiId;
  const fromToken = mode === "fund" ? evmChain.tokenAddress : solTokenAddress;
  const toToken = mode === "fund" ? solTokenAddress : evmChain.tokenAddress;
  const fromDecimals = mode === "fund" ? evmChain.decimals : solDecimals;
  const toDecimals = mode === "fund" ? solDecimals : evmChain.decimals;
  const fromAmount = toBaseUnits(amountHuman, fromDecimals);
  const fromAddress = mode === "fund" ? evmAddress : solAddress;
  const toAddress = mode === "fund" ? solAddress : evmAddress;

  if (!fromAmount || fromAmount === "0") {
    return NextResponse.json({ error: "Amount must be greater than zero." }, { status: 400 });
  }

  const lifiParams = new URLSearchParams({
    fromChain,
    toChain,
    fromToken,
    toToken,
    fromAmount,
    fromAddress,
    toAddress,
    integrator: "aegis-solana",
    slippage: "0.01",
  });

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12_000);

  try {
    const res = await fetch(`https://li.quest/v1/quote?${lifiParams.toString()}`, {
      headers: { Accept: "application/json" },
      cache: "no-store",
      signal: controller.signal,
    });

    const data = await res.json();

    if (!res.ok) {
      return NextResponse.json(
        {
          error: data?.message || "LI.FI could not find a route for this amount/pair.",
          code: data?.code,
        },
        { status: res.status }
      );
    }

    const estimate = data.estimate || {};
    const gasCosts = Array.isArray(estimate.gasCosts) ? estimate.gasCosts : [];
    const feeCosts = Array.isArray(estimate.feeCosts) ? estimate.feeCosts : [];
    const gasCostUSD = gasCosts
      .reduce((acc: number, item: { amountUSD?: string }) => acc + Number(item.amountUSD || 0), 0)
      .toFixed(4);
    const feeCostUSD = feeCosts
      .reduce((acc: number, item: { amountUSD?: string }) => acc + Number(item.amountUSD || 0), 0)
      .toFixed(4);

    const includedSteps = Array.isArray(data.includedSteps) ? data.includedSteps : [];

    const normalized: LifiNormalizedQuote = {
      id: data.id || `lifi-${Date.now()}`,
      tool: data.tool || "lifi",
      toolName: data.toolDetails?.name || data.tool || "LI.FI Router",
      toolLogoURI: data.toolDetails?.logoURI,
      fromChain: mode === "fund" ? evmChain.name : "Solana",
      toChain: mode === "fund" ? "Solana" : evmChain.name,
      fromChainId: fromChain,
      toChainId: toChain,
      fromTokenSymbol:
        data.action?.fromToken?.symbol || (mode === "fund" ? evmChain.tokenSymbol : solToken),
      toTokenSymbol:
        data.action?.toToken?.symbol || (mode === "fund" ? solToken : evmChain.tokenSymbol),
      fromAmountFormatted: formatTokenUnits(data.action?.fromAmount || fromAmount, fromDecimals),
      toAmountFormatted: formatTokenUnits(estimate.toAmount || "0", toDecimals),
      toAmountMinFormatted: formatTokenUnits(estimate.toAmountMin || "0", toDecimals),
      fromAmountUSD: estimate.fromAmountUSD || "0.00",
      toAmountUSD: estimate.toAmountUSD || "0.00",
      executionDurationSec: Number(estimate.executionDuration || 30),
      gasCostUSD,
      feeCostUSD,
      approvalAddress: estimate.approvalAddress,
      steps: includedSteps.map((s: any) => ({
        type: s.type || "cross",
        tool: s.tool || "bridge",
        toolName: s.toolDetails?.name || s.tool || "LI.FI Step",
        fromChainId: s.action?.fromChainId ?? fromChain,
        toChainId: s.action?.toChainId ?? toChain,
      })),
      hasTransactionRequest: Boolean(data.transactionRequest),
      // Full, un-truncated transactionRequest for live Solana / EVM execution
      transactionRequest: data.transactionRequest || undefined,
    };

    return NextResponse.json({ quote: normalized, mode }, { status: 200 });
  } catch (err: any) {
    const isTimeout = err?.name === "AbortError";
    return NextResponse.json(
      {
        error: isTimeout
          ? "LI.FI API timed out after 12s. Please retry."
          : `Failed to reach LI.FI API: ${err?.message || "network error"}`,
      },
      { status: isTimeout ? 504 : 502 }
    );
  } finally {
    clearTimeout(timeout);
  }
}
