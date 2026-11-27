import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";
export const maxDuration = 30;

/**
 * GET /api/lifi/status
 * Polls live LI.FI cross-chain bridge execution status (https://li.quest/v1/status)
 * for any submitted Solana or EVM transaction hash.
 */
export async function GET(req: NextRequest) {
  const { searchParams } = req.nextUrl;
  const txHash = (searchParams.get("txHash") || "").trim();
  const bridge = (searchParams.get("bridge") || "").trim();
  const fromChain = (searchParams.get("fromChain") || "").trim();
  const toChain = (searchParams.get("toChain") || "").trim();

  if (!txHash || txHash.length < 16) {
    return NextResponse.json({ error: "Provide a valid txHash to track." }, { status: 400 });
  }

  const params = new URLSearchParams({ txHash });
  if (bridge) params.set("bridge", bridge);
  if (fromChain) params.set("fromChain", fromChain);
  if (toChain) params.set("toChain", toChain);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  try {
    const res = await fetch(`https://li.quest/v1/status?${params.toString()}`, {
      headers: { Accept: "application/json" },
      cache: "no-store",
      signal: controller.signal,
    });
    const data = await res.json();

    return NextResponse.json(
      {
        status: data.status || "PENDING",
        substatus: data.substatus,
        substatusMessage: data.substatusMessage,
        sendingTxLink: data.sending?.txLink,
        receivingTxLink: data.receiving?.txLink,
        lifiExplorerLink: data.lifiExplorerLink || `https://scan.li.fi/tx/${txHash}`,
      },
      { status: res.ok ? 200 : res.status }
    );
  } catch (err: any) {
    return NextResponse.json(
      { error: `Failed to fetch LI.FI status: ${err?.message || "network error"}` },
      { status: 502 }
    );
  } finally {
    clearTimeout(timeout);
  }
}
