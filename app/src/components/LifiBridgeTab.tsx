"use client";

import React, { useState } from "react";
import { useWallet } from "@solana/wallet-adapter-react";
import { Connection, VersionedTransaction } from "@solana/web3.js";
import { Buffer } from "buffer";
import { MachinedPanel } from "@/components/MachinedPanel";
import { ChainGlyph } from "@/components/VisualPrimitives";
import {
  ArrowRightLeft,
  Globe,
  Clock,
  Fuel,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  Layers,
  Sparkles,
  Play,
  RefreshCw,
  Info,
} from "lucide-react";
import {
  EVM_CHAINS,
  LifiNormalizedQuote,
  LifiStatusResult,
  SOLANA_TOKENS,
  toBaseUnits,
} from "@/lib/lifi/client";
import type { OnChainBountyVault } from "@/lib/solana/aegisProgram";

declare global {
  interface Window {
    ethereum?: {
      request: (args: { method: string; params?: unknown[] }) => Promise<any>;
    };
  }
}

function padHex32(hexNoPrefix: string): string {
  return hexNoPrefix.toLowerCase().replace(/^0x/, "").padStart(64, "0");
}

interface LifiBridgeTabProps {
  bounties?: OnChainBountyVault[];
}

export function LifiBridgeTab({ bounties = [] }: LifiBridgeTabProps) {
  const { publicKey, sendTransaction } = useWallet();

  const [mode, setMode] = useState<"fund" | "payout">("fund");
  const [selectedVaultAddr, setSelectedVaultAddr] = useState<string>("");
  const [evmChain, setEvmChain] = useState("ARB");
  const [solToken, setSolToken] = useState("SOL");
  const [amount, setAmount] = useState("50");
  const [evmAddress, setEvmAddress] = useState("0x552008c0f6870c2f77e5cC1d2eb9bdff03e30Ea0");

  const [loading, setLoading] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [execStage, setExecStage] = useState<string>("");
  const [quote, setQuote] = useState<LifiNormalizedQuote | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [executedTxHash, setExecutedTxHash] = useState<string>("");
  const [bridgeStatus, setBridgeStatus] = useState<LifiStatusResult | null>(null);
  const [checkingStatus, setCheckingStatus] = useState(false);

  const selectedEvmChain = EVM_CHAINS.find((c) => c.id === evmChain) || EVM_CHAINS[0];
  const activeVaults = bounties.filter((b) => b.isActive);
  const targetVault = activeVaults.find((b) => b.address === selectedVaultAddr) || activeVaults[0];

  async function handleConnectEvm() {
    setError(null);
    if (typeof window === "undefined" || !window.ethereum) {
      setError("No EVM wallet (MetaMask / Rabby) detected in this browser.");
      return;
    }
    try {
      const accounts: string[] = await window.ethereum.request({
        method: "eth_requestAccounts",
      });
      if (accounts?.[0]) {
        setEvmAddress(accounts[0]);
      }
    } catch (err: any) {
      setError(err?.message || "EVM wallet connection rejected.");
    }
  }

  async function handleFetchQuote(e?: React.FormEvent) {
    if (e) e.preventDefault();
    setLoading(true);
    setError(null);
    setBridgeStatus(null);
    setExecutedTxHash("");

    try {
      const params = new URLSearchParams({
        mode,
        evmChain,
        solToken,
        amount,
        evmAddress: evmAddress.trim(),
        ...(publicKey ? { solAddress: publicKey.toBase58() } : {}),
      });

      const res = await fetch(`/api/lifi/quote?${params.toString()}`);
      const data = await res.json();
      if (!res.ok) {
        setQuote(null);
        setError(data?.error || "LI.FI could not quote this route right now.");
      } else {
        setQuote(data.quote);
      }
    } catch (err: any) {
      setError(err?.message || "Failed to contact LI.FI API.");
    } finally {
      setLoading(false);
    }
  }

  async function handleExecuteRoute() {
    if (!quote?.transactionRequest) return;
    setError(null);
    setExecuting(true);
    setExecStage("");
    setBridgeStatus(null);

    try {
      if (mode === "payout") {
        // Real Solana -> EVM execution via dedicated Solana Mainnet RPC (NOT Devnet connection!)
        if (!publicKey) {
          throw new Error("Connect your Phantom or Solflare wallet first (switched to Mainnet for live LI.FI bridge).");
        }
        const txDataB64 = quote.transactionRequest.data;
        if (!txDataB64) {
          throw new Error("LI.FI did not return serialized Solana transaction bytes.");
        }
        setExecStage("Signing Solana Mainnet VersionedTransaction...");
        const mainnetConn = new Connection(
          process.env.NEXT_PUBLIC_SOLANA_MAINNET_RPC_URL || "https://api.mainnet-beta.solana.com",
          "confirmed"
        );
        const rawBytes = Buffer.from(txDataB64, "base64");
        const vtx = VersionedTransaction.deserialize(rawBytes);
        const sig = await sendTransaction(vtx, mainnetConn);
        setExecutedTxHash(sig);
        await pollBridgeStatus(sig, quote);
      } else {
        // Real EVM -> Solana bounty funding execution via injected EVM wallet (MetaMask/Rabby)
        if (typeof window === "undefined" || !window.ethereum) {
          throw new Error("Install or unlock MetaMask / Rabby to execute EVM -> Solana bridge transactions.");
        }
        const accounts: string[] = await window.ethereum.request({
          method: "eth_requestAccounts",
        });
        const activeFrom = accounts?.[0];
        if (!activeFrom) throw new Error("No active EVM account found.");

        try {
          await window.ethereum.request({
            method: "wallet_switchEthereumChain",
            params: [{ chainId: selectedEvmChain.hexChainId }],
          });
        } catch (switchErr: any) {
          throw new Error(
            `Please switch your EVM wallet to ${selectedEvmChain.name} (${switchErr?.message || "chain switch required"}).`
          );
        }

        // Automatic ERC-20 allowance check + approve() toward quote.approvalAddress if needed
        if (quote.approvalAddress) {
          setExecStage("Checking ERC-20 USDC allowance...");
          const requiredAmount = BigInt(toBaseUnits(amount, selectedEvmChain.decimals));
          const allowanceCalldata =
            "0xdd62ed3e" + padHex32(activeFrom) + padHex32(quote.approvalAddress);
          const rawAllowance: string = await window.ethereum.request({
            method: "eth_call",
            params: [{ to: selectedEvmChain.tokenAddress, data: allowanceCalldata }, "latest"],
          });
          const currentAllowance = rawAllowance && rawAllowance !== "0x" ? BigInt(rawAllowance) : 0n;

          if (currentAllowance < requiredAmount) {
            setExecStage(`Approving ${amount} USDC for LI.FI Router...`);
            const approveCalldata =
              "0x095ea7b3" +
              padHex32(quote.approvalAddress) +
              requiredAmount.toString(16).padStart(64, "0");
            await window.ethereum.request({
              method: "eth_sendTransaction",
              params: [
                {
                  from: activeFrom,
                  to: selectedEvmChain.tokenAddress,
                  data: approveCalldata,
                  value: "0x0",
                },
              ],
            });
            // Wait briefly for approval confirmation before submitting bridge TX
            await new Promise((r) => setTimeout(r, 4000));
          }
        }

        setExecStage(`Submitting LI.FI bridge TX on ${selectedEvmChain.name}...`);
        const txReq = quote.transactionRequest;
        const txHash: string = await window.ethereum.request({
          method: "eth_sendTransaction",
          params: [
            {
              from: activeFrom,
              to: txReq.to,
              data: txReq.data,
              value: txReq.value || "0x0",
              ...(txReq.gasLimit ? { gas: txReq.gasLimit } : {}),
            },
          ],
        });
        setExecutedTxHash(txHash);
        await pollBridgeStatus(txHash, quote);
      }
    } catch (err: any) {
      setError(err?.message || "Bridge transaction cancelled or failed.");
    } finally {
      setExecuting(false);
      setExecStage("");
    }
  }

  async function pollBridgeStatus(txHashToTrack?: string, activeQuote?: LifiNormalizedQuote | null) {
    const hash = (txHashToTrack ?? executedTxHash).trim();
    const q = activeQuote ?? quote;
    if (!hash) return;
    setCheckingStatus(true);
    try {
      const params = new URLSearchParams({ txHash: hash });
      if (q?.tool) params.set("bridge", q.tool);
      if (q?.fromChainId) params.set("fromChain", q.fromChainId);
      if (q?.toChainId) params.set("toChain", q.toChainId);
      const res = await fetch(`/api/lifi/status?${params.toString()}`);
      const data = await res.json();
      if (res.ok) {
        setBridgeStatus(data);
      } else {
        setError(data?.error || "Status lookup failed.");
      }
    } catch (err: any) {
      setError(err?.message || "Failed to poll LI.FI status.");
    } finally {
      setCheckingStatus(false);
    }
  }

  function switchMode(nextMode: "fund" | "payout") {
    setMode(nextMode);
    setAmount(nextMode === "fund" ? "50" : "0.5");
    setQuote(null);
    setBridgeStatus(null);
    setExecutedTxHash("");
    setError(null);
  }

  return (
    <div className="space-y-5">
      {/* Compact minimal mode toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3 text-xs text-slate-400">
          <span className="font-mono text-slate-200">LI.FI</span>
          <span className="h-3 w-px bg-slate-800" />
          <span className="inline-flex items-center gap-1.5">
            <Info className="h-3 w-3 text-slate-500" />
            Mainnet liquidity execution · Devnet bounty vaults
          </span>
        </div>

        <div className="aegis-subbox flex rounded-xl p-1">
          <button
            onClick={() => switchMode("fund")}
            className={`rounded-lg px-3.5 py-1.5 text-xs font-medium transition ${
              mode === "fund" ? "bg-slate-200 text-slate-950" : "text-slate-400 hover:text-white"
            }`}
          >
            Fund Bounty (EVM → SOL)
          </button>
          <button
            onClick={() => switchMode("payout")}
            className={`rounded-lg px-3.5 py-1.5 text-xs font-medium transition ${
              mode === "payout" ? "bg-teal-400 text-slate-950" : "text-slate-400 hover:text-white"
            }`}
          >
            Whitehat Payout (SOL → EVM)
          </button>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-12">
        {/* Route Config Form */}
        <MachinedPanel variant="solana" delay={0.05} className="p-5 lg:col-span-5">
        <form onSubmit={handleFetchQuote} className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-semibold text-white">
              <ArrowRightLeft className="h-4 w-4 text-teal-300" />
              <span>
                {mode === "fund"
                  ? "Route Treasury Funds into Solana"
                  : "Withdraw Solana Bounty to EVM Chain"}
              </span>
            </div>
            <button
              type="button"
              onClick={handleConnectEvm}
              className="rounded-md border border-slate-600/60 bg-slate-900 px-2.5 py-1 font-mono text-[10px] text-slate-300 hover:border-teal-400/50 hover:text-white"
            >
              Connect MetaMask
            </button>
          </div>

          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-300">
              {mode === "fund" ? "Source EVM Treasury Chain (USDC)" : "Destination EVM Chain (USDC)"}
            </label>
            <div className="grid grid-cols-2 gap-2">
              {EVM_CHAINS.map((c) => (
                <button
                  type="button"
                  key={c.id}
                  onClick={() => setEvmChain(c.id)}
                  className={`flex items-center justify-between rounded-xl border px-3 py-2 text-xs font-semibold transition ${
                    evmChain === c.id
                      ? "border-teal-400/60 bg-teal-500/10 text-white"
                      : "border-slate-800 bg-slate-950 text-slate-400 hover:border-slate-600"
                  }`}
                >
                  <span className="inline-flex items-center gap-2">
                    <ChainGlyph chain={c.id} size={20} />
                    <span>{c.name}</span>
                  </span>
                  <span className="font-mono text-[10px] text-slate-400">{c.tokenSymbol}</span>
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-300">
                {mode === "fund" ? "Receive on Solana" : "Pay from Solana"}
              </label>
              <select
                value={solToken}
                onChange={(e) => setSolToken(e.target.value)}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-semibold text-white outline-none focus:border-teal-400"
              >
                {SOLANA_TOKENS.map((t) => (
                  <option key={t.symbol} value={t.symbol}>
                    {t.symbol} — {t.name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-300">
                Amount ({mode === "fund" ? "USDC" : solToken})
              </label>
              <input
                type="number"
                step="any"
                min="0.01"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                required
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-white outline-none focus:border-teal-400"
              />
            </div>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-300">
              {mode === "fund" ? "Source EVM Treasury Address" : "Destination EVM Payout Address"}
            </label>
            <input
              value={evmAddress}
              onChange={(e) => setEvmAddress(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-300 outline-none focus:border-teal-400"
            />
          </div>

          {mode === "fund" && activeVaults.length > 0 && (
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-300">
                Target AEGIS Bounty Vault (Post-Bridge Top-Up)
              </label>
              <select
                value={targetVault?.address || ""}
                onChange={(e) => setSelectedVaultAddr(e.target.value)}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white outline-none focus:border-teal-400"
              >
                {activeVaults.map((v) => (
                  <option key={v.address} value={v.address}>
                    {v.targetName} (PDA {v.address.slice(0, 8)}... → top_up_bounty)
                  </option>
                ))}
              </select>
            </div>
          )}

          <div className="aegis-subbox rounded-lg px-3 py-2 font-mono text-[11px] text-slate-400">
            Solana Endpoint:{" "}
            <span className="text-teal-300">
              {publicKey
                ? `${publicKey.toBase58().slice(0, 12)}...${publicKey.toBase58().slice(-8)}`
                : "Using AEGIS Solana Vault Treasury"}
            </span>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="flex w-full items-center justify-center gap-2 rounded-xl border border-teal-300/40 bg-gradient-to-r from-teal-400 to-emerald-300 px-4 py-2.5 text-sm font-bold text-slate-950 transition hover:brightness-105 disabled:opacity-50"
          >
            <Sparkles className="h-4 w-4" />
            {loading ? "Querying Live LI.FI Bridges & DEXs..." : "1. Fetch Live LI.FI Cross-Chain Route"}
          </button>
        </form>
        </MachinedPanel>

        {/* Live Quote Result + Real Execution Panel */}
        <MachinedPanel variant="steel" delay={0.1} className="p-5 lg:col-span-7">
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="h-4 w-4 text-teal-300" />
              <h3 className="font-display text-sm font-semibold text-white">
                Live LI.FI Optimal Route & Execution Engine
              </h3>
            </div>
            {quote && (
              <span className="inline-flex items-center gap-1 rounded-full border border-teal-500/40 bg-teal-500/10 px-2.5 py-0.5 font-mono text-[10px] text-teal-200">
                <CheckCircle2 className="h-3 w-3" />
                EXECUTABLE PAYLOAD READY
              </span>
            )}
          </div>

          {error && (
            <div className="mb-4 flex items-center gap-2 rounded-xl border border-rose-500/40 bg-rose-500/10 p-3.5 text-xs text-rose-200">
              <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
              <span>{error}</span>
            </div>
          )}

          {!quote && !error && (
            <div className="flex h-64 flex-col items-center justify-center rounded-xl border border-dashed border-slate-800/90 bg-[#05080f]/60 p-6">
              <div className="flex items-center gap-4">
                <div className="flex flex-col items-center gap-1.5 rounded-xl border border-slate-800 bg-[#090e18] px-4 py-3">
                  <ChainGlyph chain={mode === "fund" ? evmChain : "SOL"} size={28} />
                  <span className="text-xs font-semibold text-slate-200">
                    {mode === "fund" ? selectedEvmChain.name : "Solana"}
                  </span>
                </div>
                <div className="flex flex-col items-center gap-1">
                  <span className="rounded-full border border-teal-500/30 bg-teal-500/10 px-2.5 py-0.5 text-[10px] font-semibold text-teal-300">
                    LI.FI Optimal Bridge
                  </span>
                  <div className="h-px w-20 bg-gradient-to-r from-slate-700 via-teal-400 to-slate-700" />
                </div>
                <div className="flex flex-col items-center gap-1.5 rounded-xl border border-slate-800 bg-[#090e18] px-4 py-3">
                  <ChainGlyph chain={mode === "fund" ? "SOL" : evmChain} size={28} />
                  <span className="text-xs font-semibold text-slate-200">
                    {mode === "fund" ? "Solana" : selectedEvmChain.name}
                  </span>
                </div>
              </div>
              <p className="mt-4 text-xs text-slate-400">
                Select amount and fetch a live executable quote
              </p>
            </div>
          )}

          {quote && (
            <div className="space-y-4">
              {/* Primary Conversion Card */}
              <div className="aegis-subbox grid items-center gap-3 rounded-xl p-4 sm:grid-cols-3">
                <div className="flex items-center gap-3">
                  <ChainGlyph chain={mode === "fund" ? evmChain : "SOL"} size={30} />
                  <div>
                    <div className="text-[11px] text-slate-400">{quote.fromChain}</div>
                    <div className="font-mono text-lg font-bold text-white">
                      {quote.fromAmountFormatted} {quote.fromTokenSymbol}
                    </div>
                    <div className="font-mono text-xs text-slate-500">≈ ${quote.fromAmountUSD}</div>
                  </div>
                </div>
                <div className="flex flex-col items-center justify-center">
                  <span className="rounded-lg border border-teal-500/30 bg-teal-500/10 px-3 py-1 text-xs font-semibold text-teal-300">
                    via {quote.toolName}
                  </span>
                  <div className="mt-1.5 flex items-center gap-1 text-[11px] text-slate-400">
                    <Clock className="h-3 w-3 text-teal-300" /> ~{quote.executionDurationSec}s
                  </div>
                </div>
                <div className="flex items-center justify-end gap-3 sm:text-right">
                  <div>
                    <div className="text-[11px] text-slate-400">{quote.toChain}</div>
                    <div className="font-mono text-lg font-bold text-teal-300">
                      {quote.toAmountFormatted} {quote.toTokenSymbol}
                    </div>
                    <div className="font-mono text-xs text-slate-500">
                      ≈ ${quote.toAmountUSD}
                    </div>
                  </div>
                  <ChainGlyph chain={mode === "fund" ? "SOL" : evmChain} size={30} />
                </div>
              </div>

              {/* Costs & Steps */}
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="aegis-subbox rounded-xl p-3.5">
                  <div className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-slate-300">
                    <Fuel className="h-3.5 w-3.5 text-amber-400" />
                    Fee Breakdown
                  </div>
                  <div className="space-y-1 font-mono text-xs text-slate-400">
                    <div className="flex justify-between">
                      <span>Estimated Gas:</span>
                      <span className="text-slate-200">${quote.gasCostUSD}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Bridge / Protocol Fee:</span>
                      <span className="text-slate-200">${quote.feeCostUSD}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Integrator:</span>
                      <span className="text-violet-300">aegis-solana</span>
                    </div>
                  </div>
                </div>

                <div className="aegis-subbox rounded-xl p-3.5">
                  <div className="mb-2 text-xs font-semibold text-slate-300">
                    Execution Steps ({quote.steps.length || 1})
                  </div>
                  <div className="space-y-1.5">
                    {(quote.steps.length > 0
                      ? quote.steps
                      : [
                          {
                            type: "cross",
                            tool: quote.tool,
                            toolName: quote.toolName,
                            fromChainId: quote.fromChainId,
                            toChainId: quote.toChainId,
                          },
                        ]
                    ).map((s, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between rounded-lg bg-slate-900/90 px-2.5 py-1.5 font-mono text-[11px]"
                      >
                        <span className="text-teal-300">
                          {idx + 1}. {s.toolName}
                        </span>
                        <span className="uppercase text-slate-400">{s.type}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* REAL Execution Trigger */}
              {quote.hasTransactionRequest && (
                <div className="aegis-subbox rounded-xl p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <div className="text-xs font-semibold text-teal-300">
                        2. Execute Live Bridge
                      </div>
                      <p className="mt-0.5 text-[11px] text-slate-400">
                        {mode === "payout" ? "Solana Wallet Adapter" : `${selectedEvmChain.name} · MetaMask / Rabby`}
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={handleExecuteRoute}
                      disabled={executing}
                      className="aegis-btn-primary inline-flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-bold disabled:opacity-50"
                    >
                      <Play className="h-3.5 w-3.5" />
                      {executing
                        ? execStage || "Awaiting Wallet Signature..."
                        : mode === "payout"
                        ? "Sign & Bridge from Solana"
                        : `Approve & Bridge on ${selectedEvmChain.name}`}
                    </button>
                  </div>

                  {/* Live TX Status Tracker (/api/lifi/status) */}
                  <div className="mt-3 border-t border-slate-800/80 pt-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <input
                        value={executedTxHash}
                        onChange={(e) => setExecutedTxHash(e.target.value)}
                        placeholder="Paste or execute TX hash to track live LI.FI settlement (/v1/status)"
                        className="min-w-0 flex-1 rounded-lg border border-slate-700/80 bg-[#05080f] px-3 py-1.5 font-mono text-[11px] text-slate-200 outline-none focus:border-teal-400"
                      />
                      <button
                        type="button"
                        onClick={() => pollBridgeStatus()}
                        disabled={!executedTxHash || checkingStatus}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-slate-600 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-teal-400/60 disabled:opacity-40"
                      >
                        <RefreshCw className={`h-3.5 w-3.5 ${checkingStatus ? "animate-spin" : ""}`} />
                        Track Status
                      </button>
                    </div>

                    {bridgeStatus && (
                      <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-teal-500/30 bg-teal-500/10 px-3 py-2 font-mono text-[11px]">
                        <span className="font-bold text-teal-200">
                          STATUS: {bridgeStatus.status}
                          {bridgeStatus.substatus ? ` (${bridgeStatus.substatus})` : ""}
                        </span>
                        <div className="flex items-center gap-3">
                          {bridgeStatus.lifiExplorerLink && (
                            <a
                              href={bridgeStatus.lifiExplorerLink}
                              target="_blank"
                              rel="noreferrer"
                              className="inline-flex items-center gap-1 text-teal-300 hover:underline"
                            >
                              LI.FI Scan <ExternalLink className="h-3 w-3" />
                            </a>
                          )}
                          {bridgeStatus.receivingTxLink && (
                            <a
                              href={bridgeStatus.receivingTxLink}
                              target="_blank"
                              rel="noreferrer"
                              className="inline-flex items-center gap-1 text-violet-300 hover:underline"
                            >
                              Dest TX <ExternalLink className="h-3 w-3" />
                            </a>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </MachinedPanel>
      </div>
    </div>
  );
}
