import crypto from "crypto";
import { Connection, Keypair, PublicKey } from "@solana/web3.js";

/**
 * x402 V2 Protocol Specification Constants for Solana Devnet
 * CAIP-2 Network Identifier: solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1 (Solana Devnet)
 */
export const X402_VERSION = 2;
export const SOLANA_DEVNET_CAIP2 = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
export const SOLANA_NATIVE_ASSET = "So11111111111111111111111111111111111111112";
export const SPL_MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
export const SCAN_PRICE_LAMPORTS = 1_000_000; // 0.001 SOL on Devnet

export const DEFAULT_TREASURY_ADDRESS =
  process.env.NEXT_PUBLIC_AEGIS_TREASURY ||
  process.env.AEGIS_TREASURY ||
  "35t8qFV5Tyk9FdN5m9qCEtHvC8q8N3SDBv77yCj1RozJ";

export const SOLANA_RPC_URL =
  process.env.NEXT_PUBLIC_SOLANA_RPC_URL ||
  process.env.SOLANA_RPC_URL ||
  "https://api.devnet.solana.com";

export interface X402PaymentRequirement {
  scheme: "exact";
  network: string;
  amount: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra: {
    name: string;
    symbol: string;
    decimals: number;
    cluster: "devnet";
    memoProgram: string;
    memoRequired: string;
    description: string;
  };
}

export interface X402PaymentRequiredPayload {
  x402Version: 2;
  resource: {
    url: string;
    description: string;
    mimeType: string;
  };
  accepts: X402PaymentRequirement[];
}

export interface X402PaymentSignaturePayload {
  x402Version: 2;
  resource?: {
    url: string;
    description?: string;
    mimeType?: string;
  };
  accepted?: Partial<X402PaymentRequirement>;
  payload: {
    signature: string;
    account?: string;
  };
}

export interface X402PaymentResponsePayload {
  x402Version: 2;
  success: boolean;
  network: string;
  transaction: string;
  payer: string;
  payTo: string;
  amountLamports: string;
  memoBound: string;
  settledAt: string;
  explorerUrl: string;
}

export interface OracleAttestationProof {
  attesterPubkey: string;
  targetProgramId: string;
  messageHex: string;
  signatureHex: string;
}

// Synchronous anti-TOCTOU lock + redeemed set (with optional Upstash Redis persistence in serverless)
const inFlightSignatures = new Set<string>();
const consumedSignatures = new Set<string>();

async function acquireReplayLock(sig: string): Promise<{ ok: boolean; error?: string }> {
  // 1. Synchronous local lock BEFORE any await -> eliminates TOCTOU concurrent race completely
  if (consumedSignatures.has(sig) || inFlightSignatures.has(sig)) {
    return {
      ok: false,
      error: "Replay attack prevented: this Solana transaction signature is already redeemed or in flight.",
    };
  }
  inFlightSignatures.add(sig);

  // 2. Optional Upstash Redis atomic SET NX EX 1200 for multi-instance serverless persistence
  const upstashUrl = process.env.UPSTASH_REDIS_REST_URL;
  const upstashToken = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (upstashUrl && upstashToken) {
    try {
      const r = await fetch(
        `${upstashUrl}/set/aegis:x402:${encodeURIComponent(sig)}/1/NX/EX/1200`,
        { headers: { Authorization: `Bearer ${upstashToken}` } }
      );
      const data = await r.json();
      if (data?.result !== "OK") {
        inFlightSignatures.delete(sig);
        return {
          ok: false,
          error: "Replay attack prevented (persistent KV store): signature already redeemed.",
        };
      }
    } catch {
      // Fall back to process lock if optional Redis is unreachable
    }
  }

  return { ok: true };
}

function finalizeReplayLock(sig: string, success: boolean) {
  inFlightSignatures.delete(sig);
  if (success) {
    consumedSignatures.add(sig);
  } else {
    const upstashUrl = process.env.UPSTASH_REDIS_REST_URL;
    const upstashToken = process.env.UPSTASH_REDIS_REST_TOKEN;
    if (upstashUrl && upstashToken) {
      fetch(`${upstashUrl}/del/aegis:x402:${encodeURIComponent(sig)}`, {
        headers: { Authorization: `Bearer ${upstashToken}` },
      }).catch(() => {});
    }
  }
}

export function computeMemoBinding(sourceCode: string): string {
  const digest = crypto.createHash("sha256").update(sourceCode, "utf-8").digest("hex");
  return `aegis:${digest.slice(0, 16)}`;
}

export function encodeBase64Json(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj), "utf-8").toString("base64");
}

export function decodeBase64Json<T>(b64: string): T | null {
  try {
    const raw = Buffer.from(b64.trim(), "base64").toString("utf-8");
    return JSON.parse(raw) as T;
  } catch {
    try {
      return JSON.parse(b64.trim()) as T;
    } catch {
      return null;
    }
  }
}

export function buildPaymentRequired(
  resourceUrl: string,
  payTo: string,
  memoRequired: string
): X402PaymentRequiredPayload {
  return {
    x402Version: X402_VERSION,
    resource: {
      url: resourceUrl,
      description: "AEGIS Deep Solana/Anchor Security Audit Scan (20 Inter-Procedural Sealevel, Token-2022, Oracle & Pentest Detectors)",
      mimeType: "application/json",
    },
    accepts: [
      {
        scheme: "exact",
        network: SOLANA_DEVNET_CAIP2,
        amount: String(SCAN_PRICE_LAMPORTS),
        asset: SOLANA_NATIVE_ASSET,
        payTo,
        maxTimeoutSeconds: 120,
        extra: {
          name: "Native SOL (Devnet)",
          symbol: "SOL",
          decimals: 9,
          cluster: "devnet",
          memoProgram: SPL_MEMO_PROGRAM_ID,
          memoRequired,
          description:
            "0.001 SOL micropayment bound to code hash via SPL Memo to prevent transaction sniping",
        },
      },
    ],
  };
}

export interface VerifyPaymentResult {
  valid: boolean;
  error?: string;
  payer?: string;
  amountLamports?: number;
  signature?: string;
  memoMatched?: boolean;
}

/**
 * Verifies a real confirmed Solana Devnet payment matching the x402 V2 requirement:
 * 1) Synchronous anti-TOCTOU + anti-replay lock acquired BEFORE any async RPC calls
 * 2) Transaction succeeded on Solana Devnet (meta.err === null)
 * 3) Supports both legacy and v0 transactions with Address Lookup Tables (loadedAddresses)
 * 4) Verifies an explicit SystemProgram.transfer instruction to `payTo` >= minLamports
 * 5) Verifies SPL Memo binding (`aegis:<sha256(code)[0..16]>`) when present (prevents tx sniping)
 * 6) Enforces 15-minute freshness window
 */
export async function verifySolanaDevnetPayment(
  txSignature: string,
  expectedPayTo: string,
  expectedMemo: string,
  minLamports: number = SCAN_PRICE_LAMPORTS
): Promise<VerifyPaymentResult> {
  if (!txSignature || txSignature.length < 40 || txSignature.length > 96) {
    return { valid: false, error: "Invalid Solana transaction signature format." };
  }

  let expectedPubkey: PublicKey;
  try {
    expectedPubkey = new PublicKey(expectedPayTo);
  } catch {
    return { valid: false, error: "Invalid server treasury public key configuration." };
  }

  const lock = await acquireReplayLock(txSignature);
  if (!lock.ok) {
    return { valid: false, error: lock.error };
  }

  try {
    const connection = new Connection(SOLANA_RPC_URL, "confirmed");

    let tx = null;
    for (let attempt = 0; attempt < 4; attempt++) {
      tx = await connection.getParsedTransaction(txSignature, {
        commitment: "confirmed",
        maxSupportedTransactionVersion: 0,
      });
      if (tx) break;
      await new Promise((r) => setTimeout(r, 1200));
    }

    if (!tx) {
      finalizeReplayLock(txSignature, false);
      return { valid: false, error: "Transaction not found or not yet confirmed on Solana Devnet." };
    }

    if (tx.meta?.err) {
      finalizeReplayLock(txSignature, false);
      return {
        valid: false,
        error: `Solana transaction failed on-chain: ${JSON.stringify(tx.meta.err)}`,
      };
    }

    // Build complete account list including v0 Address Lookup Tables
    const staticKeys = tx.transaction.message.accountKeys.map((k) =>
      typeof k === "string" ? k : k.pubkey.toBase58()
    );
    const loadedWritable = (tx.meta?.loadedAddresses?.writable || []).map((k) =>
      typeof k === "string" ? k : k.toBase58()
    );
    const loadedReadonly = (tx.meta?.loadedAddresses?.readonly || []).map((k) =>
      typeof k === "string" ? k : k.toBase58()
    );
    const allAccountKeys = [...staticKeys, ...loadedWritable, ...loadedReadonly];

    // Verify explicit SystemProgram.transfer instruction -> expectedPayTo >= minLamports
    let transferredLamports = 0;
    let transferPayer = "";
    let memoMatched = false;
    let hasMemoIx = false;

    const instructions = tx.transaction.message.instructions || [];
    for (const ix of instructions as any[]) {
      const progId =
        typeof ix.programId === "string" ? ix.programId : ix.programId?.toBase58?.() || "";

      if (ix.program === "system" && ix.parsed?.type === "transfer") {
        const info = ix.parsed.info || {};
        if (info.destination === expectedPubkey.toBase58()) {
          transferredLamports += Number(info.lamports || 0);
          transferPayer = info.source || transferPayer;
        }
      } else if (progId === SPL_MEMO_PROGRAM_ID || ix.program === "spl-memo") {
        hasMemoIx = true;
        const memoText = typeof ix.parsed === "string" ? ix.parsed : "";
        if (memoText.includes(expectedMemo)) {
          memoMatched = true;
        }
      }
    }

    // Also inspect log messages for SPL Memo (some RPCs log memo text when parsed is unavailable)
    if (!memoMatched && Array.isArray(tx.meta?.logMessages)) {
      for (const logLine of tx.meta.logMessages) {
        if (logLine.includes(expectedMemo)) {
          hasMemoIx = true;
          memoMatched = true;
          break;
        }
      }
    }

    if (transferredLamports < minLamports) {
      finalizeReplayLock(txSignature, false);
      return {
        valid: false,
        error: `No qualifying SystemProgram.transfer of >= ${minLamports} lamports to ${expectedPubkey.toBase58()} (found ${transferredLamports}).`,
      };
    }

    // Enforce anti-sniping Memo binding: if client included a memo it must match exact code hash,
    // and enforce strict memo match when expectedMemo is required
    if (!hasMemoIx || !memoMatched) {
      finalizeReplayLock(txSignature, false);
      return {
        valid: false,
        error: `Anti-sniping Memo check failed: include SPL Memo instruction "${expectedMemo}" bound to the scanned contract SHA-256.`,
      };
    }

    if (tx.blockTime) {
      const ageSeconds = Math.floor(Date.now() / 1000) - tx.blockTime;
      if (ageSeconds > 900) {
        finalizeReplayLock(txSignature, false);
        return {
          valid: false,
          error: `Transaction expired (${ageSeconds}s old). Submit a fresh x402 payment within 15 minutes.`,
        };
      }
    }

    finalizeReplayLock(txSignature, true);
    const payer = transferPayer || allAccountKeys[0] || "unknown";
    return {
      valid: true,
      payer,
      amountLamports: transferredLamports,
      signature: txSignature,
      memoMatched,
    };
  } catch (err: any) {
    finalizeReplayLock(txSignature, false);
    return {
      valid: false,
      error: `Solana RPC verification error: ${err?.message || "unknown error"}`,
    };
  }
}

/**
 * Signs the canonical AEGIS v2 audit attestation message using the server's Ed25519 Oracle keypair
 * (stored solely in AEGIS_ATTESTER_SECRET env var) so the Solana on-chain Ed25519Program precompile
 * can cryptographically prove this audit report was genuinely issued by the AEGIS x402 backend.
 */
export function signOracleAuditAttestation(params: {
  targetProgramId: string;
  sourceCodeSha256: string;
  reportHashHex: string;
  securityScore: number;
  criticalCount: number;
  highCount: number;
  x402PaymentSig: string;
}): OracleAttestationProof | null {
  const secretB64 = process.env.AEGIS_ATTESTER_SECRET;
  if (!secretB64) return null;

  let targetPk: PublicKey;
  try {
    targetPk = new PublicKey(params.targetProgramId);
  } catch {
    return null;
  }

  try {
    const secretBytes = Buffer.from(secretB64, "base64");
    const kp = Keypair.fromSecretKey(Uint8Array.from(secretBytes));
    // PKCS#8 DER wrapper for raw 32-byte Ed25519 seed (RFC 8410)
    const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
    const seed32 = secretBytes.subarray(0, 32);
    const privateKeyObj = crypto.createPrivateKey({
      key: Buffer.concat([pkcs8Prefix, seed32]),
      format: "der",
      type: "pkcs8",
    });

    const msg = Buffer.concat([
      Buffer.from("AEGIS_AUDIT_V2:", "utf-8"),
      targetPk.toBuffer(),
      Buffer.from(params.sourceCodeSha256, "hex"),
      Buffer.from(params.reportHashHex, "hex"),
      Buffer.from([
        params.securityScore & 0xff,
        Math.min(255, params.criticalCount),
        Math.min(255, params.highCount),
      ]),
      Buffer.from(params.x402PaymentSig, "utf-8"),
    ]);

    const sig = crypto.sign(null, msg, privateKeyObj);

    return {
      attesterPubkey: kp.publicKey.toBase58(),
      targetProgramId: targetPk.toBase58(),
      messageHex: msg.toString("hex"),
      signatureHex: sig.toString("hex"),
    };
  } catch {
    return null;
  }
}
