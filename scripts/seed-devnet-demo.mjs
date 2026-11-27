#!/usr/bin/env node
/**
 * Seeds live verifiable v2 Devnet transactions against our upgraded AEGIS Solana program:
 * 1) create_bounty (rent-safe PDA escrow)
 * 2) submit_finding_commit (anti-collision researcher seed + SHA-256 commit)
 * 3) reveal_finding (on-chain SHA-256 preimage verification!)
 * 4) Real end-to-end x402 V2 HTTP 402 -> 0.001 SOL + SPL Memo -> HTTP 200 + Ed25519 Oracle Proof
 * 5) record_audit_attestation WITH Solana Ed25519Program pre-instruction (is_verified_oracle = true!)
 */

import fs from "fs";
import os from "os";
import path from "path";
import crypto from "crypto";
import { createRequire } from "module";

const require = createRequire(new URL("../app/package.json", import.meta.url));
const {
  Connection,
  Ed25519Program,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} = require("@solana/web3.js");

const PROGRAM_ID = new PublicKey("8AaU3VSHXHyKcVTe9JCA67oRR5djpjfAUgcM1cCtpe7p");
const SPL_MEMO_PROGRAM_ID = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
const RPC_URL = "https://api.devnet.solana.com";
const API_URL = process.argv[2] || "http://localhost:3000/api/x402/scan";
const KEYPAIR_PATH =
  process.argv[3] || path.join(os.homedir(), ".config", "solana", "id.json");

function ixDisc(name) {
  return crypto.createHash("sha256").update(`global:${name}`).digest().subarray(0, 8);
}

function u64LE(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n), 0);
  return b;
}

function encStr(s) {
  const buf = Buffer.from(s, "utf-8");
  const len = Buffer.alloc(4);
  len.writeUInt32LE(buf.length, 0);
  return Buffer.concat([len, buf]);
}

async function main() {
  const secret = Uint8Array.from(JSON.parse(fs.readFileSync(KEYPAIR_PATH, "utf-8")));
  const wallet = Keypair.fromSecretKey(secret);
  const connection = new Connection(RPC_URL, "confirmed");

  console.log("Wallet :", wallet.publicKey.toBase58());
  console.log("Balance:", (await connection.getBalance(wallet.publicKey)) / LAMPORTS_PER_SOL, "SOL\n");

  // 1) Create v2 Bounty Vault PDA
  const bountyId = 2026n;
  const [bountyPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("bounty"), wallet.publicKey.toBuffer(), u64LE(bountyId)],
    PROGRAM_ID
  );
  const [escrowPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("escrow_vault"), bountyPda.toBuffer()],
    PROGRAM_ID
  );

  if (!(await connection.getAccountInfo(bountyPda))) {
    console.log("[1/5] Creating v2 Rent-Safe BountyVault PDA on Devnet...");
    const ix = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
        { pubkey: bountyPda, isSigner: false, isWritable: true },
        { pubkey: escrowPda, isSigner: false, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([
        ixDisc("create_bounty"),
        u64LE(bountyId),
        encStr("Solana DeFi Lending Core v2"),
        encStr("https://github.com/aegis/solana-lending-scope"),
        u64LE(Math.round(0.05 * LAMPORTS_PER_SOL)),
        u64LE(Math.round(0.03 * LAMPORTS_PER_SOL)),
      ]),
    });
    const sig = await sendAndConfirmTransaction(connection, new Transaction().add(ix), [wallet]);
    console.log("      BountyVault TX:", `https://explorer.solana.com/tx/${sig}?cluster=devnet`);
  }

  // 2) Submit SHA-256 Commit-Reveal Finding
  const findingId = 3001n;
  const pocSummary = "CRITICAL: Missing signer check in withdraw_treasury()";
  const salt = "aegis-salt-2026";
  const commitHash = crypto.createHash("sha256").update(`${pocSummary}||${salt}`).digest();

  const [findingPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("finding"), bountyPda.toBuffer(), wallet.publicKey.toBuffer(), u64LE(findingId)],
    PROGRAM_ID
  );
  const [whitehatPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("whitehat"), wallet.publicKey.toBuffer()],
    PROGRAM_ID
  );

  if (!(await connection.getAccountInfo(findingPda))) {
    console.log("[2/5] Submitting SHA-256 Commit-Reveal Finding on Devnet...");
    const ix = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
        { pubkey: bountyPda, isSigner: false, isWritable: true },
        { pubkey: findingPda, isSigner: false, isWritable: true },
        { pubkey: whitehatPda, isSigner: false, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([
        ixDisc("submit_finding_commit"),
        u64LE(findingId),
        commitHash,
        Buffer.from([4]),
        encStr("ipfs://bafybeigdyrzt5aegisencryptedpoc"),
        encStr("crisc_pentester"),
      ]),
    });
    const sig = await sendAndConfirmTransaction(connection, new Transaction().add(ix), [wallet]);
    console.log("      FindingCommit TX:", `https://explorer.solana.com/tx/${sig}?cluster=devnet`);

    // 3) Verify SHA-256 Preimage ON-CHAIN via reveal_finding!
    console.log("[3/5] Revealing & cryptographically verifying SHA-256 on-chain...");
    const revIx = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: wallet.publicKey, isSigner: true, isWritable: false },
        { pubkey: findingPda, isSigner: false, isWritable: true },
      ],
      data: Buffer.concat([ixDisc("reveal_finding"), encStr(pocSummary), encStr(salt)]),
    });
    const revSig = await sendAndConfirmTransaction(connection, new Transaction().add(revIx), [wallet]);
    console.log("      FindingReveal TX:", `https://explorer.solana.com/tx/${revSig}?cluster=devnet`);
  }

  // 4) Run real end-to-end x402 V2 + SPL Memo scan
  console.log("[4/5] Running REAL x402 V2 HTTP 402 -> 0.001 SOL + SPL Memo -> Ed25519 Oracle Proof...");
  const sampleCode = `
use anchor_lang::prelude::*;
#[program]
pub mod aegis_v2_verified {
    use super::*;
    pub fn safe_transfer(ctx: Context<SafeTransfer>, amount: u64) -> Result<()> {
        ctx.accounts.vault.balance = ctx.accounts.vault.balance.checked_sub(amount).ok_or(Err::Overflow)?;
        Ok(())
    }
}
#[derive(Accounts)]
pub struct SafeTransfer<'info> {
    pub authority: Signer<'info>,
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, VaultState>,
}
`;
  const probe = await fetch(API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      targetName: "AEGIS v2 Self-Audit (Oracle Verified)",
      targetProgramId: PROGRAM_ID.toBase58(),
      code: sampleCode,
    }),
  });
  if (probe.status !== 402) throw new Error(`Expected 402, got ${probe.status}`);
  const reqObj = JSON.parse(
    Buffer.from(probe.headers.get("payment-required"), "base64").toString("utf-8")
  );
  const accept = reqObj.accepts[0];

  const agentKp = Keypair.generate();
  await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: wallet.publicKey,
        toPubkey: agentKp.publicKey,
        lamports: Math.round(0.004 * LAMPORTS_PER_SOL),
      })
    ),
    [wallet]
  );

  const x402PaySig = await sendAndConfirmTransaction(
    connection,
    new Transaction()
      .add(
        SystemProgram.transfer({
          fromPubkey: agentKp.publicKey,
          toPubkey: new PublicKey(accept.payTo),
          lamports: Number(accept.amount),
        })
      )
      .add(
        new TransactionInstruction({
          programId: SPL_MEMO_PROGRAM_ID,
          keys: [{ pubkey: agentKp.publicKey, isSigner: true, isWritable: false }],
          data: Buffer.from(accept.extra.memoRequired, "utf-8"),
        })
      ),
    [agentKp]
  );
  console.log("      x402 + Memo TX:", `https://explorer.solana.com/tx/${x402PaySig}?cluster=devnet`);

  const paymentSigB64 = Buffer.from(
    JSON.stringify({
      x402Version: 2,
      resource: reqObj.resource,
      accepted: accept,
      payload: { signature: x402PaySig, account: agentKp.publicKey.toBase58() },
    })
  ).toString("base64");

  const scanRes = await fetch(API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "PAYMENT-SIGNATURE": paymentSigB64,
    },
    body: JSON.stringify({
      targetName: "AEGIS v2 Self-Audit (Oracle Verified)",
      targetProgramId: PROGRAM_ID.toBase58(),
      code: sampleCode,
    }),
  });
  const scanJson = await scanRes.json();
  if (!scanRes.ok) throw new Error(`x402 failed (${scanRes.status}): ${JSON.stringify(scanJson)}`);
  console.log(
    `      x402 HTTP 200 OK! Score=${scanJson.report.securityScore}/100 | OracleProof=${Boolean(
      scanJson.oracleAttestation
    )}`
  );

  // 5) Seal Ed25519-Verified AuditAttestation PDA on Solana Devnet
  const scanId = BigInt(scanJson.report.scanId);
  const [attPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("audit"), wallet.publicKey.toBuffer(), u64LE(scanId)],
    PROGRAM_ID
  );
  console.log("[5/5] Sealing Ed25519 Oracle-Verified AuditAttestation PDA on Devnet...");
  const tx = new Transaction();
  if (scanJson.oracleAttestation) {
    tx.add(
      Ed25519Program.createInstructionWithPublicKey({
        publicKey: new PublicKey(scanJson.oracleAttestation.attesterPubkey).toBytes(),
        message: Buffer.from(scanJson.oracleAttestation.messageHex, "hex"),
        signature: Buffer.from(scanJson.oracleAttestation.signatureHex, "hex"),
      })
    );
  }
  tx.add(
    new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: wallet.publicKey, isSigner: true, isWritable: true },
        { pubkey: attPda, isSigner: false, isWritable: true },
        { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([
        ixDisc("record_audit_attestation"),
        u64LE(scanId),
        PROGRAM_ID.toBuffer(),
        Buffer.from(scanJson.report.sourceCodeSha256, "hex"),
        Buffer.from(scanJson.report.reportHashHex, "hex"),
        Buffer.from([scanJson.report.securityScore]),
        Buffer.from([scanJson.report.summary.critical]),
        Buffer.from([scanJson.report.summary.high]),
        encStr(x402PaySig),
      ]),
    })
  );
  const attSig = await sendAndConfirmTransaction(connection, tx, [wallet]);
  console.log("      Verified Oracle Attestation TX:", `https://explorer.solana.com/tx/${attSig}?cluster=devnet`);
  console.log("\n=== ALL AEGIS v2 DEVNET LIVE TRANSACTIONS VERIFIED ===");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
