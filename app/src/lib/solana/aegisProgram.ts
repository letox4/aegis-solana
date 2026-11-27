import {
  Connection,
  Ed25519Program,
  PublicKey,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import { Buffer } from "buffer";

export const AEGIS_PROGRAM_ID = new PublicKey(
  process.env.NEXT_PUBLIC_AEGIS_PROGRAM_ID ||
    "8AaU3VSHXHyKcVTe9JCA67oRR5djpjfAUgcM1cCtpe7p"
);

export const SPL_MEMO_PROGRAM_PUBKEY = new PublicKey(
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
);

export const SOLANA_RENT_EXEMPT_MIN_LAMPORTS = 890_880;

// ============================================================================
// SHA-256 + Anchor Discriminator Helpers
// ============================================================================

async function sha256Bytes(data: Uint8Array): Promise<Uint8Array> {
  if (typeof globalThis !== "undefined" && globalThis.crypto?.subtle) {
    const digest = await globalThis.crypto.subtle.digest("SHA-256", data as BufferSource);
    return new Uint8Array(digest);
  }
  const nodeCrypto = await import("crypto");
  return new Uint8Array(nodeCrypto.createHash("sha256").update(data).digest());
}

export async function sha256Text(text: string): Promise<Uint8Array> {
  return sha256Bytes(new TextEncoder().encode(text));
}

export function bytesToHex(bytes: Uint8Array | number[]): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexToBytes32(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, "");
  if (!/^[a-fA-F0-9]{64}$/.test(clean)) {
    throw new Error("Expected exact 64-character SHA-256 hex digest.");
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function hexToUint8Array(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function anchorIxDiscriminator(snakeName: string): Promise<Buffer> {
  const hash = await sha256Text(`global:${snakeName}`);
  return Buffer.from(hash.slice(0, 8));
}

export async function anchorAccountDiscriminator(structName: string): Promise<Buffer> {
  const hash = await sha256Text(`account:${structName}`);
  return Buffer.from(hash.slice(0, 8));
}

// ============================================================================
// Borsh Encoding / Decoding Primitives
// ============================================================================

function encodeU64LE(val: bigint | number): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(BigInt(val), 0);
  return buf;
}

function encodeU8(val: number): Buffer {
  return Buffer.from([Math.max(0, Math.min(255, Math.floor(val)))]);
}

function encodeBool(val: boolean): Buffer {
  return Buffer.from([val ? 1 : 0]);
}

function encodeString(str: string): Buffer {
  const strBuf = Buffer.from(str, "utf-8");
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32LE(strBuf.length, 0);
  return Buffer.concat([lenBuf, strBuf]);
}

class BorshReader {
  private offset = 0;
  constructor(private buf: Buffer) {}

  get remaining(): number {
    return this.buf.length - this.offset;
  }

  skip(n: number) {
    this.offset += n;
  }

  readPubkey(): string {
    const slice = this.buf.subarray(this.offset, this.offset + 32);
    this.offset += 32;
    return new PublicKey(slice).toBase58();
  }

  readBytes(len: number): Uint8Array {
    const slice = this.buf.subarray(this.offset, this.offset + len);
    this.offset += len;
    return new Uint8Array(slice);
  }

  readU8(): number {
    const v = this.buf.readUInt8(this.offset);
    this.offset += 1;
    return v;
  }

  readBool(): boolean {
    return this.readU8() !== 0;
  }

  readU32(): number {
    const v = this.buf.readUInt32LE(this.offset);
    this.offset += 4;
    return v;
  }

  readU64(): number {
    const v = this.buf.readBigUInt64LE(this.offset);
    this.offset += 8;
    return Number(v);
  }

  readI64(): number {
    const v = this.buf.readBigInt64LE(this.offset);
    this.offset += 8;
    return Number(v);
  }

  readString(): string {
    const len = this.readU32();
    if (len > this.remaining) {
      throw new Error("String exceeds buffer bounds");
    }
    const s = this.buf.subarray(this.offset, this.offset + len).toString("utf-8");
    this.offset += len;
    return s;
  }
}

// ============================================================================
// PDA Derivations (v2/v3 Compatible)
// ============================================================================

export function deriveBountyPda(
  authority: PublicKey,
  bountyId: bigint | number,
  programId: PublicKey = AEGIS_PROGRAM_ID
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("bounty"), authority.toBuffer(), encodeU64LE(bountyId)],
    programId
  );
}

export function deriveEscrowVaultPda(
  bountyPda: PublicKey,
  programId: PublicKey = AEGIS_PROGRAM_ID
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("escrow_vault"), bountyPda.toBuffer()],
    programId
  );
}

export function deriveVaultCooldownPda(
  bountyPda: PublicKey,
  programId: PublicKey = AEGIS_PROGRAM_ID
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("cooldown"), bountyPda.toBuffer()],
    programId
  );
}

export function deriveFindingPda(
  bountyPda: PublicKey,
  researcher: PublicKey,
  findingId: bigint | number,
  programId: PublicKey = AEGIS_PROGRAM_ID
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("finding"),
      bountyPda.toBuffer(),
      researcher.toBuffer(),
      encodeU64LE(findingId),
    ],
    programId
  );
}

export function deriveDisputeTicketPda(
  findingPda: PublicKey,
  programId: PublicKey = AEGIS_PROGRAM_ID
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("dispute"), findingPda.toBuffer()],
    programId
  );
}

export function deriveArbConfigPda(
  programId: PublicKey = AEGIS_PROGRAM_ID
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Buffer.from("arb_config")], programId);
}

export function deriveWhitehatPda(
  researcher: PublicKey,
  programId: PublicKey = AEGIS_PROGRAM_ID
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("whitehat"), researcher.toBuffer()],
    programId
  );
}

export function deriveAuditAttestationPda(
  auditor: PublicKey,
  scanId: bigint | number,
  programId: PublicKey = AEGIS_PROGRAM_ID
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("audit"), auditor.toBuffer(), encodeU64LE(scanId)],
    programId
  );
}

// ============================================================================
// Helper: SPL Memo Instruction
// ============================================================================

export function buildMemoIx(memo: string, signer: PublicKey): TransactionInstruction {
  return new TransactionInstruction({
    programId: SPL_MEMO_PROGRAM_PUBKEY,
    keys: [{ pubkey: signer, isSigner: true, isWritable: false }],
    data: Buffer.from(memo, "utf-8"),
  });
}

// ============================================================================
// Instruction Builders (100% Anchor v3 Binary-Compatible)
// ============================================================================

export async function buildCreateBountyIx(params: {
  authority: PublicKey;
  bountyId: bigint | number;
  targetName: string;
  scopeUri: string;
  rewardLamports: bigint | number;
  maxPayoutPerFinding: bigint | number;
  programId?: PublicKey;
}): Promise<{ ix: TransactionInstruction; bountyPda: PublicKey; escrowVaultPda: PublicKey }> {
  const programId = params.programId ?? AEGIS_PROGRAM_ID;
  const [bountyPda] = deriveBountyPda(params.authority, params.bountyId, programId);
  const [escrowVaultPda] = deriveEscrowVaultPda(bountyPda, programId);

  const disc = await anchorIxDiscriminator("create_bounty");
  const data = Buffer.concat([
    disc,
    encodeU64LE(params.bountyId),
    encodeString(params.targetName),
    encodeString(params.scopeUri),
    encodeU64LE(params.rewardLamports),
    encodeU64LE(params.maxPayoutPerFinding),
  ]);

  const ix = new TransactionInstruction({
    programId,
    keys: [
      { pubkey: params.authority, isSigner: true, isWritable: true },
      { pubkey: bountyPda, isSigner: false, isWritable: true },
      { pubkey: escrowVaultPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });

  return { ix, bountyPda, escrowVaultPda };
}

export async function buildTopUpBountyIx(params: {
  funder: PublicKey;
  bountyPda: PublicKey;
  amountLamports: bigint | number;
  programId?: PublicKey;
}): Promise<TransactionInstruction> {
  const programId = params.programId ?? AEGIS_PROGRAM_ID;
  const [escrowVaultPda] = deriveEscrowVaultPda(params.bountyPda, programId);

  const disc = await anchorIxDiscriminator("top_up_bounty");
  const data = Buffer.concat([disc, encodeU64LE(params.amountLamports)]);

  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: params.funder, isSigner: true, isWritable: true },
      { pubkey: params.bountyPda, isSigner: false, isWritable: true },
      { pubkey: escrowVaultPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

export async function buildSubmitFindingCommitIx(params: {
  researcher: PublicKey;
  bountyPda: PublicKey;
  findingId: bigint | number;
  commitHash: Uint8Array;
  severity: number;
  encryptedReportUri: string;
  researcherHandle: string;
  programId?: PublicKey;
}): Promise<{ ix: TransactionInstruction; findingPda: PublicKey; whitehatPda: PublicKey }> {
  if (params.commitHash.length !== 32) {
    throw new Error("commitHash must be exactly 32 bytes (SHA-256).");
  }
  const programId = params.programId ?? AEGIS_PROGRAM_ID;
  const [findingPda] = deriveFindingPda(
    params.bountyPda,
    params.researcher,
    params.findingId,
    programId
  );
  const [whitehatPda] = deriveWhitehatPda(params.researcher, programId);

  const disc = await anchorIxDiscriminator("submit_finding_commit");
  const data = Buffer.concat([
    disc,
    encodeU64LE(params.findingId),
    Buffer.from(params.commitHash),
    encodeU8(params.severity),
    encodeString(params.encryptedReportUri),
    encodeString(params.researcherHandle),
  ]);

  const ix = new TransactionInstruction({
    programId,
    keys: [
      { pubkey: params.researcher, isSigner: true, isWritable: true },
      { pubkey: params.bountyPda, isSigner: false, isWritable: true },
      { pubkey: findingPda, isSigner: false, isWritable: true },
      { pubkey: whitehatPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });

  return { ix, findingPda, whitehatPda };
}

export async function buildRevealFindingIx(params: {
  researcher: PublicKey;
  findingPda: PublicKey;
  pocSummary: string;
  salt: string;
  programId?: PublicKey;
}): Promise<TransactionInstruction> {
  const programId = params.programId ?? AEGIS_PROGRAM_ID;
  const disc = await anchorIxDiscriminator("reveal_finding");
  const data = Buffer.concat([
    disc,
    encodeString(params.pocSummary),
    encodeString(params.salt),
  ]);

  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: params.researcher, isSigner: true, isWritable: false },
      { pubkey: params.findingPda, isSigner: false, isWritable: true },
    ],
    data,
  });
}

export async function buildApproveAndPayoutIx(params: {
  authority: PublicKey;
  bountyPda: PublicKey;
  findingPda: PublicKey;
  researcher: PublicKey;
  payoutLamports: bigint | number;
  programId?: PublicKey;
}): Promise<TransactionInstruction> {
  const programId = params.programId ?? AEGIS_PROGRAM_ID;
  const [escrowVaultPda] = deriveEscrowVaultPda(params.bountyPda, programId);
  const [whitehatPda] = deriveWhitehatPda(params.researcher, programId);

  const disc = await anchorIxDiscriminator("approve_and_payout");
  const data = Buffer.concat([disc, encodeU64LE(params.payoutLamports)]);

  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: params.authority, isSigner: true, isWritable: true },
      { pubkey: params.bountyPda, isSigner: false, isWritable: true },
      { pubkey: escrowVaultPda, isSigner: false, isWritable: true },
      { pubkey: params.findingPda, isSigner: false, isWritable: true },
      { pubkey: whitehatPda, isSigner: false, isWritable: true },
      { pubkey: params.researcher, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

export async function buildRejectFindingIx(params: {
  authority: PublicKey;
  bountyPda: PublicKey;
  findingPda: PublicKey;
  programId?: PublicKey;
}): Promise<TransactionInstruction> {
  const programId = params.programId ?? AEGIS_PROGRAM_ID;
  const [vaultCooldownPda] = deriveVaultCooldownPda(params.bountyPda, programId);
  const disc = await anchorIxDiscriminator("reject_finding");

  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: params.authority, isSigner: true, isWritable: true },
      { pubkey: params.bountyPda, isSigner: false, isWritable: true },
      { pubkey: params.findingPda, isSigner: false, isWritable: true },
      { pubkey: vaultCooldownPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: disc,
  });
}

export async function buildRaiseDisputeIx(params: {
  researcher: PublicKey;
  bountyPda: PublicKey;
  findingPda: PublicKey;
  reasonUri: string;
  programId?: PublicKey;
}): Promise<{ ix: TransactionInstruction; disputeTicketPda: PublicKey }> {
  const programId = params.programId ?? AEGIS_PROGRAM_ID;
  const [disputeTicketPda] = deriveDisputeTicketPda(params.findingPda, programId);
  const disc = await anchorIxDiscriminator("raise_dispute");
  const data = Buffer.concat([disc, encodeString(params.reasonUri)]);

  const ix = new TransactionInstruction({
    programId,
    keys: [
      { pubkey: params.researcher, isSigner: true, isWritable: true },
      { pubkey: params.bountyPda, isSigner: false, isWritable: true },
      { pubkey: params.findingPda, isSigner: false, isWritable: true },
      { pubkey: disputeTicketPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });

  return { ix, disputeTicketPda };
}

export async function buildResolveDisputeIx(params: {
  caller: PublicKey;
  bountyPda: PublicKey;
  findingPda: PublicKey;
  researcher: PublicKey;
  upholdResearcher: boolean;
  awardLamports: bigint | number;
  programId?: PublicKey;
}): Promise<TransactionInstruction> {
  const programId = params.programId ?? AEGIS_PROGRAM_ID;
  const [escrowVaultPda] = deriveEscrowVaultPda(params.bountyPda, programId);
  const [disputeTicketPda] = deriveDisputeTicketPda(params.findingPda, programId);
  const [whitehatPda] = deriveWhitehatPda(params.researcher, programId);
  const [arbConfigPda] = deriveArbConfigPda(programId);

  const disc = await anchorIxDiscriminator("resolve_dispute");
  const data = Buffer.concat([
    disc,
    encodeBool(params.upholdResearcher),
    encodeU64LE(params.awardLamports),
  ]);

  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: params.caller, isSigner: true, isWritable: true },
      { pubkey: params.bountyPda, isSigner: false, isWritable: true },
      { pubkey: escrowVaultPda, isSigner: false, isWritable: true },
      { pubkey: params.findingPda, isSigner: false, isWritable: true },
      { pubkey: disputeTicketPda, isSigner: false, isWritable: true },
      { pubkey: whitehatPda, isSigner: false, isWritable: true },
      { pubkey: params.researcher, isSigner: false, isWritable: true },
      { pubkey: arbConfigPda, isSigner: false, isWritable: false },
      { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

export async function buildCloseBountyIx(params: {
  authority: PublicKey;
  bountyPda: PublicKey;
  programId?: PublicKey;
}): Promise<TransactionInstruction> {
  const programId = params.programId ?? AEGIS_PROGRAM_ID;
  const [escrowVaultPda] = deriveEscrowVaultPda(params.bountyPda, programId);
  const [vaultCooldownPda] = deriveVaultCooldownPda(params.bountyPda, programId);
  const disc = await anchorIxDiscriminator("close_bounty");

  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: params.authority, isSigner: true, isWritable: true },
      { pubkey: params.bountyPda, isSigner: false, isWritable: true },
      { pubkey: escrowVaultPda, isSigner: false, isWritable: true },
      { pubkey: vaultCooldownPda, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: disc,
  });
}

export async function buildRecordAuditAttestationIxs(params: {
  auditor: PublicKey;
  scanId: bigint | number;
  targetProgramId: PublicKey;
  sourceCodeHash: Uint8Array;
  reportHash: Uint8Array;
  securityScore: number;
  criticalCount: number;
  highCount: number;
  x402PaymentSig: string;
  oracleProof?: {
    attesterPubkey: string;
    messageHex: string;
    signatureHex: string;
  } | null;
  programId?: PublicKey;
}): Promise<{ ixs: TransactionInstruction[]; attestationPda: PublicKey }> {
  const programId = params.programId ?? AEGIS_PROGRAM_ID;
  const [attestationPda] = deriveAuditAttestationPda(params.auditor, params.scanId, programId);

  const ixs: TransactionInstruction[] = [];

  if (params.oracleProof) {
    const ed25519Ix = Ed25519Program.createInstructionWithPublicKey({
      publicKey: new PublicKey(params.oracleProof.attesterPubkey).toBytes(),
      message: hexToUint8Array(params.oracleProof.messageHex),
      signature: hexToUint8Array(params.oracleProof.signatureHex),
    });
    ixs.push(ed25519Ix);
  }

  const disc = await anchorIxDiscriminator("record_audit_attestation");
  const data = Buffer.concat([
    disc,
    encodeU64LE(params.scanId),
    params.targetProgramId.toBuffer(),
    Buffer.from(params.sourceCodeHash.slice(0, 32)),
    Buffer.from(params.reportHash.slice(0, 32)),
    encodeU8(params.securityScore),
    encodeU8(params.criticalCount),
    encodeU8(params.highCount),
    encodeString(params.x402PaymentSig),
  ]);

  const recordIx = new TransactionInstruction({
    programId,
    keys: [
      { pubkey: params.auditor, isSigner: true, isWritable: true },
      { pubkey: attestationPda, isSigner: false, isWritable: true },
      { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });

  ixs.push(recordIx);
  return { ixs, attestationPda };
}

// ============================================================================
// On-Chain Account Types & v2/v3 Deserializers
// ============================================================================

export interface OnChainBountyVault {
  address: string;
  escrowAddress: string;
  authority: string;
  bountyId: number;
  targetName: string;
  scopeUri: string;
  totalDeposited: number;
  remainingPool: number;
  maxPayoutPerFinding: number;
  findingsCount: number;
  pendingFindings: number;
  approvedCount: number;
  isActive: boolean;
  createdAt: number;
  cooldownUnlockAt?: number;
}

export interface OnChainFindingReport {
  address: string;
  bounty: string;
  researcher: string;
  findingId: number;
  commitHashHex: string;
  severity: number;
  encryptedReportUri: string;
  revealedSummary: string;
  status: "Committed" | "Revealed" | "Approved" | "Rejected" | "Disputed";
  payoutLamports: number;
  submittedAt: number;
  resolvedAt: number;
  disputeReasonUri?: string;
}

export interface OnChainWhitehatProfile {
  address: string;
  researcher: string;
  handle: string;
  totalSubmissions: number;
  approvedFindings: number;
  totalEarnedLamports: number;
  reputationScore: number;
}

export interface OnChainAuditAttestation {
  address: string;
  auditor: string;
  scanId: number;
  targetProgramId: string;
  sourceCodeHashHex: string;
  reportHashHex: string;
  securityScore: number;
  criticalCount: number;
  highCount: number;
  x402PaymentSig: string;
  isVerifiedOracle: boolean;
  auditedAt: number;
}

const BOUNTY_V2_SIZE = 367;
const FINDING_V2_SIZE = 507;
const AUDIT_V2_SIZE = 257;
const COOLDOWN_V3_SIZE = 81;
const DISPUTE_V3_SIZE = 335;

function deserializeAuditAttestationV2(
  pubkey: PublicKey,
  buf: Buffer,
  auditDisc: Buffer
): OnChainAuditAttestation | null {
  if (buf.length !== AUDIT_V2_SIZE || !buf.subarray(0, 8).equals(auditDisc)) {
    return null;
  }
  try {
    const r = new BorshReader(buf);
    r.skip(8);
    return {
      address: pubkey.toBase58(),
      auditor: r.readPubkey(),
      scanId: r.readU64(),
      targetProgramId: r.readPubkey(),
      sourceCodeHashHex: bytesToHex(r.readBytes(32)),
      reportHashHex: bytesToHex(r.readBytes(32)),
      securityScore: r.readU8(),
      criticalCount: r.readU8(),
      highCount: r.readU8(),
      x402PaymentSig: r.readString(),
      isVerifiedOracle: r.readBool(),
      auditedAt: r.readI64(),
    };
  } catch {
    return null;
  }
}

export async function fetchAttestationsByTargetProgram(
  connection: Connection,
  targetProgramId: PublicKey,
  programId: PublicKey = AEGIS_PROGRAM_ID
): Promise<OnChainAuditAttestation[]> {
  const auditDisc = await anchorAccountDiscriminator("AuditAttestation");
  const accounts = await connection.getProgramAccounts(programId, {
    commitment: "confirmed",
    filters: [
      { dataSize: AUDIT_V2_SIZE },
      { memcmp: { offset: 48, bytes: targetProgramId.toBase58() } },
    ],
  });

  const attestations: OnChainAuditAttestation[] = [];
  for (const { pubkey, account } of accounts) {
    const parsed = deserializeAuditAttestationV2(pubkey, Buffer.from(account.data), auditDisc);
    if (parsed) {
      attestations.push(parsed);
    }
  }

  attestations.sort(
    (a, b) => Number(b.isVerifiedOracle) - Number(a.isVerifiedOracle) || b.auditedAt - a.auditedAt
  );

  return attestations;
}

export async function fetchAllAegisOnChainState(
  connection: Connection,
  programId: PublicKey = AEGIS_PROGRAM_ID
) {
  const [bountyDisc, findingDisc, whitehatDisc, auditDisc, cooldownDisc, disputeDisc] =
    await Promise.all([
      anchorAccountDiscriminator("BountyVault"),
      anchorAccountDiscriminator("FindingReport"),
      anchorAccountDiscriminator("WhitehatProfile"),
      anchorAccountDiscriminator("AuditAttestation"),
      anchorAccountDiscriminator("VaultCooldown"),
      anchorAccountDiscriminator("DisputeTicket"),
    ]);

  const accounts = await connection.getProgramAccounts(programId, { commitment: "confirmed" });

  const bounties: OnChainBountyVault[] = [];
  const findings: OnChainFindingReport[] = [];
  const whitehats: OnChainWhitehatProfile[] = [];
  const attestations: OnChainAuditAttestation[] = [];
  const cooldownMap = new Map<string, number>();
  const disputeMap = new Map<string, string>();

  for (const { pubkey, account } of accounts) {
    const buf = Buffer.from(account.data);
    if (buf.length < 8) continue;
    const disc = buf.subarray(0, 8);

    try {
      const r = new BorshReader(buf);
      r.skip(8);

      if (disc.equals(bountyDisc) && buf.length === BOUNTY_V2_SIZE) {
        const [escrow] = deriveEscrowVaultPda(pubkey, programId);
        bounties.push({
          address: pubkey.toBase58(),
          escrowAddress: escrow.toBase58(),
          authority: r.readPubkey(),
          bountyId: r.readU64(),
          targetName: r.readString(),
          scopeUri: r.readString(),
          totalDeposited: r.readU64(),
          remainingPool: r.readU64(),
          maxPayoutPerFinding: r.readU64(),
          findingsCount: r.readU32(),
          pendingFindings: r.readU32(),
          approvedCount: r.readU32(),
          isActive: r.readBool(),
          createdAt: r.readI64(),
        });
      } else if (disc.equals(findingDisc) && buf.length === FINDING_V2_SIZE) {
        const bounty = r.readPubkey();
        const researcher = r.readPubkey();
        const findingId = r.readU64();
        const commitHashHex = bytesToHex(r.readBytes(32));
        const severity = r.readU8();
        const encryptedReportUri = r.readString();
        const revealedSummary = r.readString();
        const statusByte = r.readU8();
        const status: OnChainFindingReport["status"] =
          statusByte === 1
            ? "Revealed"
            : statusByte === 2
            ? "Approved"
            : statusByte === 3
            ? "Rejected"
            : statusByte === 4
            ? "Disputed"
            : "Committed";
        const payoutLamports = r.readU64();
        const submittedAt = r.readI64();
        const resolvedAt = r.readI64();
        findings.push({
          address: pubkey.toBase58(),
          bounty,
          researcher,
          findingId,
          commitHashHex,
          severity,
          encryptedReportUri,
          revealedSummary,
          status,
          payoutLamports,
          submittedAt,
          resolvedAt,
        });
      } else if (disc.equals(cooldownDisc) && buf.length === COOLDOWN_V3_SIZE) {
        const bountyKey = r.readPubkey();
        const unlockAt = r.readI64();
        if (unlockAt > 0) {
          cooldownMap.set(bountyKey, unlockAt);
        }
      } else if (disc.equals(disputeDisc) && buf.length === DISPUTE_V3_SIZE) {
        r.readPubkey(); // bounty
        const findingKey = r.readPubkey();
        r.readPubkey(); // researcher
        const reasonUri = r.readString();
        disputeMap.set(findingKey, reasonUri);
      } else if (disc.equals(whitehatDisc)) {
        whitehats.push({
          address: pubkey.toBase58(),
          researcher: r.readPubkey(),
          handle: r.readString(),
          totalSubmissions: r.readU32(),
          approvedFindings: r.readU32(),
          totalEarnedLamports: r.readU64(),
          reputationScore: r.readU64(),
        });
      } else {
        const parsedAttestation = deserializeAuditAttestationV2(pubkey, buf, auditDisc);
        if (parsedAttestation) {
          attestations.push(parsedAttestation);
        }
      }
    } catch {
      // Safely skip legacy v1 accounts
    }
  }

  for (const b of bounties) {
    const unlock = cooldownMap.get(b.address);
    if (unlock) b.cooldownUnlockAt = unlock;
  }
  for (const f of findings) {
    const reason = disputeMap.get(f.address);
    if (reason) f.disputeReasonUri = reason;
  }

  bounties.sort((a, b) => b.createdAt - a.createdAt);
  findings.sort((a, b) => b.submittedAt - a.submittedAt);
  whitehats.sort((a, b) => b.reputationScore - a.reputationScore);
  attestations.sort((a, b) => b.auditedAt - a.auditedAt);

  return { bounties, findings, whitehats, attestations };
}
