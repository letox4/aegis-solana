import zlib from "zlib";
import { Connection, PublicKey } from "@solana/web3.js";
import {
  AEGIS_PROGRAM_ID,
  fetchAttestationsByTargetProgram,
  OnChainAuditAttestation,
} from "./aegisProgram";
import { SOLANA_RPC_URL } from "@/lib/x402/protocol";

const BPF_LOADER_UPGRADEABLE = "BPFLoaderUpgradeab1e11111111111111111111111";
const BPF_LOADER_V2 = "BPFLoader2111111111111111111111111111111111";
const MAINNET_RPC_URL =
  process.env.NEXT_PUBLIC_SOLANA_MAINNET_RPC_URL || "https://api.mainnet-beta.solana.com";

export type InspectCluster = "devnet" | "mainnet-beta";

export interface IdlInstructionSurface {
  name: string;
  accountCount: number;
  writableCount: number;
  signerCount: number;
  writableWithoutSigner: boolean;
  accounts: Array<{ name: string; writable: boolean; signer: boolean }>;
}

export interface OnChainRiskCheck {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "INFO";
  title: string;
  detail: string;
}

export interface OnChainProgramInspection {
  programId: string;
  cluster: InspectCluster;
  exists: boolean;
  executable: boolean;
  owner: string;
  loaderType: "BPFLoaderUpgradeable" | "BPFLoader2" | "NativeLoader" | "Non-Executable / Other";
  lamports: number;
  programDataAddress: string | null;
  lastDeployedSlot: number | null;
  isImmutable: boolean | null;
  upgradeAuthority: string | null;
  binarySizeBytes: number | null;
  idlFound: boolean;
  idlAddress: string;
  idlProgramName: string | null;
  idlSpecVersion: string | null;
  idlInstructions: IdlInstructionSurface[];
  aegisAttestation: OnChainAuditAttestation | null;
  riskChecks: OnChainRiskCheck[];
  surfaceScore: number;
  inspectedAt: string;
}

/**
 * Derives the standard Anchor on-chain IDL address for any Solana Program ID.
 */
export async function deriveAnchorIdlAddress(programId: PublicKey): Promise<PublicKey> {
  const [base] = PublicKey.findProgramAddressSync([], programId);
  return PublicKey.createWithSeed(base, "anchor:idl", programId);
}

/**
 * Safely parses an Anchor on-chain IDL account:
 * layout = 8-byte discriminator + 32-byte authority + 4-byte u32 LE compressed length + zlib bytes
 */
function decodeAnchorIdlAccount(data: Buffer): {
  name: string | null;
  specVersion: string | null;
  instructions: IdlInstructionSurface[];
} | null {
  if (data.length < 45) return null;
  const compressedLen = data.readUInt32LE(40);
  if (compressedLen === 0 || compressedLen > 512_000 || 44 + compressedLen > data.length) {
    return null;
  }

  try {
    const compressed = data.subarray(44, 44 + compressedLen);
    const inflated = zlib.inflateSync(compressed, { maxOutputLength: 2_000_000 });
    const parsed = JSON.parse(inflated.toString("utf-8"));

    const rawIxs: any[] = Array.isArray(parsed?.instructions) ? parsed.instructions : [];
    const instructions: IdlInstructionSurface[] = rawIxs.slice(0, 64).map((ix) => {
      const rawAccounts: any[] = Array.isArray(ix?.accounts) ? ix.accounts : [];
      const flatAccounts: Array<{ name: string; writable: boolean; signer: boolean }> = [];

      const visit = (list: any[]) => {
        for (const a of list) {
          if (Array.isArray(a?.accounts)) {
            visit(a.accounts);
          } else if (a?.name) {
            flatAccounts.push({
              name: String(a.name),
              writable: Boolean(a.writable ?? a.isMut),
              signer: Boolean(a.signer ?? a.isSigner),
            });
          }
        }
      };
      visit(rawAccounts);

      const writableCount = flatAccounts.filter((a) => a.writable).length;
      const signerCount = flatAccounts.filter((a) => a.signer).length;

      return {
        name: String(ix?.name || "unknown_ix"),
        accountCount: flatAccounts.length,
        writableCount,
        signerCount,
        writableWithoutSigner: writableCount > 0 && signerCount === 0,
        accounts: flatAccounts.slice(0, 20),
      };
    });

    const rawName: string | null = parsed?.metadata?.name || parsed?.name || null;
    const displayName =
      rawName && rawName.toLowerCase() === "aegis402" ? "AEGIS Protocol" : rawName;

    return {
      name: displayName,
      specVersion: parsed?.metadata?.spec || parsed?.version || null,
      instructions,
    };
  } catch {
    return null;
  }
}

/**
 * Inspects ANY live deployed Solana Program ID on Devnet or Mainnet:
 * - Reads BPFLoaderUpgradeable + ProgramData PDA (Upgrade Authority, last deployed slot, ELF size)
 * - Extracts & inflates on-chain Anchor IDL (zlib) to map instruction signer/writable attack surface
 * - Checks live AEGIS Ed25519 AuditAttestation PDAs on Devnet
 */
export async function inspectSolanaProgramOnChain(
  rawProgramId: string,
  cluster: InspectCluster = "devnet"
): Promise<OnChainProgramInspection> {
  const programPubkey = new PublicKey(rawProgramId.trim());
  const rpcUrl = cluster === "mainnet-beta" ? MAINNET_RPC_URL : SOLANA_RPC_URL;
  const connection = new Connection(rpcUrl, "confirmed");
  const devnetConn = cluster === "devnet" ? connection : new Connection(SOLANA_RPC_URL, "confirmed");

  const idlPubkey = await deriveAnchorIdlAddress(programPubkey);

  const [programInfo, idlInfo, matchingAttestations] = await Promise.all([
    connection.getAccountInfo(programPubkey),
    connection.getAccountInfo(idlPubkey).catch(() => null),
    fetchAttestationsByTargetProgram(devnetConn, programPubkey, AEGIS_PROGRAM_ID).catch(
      () => [] as OnChainAuditAttestation[]
    ),
  ]);

  const latestAttestation = matchingAttestations[0] || null;

  const riskChecks: OnChainRiskCheck[] = [];

  if (!programInfo) {
    riskChecks.push({
      id: "AEGIS-CHAIN-404",
      severity: "HIGH",
      title: `Program Not Found on Solana ${cluster}`,
      detail: `No account exists at ${programPubkey.toBase58()} on ${cluster}. Verify the Program ID or toggle between Devnet and Mainnet.`,
    });

    return {
      programId: programPubkey.toBase58(),
      cluster,
      exists: false,
      executable: false,
      owner: "None",
      loaderType: "Non-Executable / Other",
      lamports: 0,
      programDataAddress: null,
      lastDeployedSlot: null,
      isImmutable: null,
      upgradeAuthority: null,
      binarySizeBytes: null,
      idlFound: false,
      idlAddress: idlPubkey.toBase58(),
      idlProgramName: null,
      idlSpecVersion: null,
      idlInstructions: [],
      aegisAttestation: latestAttestation,
      riskChecks,
      surfaceScore: 0,
      inspectedAt: new Date().toISOString(),
    };
  }

  const ownerStr = programInfo.owner.toBase58();
  let loaderType: OnChainProgramInspection["loaderType"] = "Non-Executable / Other";
  if (ownerStr === BPF_LOADER_UPGRADEABLE) loaderType = "BPFLoaderUpgradeable";
  else if (ownerStr === BPF_LOADER_V2) loaderType = "BPFLoader2";
  else if (ownerStr === "NativeLoader1111111111111111111111111111111") loaderType = "NativeLoader";

  let programDataAddress: string | null = null;
  let lastDeployedSlot: number | null = null;
  let isImmutable: boolean | null = null;
  let upgradeAuthority: string | null = null;
  let binarySizeBytes: number | null = null;

  if (!programInfo.executable) {
    riskChecks.push({
      id: "AEGIS-CHAIN-000",
      severity: "HIGH",
      title: "Account Is Not Executable",
      detail: "This address holds data or lamports but is not a deployed BPF executable program.",
    });
  } else if (loaderType === "BPFLoaderUpgradeable" && programInfo.data.length >= 36) {
    // UpgradeableLoaderState::Program -> tag u32 LE == 2, bytes 4..36 = programdata_address
    const tag = programInfo.data.readUInt32LE(0);
    if (tag === 2) {
      const pdPubkey = new PublicKey(programInfo.data.subarray(4, 36));
      programDataAddress = pdPubkey.toBase58();
      const pdInfo = await connection.getAccountInfo(pdPubkey);
      if (pdInfo && pdInfo.data.length >= 45 && pdInfo.data.readUInt32LE(0) === 3) {
        lastDeployedSlot = Number(pdInfo.data.readBigUInt64LE(4));
        const hasAuth = pdInfo.data[12] === 1;
        if (hasAuth) {
          upgradeAuthority = new PublicKey(pdInfo.data.subarray(13, 45)).toBase58();
          isImmutable = false;
          riskChecks.push({
            id: "AEGIS-CHAIN-001",
            severity: "HIGH",
            title: "Active Upgrade Authority Detected (Bytecode Rug-Pull Surface)",
            detail: `Program bytecode is mutable and controlled by ${upgradeAuthority}. Unless this key is a Squads multisig with timelock, a compromised deployer key can replace on-chain logic without notice.`,
          });
        } else {
          isImmutable = true;
          riskChecks.push({
            id: "AEGIS-CHAIN-001",
            severity: "INFO",
            title: "Program Is Permanently Immutable (Upgrade Authority Revoked)",
            detail:
              "Upgrade authority is set to None. Deployed BPF bytecode cannot be silently altered.",
          });
        }
        binarySizeBytes = Math.max(0, pdInfo.data.length - 45);
      }
    }
  } else if (loaderType === "BPFLoader2") {
    isImmutable = true;
    binarySizeBytes = programInfo.data.length;
    riskChecks.push({
      id: "AEGIS-CHAIN-001",
      severity: "INFO",
      title: "Immutable BPFLoader2 Deployment",
      detail: "Legacy immutable loader — bytecode cannot be mutated post-deploy.",
    });
  }

  // Decode on-chain Anchor IDL if present
  const decodedIdl = idlInfo?.data ? decodeAnchorIdlAccount(idlInfo.data) : null;
  const idlFound = Boolean(decodedIdl);
  const idlInstructions = decodedIdl?.instructions || [];

  if (idlFound) {
    const unsignedMutIxs = idlInstructions.filter((ix) => ix.writableWithoutSigner);
    if (unsignedMutIxs.length > 0) {
      riskChecks.push({
        id: "AEGIS-CHAIN-002",
        severity: "CRITICAL",
        title: `Permissionless State Mutation Detected in On-Chain IDL (${unsignedMutIxs.length} ix)`,
        detail: `Instruction(s) [${unsignedMutIxs.map((i) => i.name).join(", ")}] mutate writable accounts without requiring any Signer account in the published IDL. Audit authorization constraints immediately.`,
      });
    } else {
      riskChecks.push({
        id: "AEGIS-CHAIN-002",
        severity: "INFO",
        title: `On-Chain Anchor IDL Extracted (${idlInstructions.length} instructions)`,
        detail: "All state-mutating instructions declared in the published IDL require at least one Signer.",
      });
    }
  } else if (programInfo.executable) {
    riskChecks.push({
      id: "AEGIS-CHAIN-003",
      severity: "MEDIUM",
      title: "No On-Chain Anchor IDL Published (Closed Interface / Opaque ABI)",
      detail: `No compressed IDL account found at ${idlPubkey.toBase58()}. Users and wallets cannot independently verify instruction layouts on-chain.`,
    });
  }

  if (latestAttestation?.isVerifiedOracle) {
    riskChecks.push({
      id: "AEGIS-CHAIN-004",
      severity: "INFO",
      title: `AEGIS Ed25519 Oracle Audit Sealed (${latestAttestation.securityScore}/100)`,
      detail: `Cryptographically attested on-chain via Solana Ed25519Program sysvar (${latestAttestation.criticalCount} Critical, ${latestAttestation.highCount} High).`,
    });
  } else if (programInfo.executable) {
    riskChecks.push({
      id: "AEGIS-CHAIN-004",
      severity: "MEDIUM",
      title: "No AEGIS Ed25519 Oracle Audit Attestation Sealed On-Chain",
      detail:
        "Run an x402 V2 source audit and seal an Ed25519-verified AuditAttestation PDA to unlock a verified on-chain trust badge.",
    });
  }

  let surfaceScore = 100;
  for (const r of riskChecks) {
    if (r.severity === "CRITICAL") surfaceScore -= 30;
    else if (r.severity === "HIGH") surfaceScore -= 18;
    else if (r.severity === "MEDIUM") surfaceScore -= 10;
  }
  surfaceScore = Math.max(0, Math.min(100, surfaceScore));

  return {
    programId: programPubkey.toBase58(),
    cluster,
    exists: true,
    executable: programInfo.executable,
    owner: ownerStr,
    loaderType,
    lamports: programInfo.lamports,
    programDataAddress,
    lastDeployedSlot,
    isImmutable,
    upgradeAuthority,
    binarySizeBytes,
    idlFound,
    idlAddress: idlPubkey.toBase58(),
    idlProgramName: decodedIdl?.name || null,
    idlSpecVersion: decodedIdl?.specVersion || null,
    idlInstructions,
    aegisAttestation: latestAttestation,
    riskChecks,
    surfaceScore,
    inspectedAt: new Date().toISOString(),
  };
}
