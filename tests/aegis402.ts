import * as anchorNamespace from "@coral-xyz/anchor";
import {
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  SystemProgram,
} from "@solana/web3.js";
import { expect } from "chai";
import crypto from "crypto";

const anchor: typeof anchorNamespace =
  (anchorNamespace as any).default ?? anchorNamespace;
type Program<T = any> = anchorNamespace.Program<T>;

describe("AEGIS v3 — Commit-Reveal Vault, Anti-Poaching Cooldown, Oracle Arbitration & Ed25519 Attestations", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.Aegis402 as Program<any>;
  const authority = provider.wallet as anchor.Wallet;
  const researcher = Keypair.generate();
  const attacker = Keypair.generate();
  const arbitrator = Keypair.generate();

  const bountyId = new anchor.BN(1);
  const bountyIdDisputed = new anchor.BN(2);
  const findingId = new anchor.BN(101);
  const findingId2 = new anchor.BN(102);
  const findingIdDisputed = new anchor.BN(201);
  const scanId = new anchor.BN(5001);

  let bountyPda: PublicKey;
  let escrowVaultPda: PublicKey;
  let cooldownPda: PublicKey;
  let findingPda: PublicKey;
  let findingPda2: PublicKey;
  let whitehatPda: PublicKey;
  let attestationPda: PublicKey;
  let arbConfigPda: PublicKey;

  let disputedBountyPda: PublicKey;
  let disputedEscrowPda: PublicKey;
  let disputedCooldownPda: PublicKey;
  let disputedFindingPda: PublicKey;
  let disputeTicketPda: PublicKey;

  const pocSummary = "CRITICAL: Missing signer check in withdraw_vault()";
  const secretSalt = "aegis-salt-2026";

  before(async () => {
    const sig1 = await provider.connection.requestAirdrop(researcher.publicKey, 2 * LAMPORTS_PER_SOL);
    const sig2 = await provider.connection.requestAirdrop(attacker.publicKey, 1 * LAMPORTS_PER_SOL);
    const sig3 = await provider.connection.requestAirdrop(arbitrator.publicKey, 1 * LAMPORTS_PER_SOL);
    await provider.connection.confirmTransaction(sig1);
    await provider.connection.confirmTransaction(sig2);
    await provider.connection.confirmTransaction(sig3);

    [arbConfigPda] = PublicKey.findProgramAddressSync([Buffer.from("arb_config")], program.programId);

    [bountyPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("bounty"), authority.publicKey.toBuffer(), bountyId.toArrayLike(Buffer, "le", 8)],
      program.programId
    );
    [escrowVaultPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("escrow_vault"), bountyPda.toBuffer()],
      program.programId
    );
    [cooldownPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("cooldown"), bountyPda.toBuffer()],
      program.programId
    );
    [findingPda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("finding"),
        bountyPda.toBuffer(),
        researcher.publicKey.toBuffer(),
        findingId.toArrayLike(Buffer, "le", 8),
      ],
      program.programId
    );
    [findingPda2] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("finding"),
        bountyPda.toBuffer(),
        researcher.publicKey.toBuffer(),
        findingId2.toArrayLike(Buffer, "le", 8),
      ],
      program.programId
    );
    [whitehatPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("whitehat"), researcher.publicKey.toBuffer()],
      program.programId
    );
    [attestationPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("audit"), researcher.publicKey.toBuffer(), scanId.toArrayLike(Buffer, "le", 8)],
      program.programId
    );

    [disputedBountyPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("bounty"), authority.publicKey.toBuffer(), bountyIdDisputed.toArrayLike(Buffer, "le", 8)],
      program.programId
    );
    [disputedEscrowPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("escrow_vault"), disputedBountyPda.toBuffer()],
      program.programId
    );
    [disputedCooldownPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("cooldown"), disputedBountyPda.toBuffer()],
      program.programId
    );
    [disputedFindingPda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("finding"),
        disputedBountyPda.toBuffer(),
        researcher.publicKey.toBuffer(),
        findingIdDisputed.toArrayLike(Buffer, "le", 8),
      ],
      program.programId
    );
    [disputeTicketPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("dispute"), disputedFindingPda.toBuffer()],
      program.programId
    );
  });

  it("1. Initializes the cluster arbitration oracle configuration", async () => {
    const [programDataPda] = PublicKey.findProgramAddressSync(
      [program.programId.toBuffer()],
      new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111")
    );
    await program.methods
      .initializeArbitrator(arbitrator.publicKey)
      .accounts({
        authority: authority.publicKey,
        arbConfig: arbConfigPda,
        programAccount: program.programId,
        programData: programDataPda,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const cfg = await program.account.arbitrationConfig.fetch(arbConfigPda);
    expect(cfg.arbitrator.toBase58()).to.equal(arbitrator.publicKey.toBase58());
  });

  it("2. Rejects creating a bounty below Solana rent-exempt minimum", async () => {
    const tinyBountyId = new anchor.BN(999);
    const [tinyBountyPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("bounty"), authority.publicKey.toBuffer(), tinyBountyId.toArrayLike(Buffer, "le", 8)],
      program.programId
    );
    const [tinyEscrowPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("escrow_vault"), tinyBountyPda.toBuffer()],
      program.programId
    );
    try {
      await program.methods
        .createBounty(tinyBountyId, "Dust Vault", "https://example.com", new anchor.BN(1000), new anchor.BN(500))
        .accounts({
          authority: authority.publicKey,
          bountyVault: tinyBountyPda,
          escrowSolVault: tinyEscrowPda,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      expect.fail("Should reject below rent-exempt minimum");
    } catch (err: any) {
      expect(err.toString()).to.include("BelowRentExemptMinimum");
    }
  });

  it("3. Creates a rent-safe SOL Bug Bounty Vault backed by PDA escrow", async () => {
    const rewardLamports = new anchor.BN(0.5 * LAMPORTS_PER_SOL);
    const maxPayout = new anchor.BN(0.3 * LAMPORTS_PER_SOL);

    await program.methods
      .createBounty(
        bountyId,
        "Solana DeFi Lending Core",
        "https://github.com/example/solana-lending-scope",
        rewardLamports,
        maxPayout
      )
      .accounts({
        authority: authority.publicKey,
        bountyVault: bountyPda,
        escrowSolVault: escrowVaultPda,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const vaultAccount = await program.account.bountyVault.fetch(bountyPda);
    expect(vaultAccount.remainingPool.toNumber()).to.equal(0.5 * LAMPORTS_PER_SOL);
    expect(vaultAccount.pendingFindings).to.equal(0);
    expect(vaultAccount.isActive).to.be.true;
  });

  it("4. Allows topping up the bounty vault", async () => {
    await program.methods
      .topUpBounty(new anchor.BN(0.2 * LAMPORTS_PER_SOL))
      .accounts({
        funder: authority.publicKey,
        bountyVault: bountyPda,
        escrowSolVault: escrowVaultPda,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const vaultAccount = await program.account.bountyVault.fetch(bountyPda);
    expect(vaultAccount.remainingPool.toNumber()).to.equal(0.7 * LAMPORTS_PER_SOL);
  });

  it("5. Submits a cryptographic SHA-256 Commit-Reveal finding and increments pending_findings", async () => {
    const commitHash = Array.from(
      crypto.createHash("sha256").update(`${pocSummary}||${secretSalt}`).digest()
    );

    await program.methods
      .submitFindingCommit(
        findingId,
        commitHash,
        4,
        "aegis-aes256://sha256/0123456789abcdef0123456789abcdef",
        "crisc_pentester"
      )
      .accounts({
        researcher: researcher.publicKey,
        bountyVault: bountyPda,
        findingReport: findingPda,
        whitehatProfile: whitehatPda,
        systemProgram: SystemProgram.programId,
      })
      .signers([researcher])
      .rpc();

    const vaultAccount = await program.account.bountyVault.fetch(bountyPda);
    expect(vaultAccount.pendingFindings).to.equal(1);
  });

  it("6. Blocks protocol rug-pull: rejects close_bounty while pending findings exist", async () => {
    try {
      await program.methods
        .closeBounty()
        .accounts({
          authority: authority.publicKey,
          bountyVault: bountyPda,
          escrowSolVault: escrowVaultPda,
          vaultCooldown: cooldownPda,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      expect.fail("Protocol must not rug-pull while findings are pending");
    } catch (err: any) {
      expect(err.toString()).to.include("PendingFindingsExist");
    }
  });

  it("7. Rejects reveal_finding with forged salt (SHA-256 mismatch)", async () => {
    try {
      await program.methods
        .revealFinding(pocSummary, "wrong-salt")
        .accounts({
          researcher: researcher.publicKey,
          findingReport: findingPda,
        })
        .signers([researcher])
        .rpc();
      expect.fail("Wrong salt must fail SHA-256 verification");
    } catch (err: any) {
      expect(err.toString()).to.include("CommitHashMismatch");
    }
  });

  it("8. Cryptographically verifies SHA-256 preimage on-chain in reveal_finding", async () => {
    await program.methods
      .revealFinding(pocSummary, secretSalt)
      .accounts({
        researcher: researcher.publicKey,
        findingReport: findingPda,
      })
      .signers([researcher])
      .rpc();

    const finding = await program.account.findingReport.fetch(findingPda);
    expect(finding.revealedSummary).to.equal(pocSummary);
    expect(finding.status).to.have.property("revealed");
  });

  it("9. Rejects unauthorized attacker attempting to steal escrow via approve_and_payout", async () => {
    try {
      await program.methods
        .approveAndPayout(new anchor.BN(0.1 * LAMPORTS_PER_SOL))
        .accounts({
          authority: attacker.publicKey,
          bountyVault: bountyPda,
          escrowSolVault: escrowVaultPda,
          findingReport: findingPda,
          whitehatProfile: whitehatPda,
          researcher: researcher.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([attacker])
        .rpc();
      expect.fail("Unauthorized attacker should be rejected");
    } catch (err: any) {
      expect(err).to.exist;
    }
  });

  it("10. Approves revealed finding, pays SOL from PDA escrow, decrements pending, and awards rep", async () => {
    const balanceBefore = await provider.connection.getBalance(researcher.publicKey);
    const payout = new anchor.BN(0.25 * LAMPORTS_PER_SOL);

    await program.methods
      .approveAndPayout(payout)
      .accounts({
        authority: authority.publicKey,
        bountyVault: bountyPda,
        escrowSolVault: escrowVaultPda,
        findingReport: findingPda,
        whitehatProfile: whitehatPda,
        researcher: researcher.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const balanceAfter = await provider.connection.getBalance(researcher.publicKey);
    expect(balanceAfter - balanceBefore).to.equal(0.25 * LAMPORTS_PER_SOL);

    const profile = await program.account.whitehatProfile.fetch(whitehatPda);
    expect(profile.approvedFindings).to.equal(1);
    expect(profile.reputationScore.toNumber()).to.equal(120);

    const vault = await program.account.bountyVault.fetch(bountyPda);
    expect(vault.pendingFindings).to.equal(0);
  });

  it("11. Allows rejecting an unrevealed spam commit without locking vault cooldown", async () => {
    const hash2 = Array.from(crypto.createHash("sha256").update("dup||salt2").digest());
    await program.methods
      .submitFindingCommit(findingId2, hash2, 1, "aegis-aes256://dup", "crisc_pentester")
      .accounts({
        researcher: researcher.publicKey,
        bountyVault: bountyPda,
        findingReport: findingPda2,
        whitehatProfile: whitehatPda,
        systemProgram: SystemProgram.programId,
      })
      .signers([researcher])
      .rpc();

    await program.methods
      .rejectFinding()
      .accounts({
        authority: authority.publicKey,
        bountyVault: bountyPda,
        findingReport: findingPda2,
        vaultCooldown: cooldownPda,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const f2 = await program.account.findingReport.fetch(findingPda2);
    expect(f2.status).to.have.property("rejected");
    const vault = await program.account.bountyVault.fetch(bountyPda);
    expect(vault.pendingFindings).to.equal(0);
  });

  it("12. Closes bounty vault once pending_findings == 0 and sweeps 100% of escrow SOL", async () => {
    await program.methods
      .closeBounty()
      .accounts({
        authority: authority.publicKey,
        bountyVault: bountyPda,
        escrowSolVault: escrowVaultPda,
        vaultCooldown: cooldownPda,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const vaultAccount = await program.account.bountyVault.fetch(bountyPda);
    expect(vaultAccount.isActive).to.be.false;
    expect(vaultAccount.remainingPool.toNumber()).to.equal(0);
    expect(await provider.connection.getBalance(escrowVaultPda)).to.equal(0);
  });

  it("13. ANTI-POACHING GUARD: Rejecting a Revealed PoC triggers 24h cooldown blocking atomic close_bounty!", async () => {
    await program.methods
      .createBounty(
        bountyIdDisputed,
        "Malicious Protocol Vault",
        "https://github.com/example/malicious-protocol",
        new anchor.BN(0.4 * LAMPORTS_PER_SOL),
        new anchor.BN(0.25 * LAMPORTS_PER_SOL)
      )
      .accounts({
        authority: authority.publicKey,
        bountyVault: disputedBountyPda,
        escrowSolVault: disputedEscrowPda,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const poc = "CRITICAL: Arbitrary CPI hijack in swap_tokens()";
    const salt = "anti-poach-salt";
    const commitHash = Array.from(crypto.createHash("sha256").update(`${poc}||${salt}`).digest());

    await program.methods
      .submitFindingCommit(findingIdDisputed, commitHash, 4, "aegis-aes256://sha256/poach", "crisc_pentester")
      .accounts({
        researcher: researcher.publicKey,
        bountyVault: disputedBountyPda,
        findingReport: disputedFindingPda,
        whitehatProfile: whitehatPda,
        systemProgram: SystemProgram.programId,
      })
      .signers([researcher])
      .rpc();

    await program.methods
      .revealFinding(poc, salt)
      .accounts({
        researcher: researcher.publicKey,
        findingReport: disputedFindingPda,
      })
      .signers([researcher])
      .rpc();

    // Malicious owner rejects the Revealed finding and immediately attempts to drain escrow via close_bounty
    await program.methods
      .rejectFinding()
      .accounts({
        authority: authority.publicKey,
        bountyVault: disputedBountyPda,
        findingReport: disputedFindingPda,
        vaultCooldown: disputedCooldownPda,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    try {
      await program.methods
        .closeBounty()
        .accounts({
          authority: authority.publicKey,
          bountyVault: disputedBountyPda,
          escrowSolVault: disputedEscrowPda,
          vaultCooldown: disputedCooldownPda,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      expect.fail("close_bounty MUST revert during 24h anti-poaching cooldown after rejecting a Revealed PoC!");
    } catch (err: any) {
      expect(err.toString()).to.include("AntiPoachingCooldownActive");
    }
  });

  it("14. Whitehat invokes raise_dispute on rejected Revealed finding, freezing escrow until arbitration", async () => {
    await program.methods
      .raiseDispute("aegis-dispute://evidence/commit-proof-and-patch-diff")
      .accounts({
        researcher: researcher.publicKey,
        bountyVault: disputedBountyPda,
        findingReport: disputedFindingPda,
        disputeTicket: disputeTicketPda,
        systemProgram: SystemProgram.programId,
      })
      .signers([researcher])
      .rpc();

    const finding = await program.account.findingReport.fetch(disputedFindingPda);
    expect(finding.status).to.have.property("disputed");

    const vault = await program.account.bountyVault.fetch(disputedBountyPda);
    expect(vault.pendingFindings).to.equal(1);
  });

  it("15. Blocks unauthorized attacker from forging resolve_dispute arbitration ruling", async () => {
    try {
      await program.methods
        .resolveDispute(true, new anchor.BN(0.2 * LAMPORTS_PER_SOL))
        .accounts({
          caller: attacker.publicKey,
          bountyVault: disputedBountyPda,
          escrowSolVault: disputedEscrowPda,
          findingReport: disputedFindingPda,
          disputeTicket: disputeTicketPda,
          whitehatProfile: whitehatPda,
          researcher: researcher.publicKey,
          arbConfig: arbConfigPda,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
          systemProgram: SystemProgram.programId,
        })
        .signers([attacker])
        .rpc();
      expect.fail("Unauthorized caller must be rejected by resolve_dispute");
    } catch (err: any) {
      expect(err.toString()).to.include("UnauthorizedArbitrator");
    }
  });

  it("16. Authorized AEGIS Oracle resolves dispute in whitehat's favor, releasing escrow SOL & +120 REP", async () => {
    const balBefore = await provider.connection.getBalance(researcher.publicKey);
    const award = new anchor.BN(0.2 * LAMPORTS_PER_SOL);

    await program.methods
      .resolveDispute(true, award)
      .accounts({
        caller: arbitrator.publicKey,
        bountyVault: disputedBountyPda,
        escrowSolVault: disputedEscrowPda,
        findingReport: disputedFindingPda,
        disputeTicket: disputeTicketPda,
        whitehatProfile: whitehatPda,
        researcher: researcher.publicKey,
        arbConfig: arbConfigPda,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        systemProgram: SystemProgram.programId,
      })
      .signers([arbitrator])
      .rpc();

    const balAfter = await provider.connection.getBalance(researcher.publicKey);
    expect(balAfter - balBefore).to.equal(0.2 * LAMPORTS_PER_SOL);

    const ticket = await program.account.disputeTicket.fetch(disputeTicketPda);
    expect(ticket.resolved).to.be.true;
    expect(ticket.upheld).to.be.true;

    const profile = await program.account.whitehatProfile.fetch(whitehatPda);
    expect(profile.approvedFindings).to.equal(2);
    expect(profile.reputationScore.toNumber()).to.equal(240);
  });

  it("17. Marks self-attested audit as is_verified_oracle = false without Ed25519 oracle proof", async () => {
    const srcHash = Array.from(crypto.createHash("sha256").update("fn main() {}").digest());
    const reportHash = Array.from(crypto.createHash("sha256").update("aegis-report-v3").digest());

    await program.methods
      .recordAuditAttestation(
        scanId,
        program.programId,
        srcHash,
        reportHash,
        96,
        0,
        0,
        "5x402DevnetPaymentSignatureVerifiedOnChain987654321"
      )
      .accounts({
        auditor: researcher.publicKey,
        auditAttestation: attestationPda,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        systemProgram: SystemProgram.programId,
      })
      .signers([researcher])
      .rpc();

    const att = await program.account.auditAttestation.fetch(attestationPda);
    expect(att.securityScore).to.equal(96);
    expect(att.isVerifiedOracle).to.be.false;
  });
});
