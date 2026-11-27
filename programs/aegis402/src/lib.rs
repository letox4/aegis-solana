use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    bpf_loader_upgradeable,
    ed25519_program,
    hash::hashv,
    sysvar::instructions::{
        load_current_index_checked, load_instruction_at_checked, ID as IX_SYSVAR_ID,
    },
};
use anchor_lang::system_program;

// Live deployed Solana Devnet Program ID (in-place upgradeable)
declare_id!("8AaU3VSHXHyKcVTe9JCA67oRR5djpjfAUgcM1cCtpe7p");

// Authorized AEGIS x402 Oracle & Default Arbitrator Public Key (3tHUR3MYb1y4uhnWpJub8qCpETVbduXDMVECSBPE9AZS)
pub const AEGIS_ATTESTER_PUBKEY: [u8; 32] = [
    42, 218, 158, 237, 199, 129, 236, 121, 50, 88, 93, 114, 53, 12, 32, 106, 242, 150, 71, 49, 189,
    134, 50, 141, 63, 49, 119, 162, 159, 40, 134, 109,
];

pub const MAX_NAME_LEN: usize = 64;
pub const MAX_URI_LEN: usize = 200;
pub const MAX_SIG_LEN: usize = 96;
pub const MAX_HANDLE_LEN: usize = 32;
pub const MAX_REVEAL_LEN: usize = 160;

// Game-theoretic anti-poaching guards:
// Rejecting an already-Revealed PoC freezes `close_bounty` for 24h so the whitehat can raise arbitration.
pub const REVEALED_REJECT_COOLDOWN_SECS: i64 = 86_400;
pub const DISPUTE_WINDOW_SECS: i64 = 7 * 86_400;

#[program]
pub mod aegis402 {
    use super::*;

    /// Initializes the cluster-wide arbitration oracle keypair once.
    /// On BPFLoaderUpgradeable (Devnet/Mainnet), cryptographically enforces that ONLY the
    /// program's upgrade authority can initialize `arb_config` (100% immune to front-running).
    pub fn initialize_arbitrator(
        ctx: Context<InitializeArbitrator>,
        arbitrator: Pubkey,
    ) -> Result<()> {
        require!(arbitrator != Pubkey::default(), AegisError::InvalidArbitrator);

        let prog_info = &ctx.accounts.program_account;
        if *prog_info.owner == bpf_loader_upgradeable::ID {
            let prog_bytes = prog_info.try_borrow_data()?;
            require!(
                prog_bytes.len() >= 36 && u32::from_le_bytes([prog_bytes[0], prog_bytes[1], prog_bytes[2], prog_bytes[3]]) == 2,
                AegisError::Unauthorized
            );
            let expected_pd = Pubkey::try_from(&prog_bytes[4..36])
                .map_err(|_| error!(AegisError::Unauthorized))?;
            require_keys_eq!(
                ctx.accounts.program_data.key(),
                expected_pd,
                AegisError::Unauthorized
            );

            let pd_info = &ctx.accounts.program_data;
            require_keys_eq!(
                *pd_info.owner,
                bpf_loader_upgradeable::ID,
                AegisError::Unauthorized
            );
            let pd_bytes = pd_info.try_borrow_data()?;
            require!(
                pd_bytes.len() >= 45
                    && u32::from_le_bytes([pd_bytes[0], pd_bytes[1], pd_bytes[2], pd_bytes[3]]) == 3,
                AegisError::Unauthorized
            );
            let deployed_slot = u64::from_le_bytes([
                pd_bytes[4], pd_bytes[5], pd_bytes[6], pd_bytes[7],
                pd_bytes[8], pd_bytes[9], pd_bytes[10], pd_bytes[11],
            ]);
            if pd_bytes[12] == 1 {
                let upgrade_auth = Pubkey::try_from(&pd_bytes[13..45])
                    .map_err(|_| error!(AegisError::Unauthorized))?;
                if upgrade_auth != Pubkey::default() {
                    require_keys_eq!(
                        ctx.accounts.authority.key(),
                        upgrade_auth,
                        AegisError::Unauthorized
                    );
                } else {
                    require!(deployed_slot == 0, AegisError::Unauthorized);
                }
            } else {
                require!(deployed_slot == 0, AegisError::Unauthorized);
            }
        }

        let cfg = &mut ctx.accounts.arb_config;
        cfg.authority = ctx.accounts.authority.key();
        cfg.arbitrator = arbitrator;
        cfg.bump = ctx.bumps.arb_config;

        Ok(())
    }

    /// Protocol creates a trustless SOL Bug Bounty Vault backed by a rent-safe PDA escrow.
    pub fn create_bounty(
        ctx: Context<CreateBounty>,
        bounty_id: u64,
        target_name: String,
        scope_uri: String,
        reward_lamports: u64,
        max_payout_per_finding: u64,
    ) -> Result<()> {
        let rent_min = Rent::get()?.minimum_balance(0);
        require!(
            !target_name.is_empty() && target_name.len() <= MAX_NAME_LEN,
            AegisError::InvalidTargetName
        );
        require!(
            !scope_uri.is_empty() && scope_uri.len() <= MAX_URI_LEN,
            AegisError::InvalidScopeUri
        );
        require!(
            reward_lamports >= rent_min,
            AegisError::BelowRentExemptMinimum
        );
        require!(
            max_payout_per_finding > 0 && max_payout_per_finding <= reward_lamports,
            AegisError::InvalidMaxPayout
        );

        let bounty = &mut ctx.accounts.bounty_vault;
        let clock = Clock::get()?;

        bounty.authority = ctx.accounts.authority.key();
        bounty.bounty_id = bounty_id;
        bounty.target_name = target_name.clone();
        bounty.scope_uri = scope_uri;
        bounty.total_deposited = reward_lamports;
        bounty.remaining_pool = reward_lamports;
        bounty.max_payout_per_finding = max_payout_per_finding;
        bounty.findings_count = 0;
        bounty.pending_findings = 0;
        bounty.approved_count = 0;
        bounty.is_active = true;
        bounty.created_at = clock.unix_timestamp;
        bounty.bump = ctx.bumps.bounty_vault;
        bounty.vault_bump = ctx.bumps.escrow_sol_vault;

        let cpi_ctx = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: ctx.accounts.authority.to_account_info(),
                to: ctx.accounts.escrow_sol_vault.to_account_info(),
            },
        );
        system_program::transfer(cpi_ctx, reward_lamports)?;

        emit!(BountyCreatedEvent {
            bounty: bounty.key(),
            authority: bounty.authority,
            bounty_id,
            target_name,
            reward_lamports,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    /// Anyone (protocol treasury or LI.FI bridge recipient) can top up an active bounty pool.
    pub fn top_up_bounty(ctx: Context<TopUpBounty>, amount_lamports: u64) -> Result<()> {
        require!(amount_lamports > 0, AegisError::ZeroAmount);
        let bounty = &mut ctx.accounts.bounty_vault;
        require!(bounty.is_active, AegisError::BountyClosed);

        let cpi_ctx = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: ctx.accounts.funder.to_account_info(),
                to: ctx.accounts.escrow_sol_vault.to_account_info(),
            },
        );
        system_program::transfer(cpi_ctx, amount_lamports)?;

        bounty.total_deposited = bounty
            .total_deposited
            .checked_add(amount_lamports)
            .ok_or(AegisError::ArithmeticOverflow)?;
        bounty.remaining_pool = bounty
            .remaining_pool
            .checked_add(amount_lamports)
            .ok_or(AegisError::ArithmeticOverflow)?;

        emit!(BountyFundedEvent {
            bounty: bounty.key(),
            funder: ctx.accounts.funder.key(),
            amount_lamports,
            new_pool: bounty.remaining_pool,
        });

        Ok(())
    }

    /// Whitehat commits SHA-256(poc_summary || "||" || salt) on-chain.
    /// Locks cryptographic timestamp proof without leaking exploit details, and prevents protocol rug-pull.
    pub fn submit_finding_commit(
        ctx: Context<SubmitFindingCommit>,
        finding_id: u64,
        commit_hash: [u8; 32],
        severity: u8,
        encrypted_report_uri: String,
        researcher_handle: String,
    ) -> Result<()> {
        require!(severity >= 1 && severity <= 4, AegisError::InvalidSeverity);
        require!(
            !encrypted_report_uri.is_empty() && encrypted_report_uri.len() <= MAX_URI_LEN,
            AegisError::InvalidReportUri
        );
        require!(
            !researcher_handle.is_empty() && researcher_handle.len() <= MAX_HANDLE_LEN,
            AegisError::InvalidHandle
        );
        require!(commit_hash != [0u8; 32], AegisError::InvalidCommitHash);

        let bounty = &mut ctx.accounts.bounty_vault;
        require!(bounty.is_active, AegisError::BountyClosed);

        let clock = Clock::get()?;

        let finding = &mut ctx.accounts.finding_report;
        finding.bounty = bounty.key();
        finding.researcher = ctx.accounts.researcher.key();
        finding.finding_id = finding_id;
        finding.commit_hash = commit_hash;
        finding.severity = severity;
        finding.encrypted_report_uri = encrypted_report_uri;
        finding.revealed_summary = String::new();
        finding.status = FindingStatus::Committed;
        finding.payout_lamports = 0;
        finding.submitted_at = clock.unix_timestamp;
        finding.resolved_at = 0;
        finding.bump = ctx.bumps.finding_report;

        bounty.findings_count = bounty
            .findings_count
            .checked_add(1)
            .ok_or(AegisError::ArithmeticOverflow)?;
        bounty.pending_findings = bounty
            .pending_findings
            .checked_add(1)
            .ok_or(AegisError::ArithmeticOverflow)?;

        let profile = &mut ctx.accounts.whitehat_profile;
        if profile.researcher == Pubkey::default() {
            profile.researcher = ctx.accounts.researcher.key();
            profile.handle = researcher_handle;
            profile.bump = ctx.bumps.whitehat_profile;
        }
        profile.total_submissions = profile
            .total_submissions
            .checked_add(1)
            .ok_or(AegisError::ArithmeticOverflow)?;

        emit!(FindingCommittedEvent {
            bounty: bounty.key(),
            finding: finding.key(),
            researcher: finding.researcher,
            finding_id,
            commit_hash,
            severity,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    /// Whitehat cryptographically reveals PoC summary + salt; Solana runtime verifies SHA-256 on-chain!
    pub fn reveal_finding(
        ctx: Context<RevealFinding>,
        poc_summary: String,
        salt: String,
    ) -> Result<()> {
        require!(
            !poc_summary.is_empty() && poc_summary.len() <= MAX_REVEAL_LEN,
            AegisError::InvalidRevealSummary
        );
        require!(!salt.is_empty() && salt.len() <= 64, AegisError::InvalidSalt);

        let finding = &mut ctx.accounts.finding_report;
        require!(
            finding.status == FindingStatus::Committed,
            AegisError::FindingAlreadyResolved
        );

        let computed = hashv(&[poc_summary.as_bytes(), b"||", salt.as_bytes()]);
        require!(
            computed.to_bytes() == finding.commit_hash,
            AegisError::CommitHashMismatch
        );

        let clock = Clock::get()?;
        finding.status = FindingStatus::Revealed;
        finding.revealed_summary = poc_summary;

        emit!(FindingRevealedEvent {
            bounty: finding.bounty,
            finding: finding.key(),
            researcher: finding.researcher,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    /// Protocol authority approves a Committed/Revealed/Disputed finding, releases rent-safe SOL
    /// from PDA escrow, and awards anti-Sybil reputation.
    pub fn approve_and_payout(
        ctx: Context<ApproveAndPayout>,
        payout_lamports: u64,
    ) -> Result<()> {
        let bounty = &mut ctx.accounts.bounty_vault;
        let finding = &mut ctx.accounts.finding_report;
        let profile = &mut ctx.accounts.whitehat_profile;

        require!(
            finding.status == FindingStatus::Committed
                || finding.status == FindingStatus::Revealed
                || finding.status == FindingStatus::Disputed,
            AegisError::FindingAlreadyResolved
        );
        require!(payout_lamports > 0, AegisError::ZeroAmount);
        require!(
            payout_lamports <= bounty.max_payout_per_finding,
            AegisError::ExceedsMaxPayout
        );
        require!(
            payout_lamports <= bounty.remaining_pool,
            AegisError::InsufficientVaultFunds
        );

        let rent_min = Rent::get()?.minimum_balance(0);
        let escrow_balance = ctx.accounts.escrow_sol_vault.lamports();
        require!(
            payout_lamports <= escrow_balance,
            AegisError::InsufficientVaultFunds
        );
        let escrow_after = escrow_balance
            .checked_sub(payout_lamports)
            .ok_or(AegisError::ArithmeticOverflow)?;
        require!(
            escrow_after == 0 || escrow_after >= rent_min,
            AegisError::RentExemptViolation
        );

        let researcher_after = ctx
            .accounts
            .researcher
            .lamports()
            .checked_add(payout_lamports)
            .ok_or(AegisError::ArithmeticOverflow)?;
        require!(researcher_after >= rent_min, AegisError::RentExemptViolation);

        let clock = Clock::get()?;

        let bounty_key = bounty.key();
        let signer_seeds: &[&[&[u8]]] = &[&[
            b"escrow_vault",
            bounty_key.as_ref(),
            &[bounty.vault_bump],
        ]];

        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: ctx.accounts.escrow_sol_vault.to_account_info(),
                to: ctx.accounts.researcher.to_account_info(),
            },
            signer_seeds,
        );
        system_program::transfer(cpi_ctx, payout_lamports)?;

        bounty.remaining_pool = bounty
            .remaining_pool
            .checked_sub(payout_lamports)
            .ok_or(AegisError::ArithmeticOverflow)?;
        bounty.pending_findings = bounty
            .pending_findings
            .checked_sub(1)
            .ok_or(AegisError::ArithmeticOverflow)?;
        bounty.approved_count = bounty
            .approved_count
            .checked_add(1)
            .ok_or(AegisError::ArithmeticOverflow)?;

        finding.status = FindingStatus::Approved;
        finding.payout_lamports = payout_lamports;
        finding.resolved_at = clock.unix_timestamp;

        let rep_gain: u64 = compute_reputation_gain(bounty.authority, finding.researcher, finding.severity);

        profile.approved_findings = profile
            .approved_findings
            .checked_add(1)
            .ok_or(AegisError::ArithmeticOverflow)?;
        profile.total_earned_lamports = profile
            .total_earned_lamports
            .checked_add(payout_lamports)
            .ok_or(AegisError::ArithmeticOverflow)?;
        profile.reputation_score = profile
            .reputation_score
            .checked_add(rep_gain)
            .ok_or(AegisError::ArithmeticOverflow)?;

        emit!(FindingApprovedEvent {
            bounty: bounty.key(),
            finding: finding.key(),
            researcher: finding.researcher,
            payout_lamports,
            reputation_score: profile.reputation_score,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    /// Protocol authority rejects an invalid/duplicate finding.
    /// ANTI-POACHING GAME THEORY: If the finding was already cryptographically `Revealed`,
    /// rejecting it triggers a 24h `VaultCooldown` lock blocking `close_bounty` so the
    /// researcher cannot be front-run by an atomic `[reject_finding, close_bounty]` bundle
    /// and has guaranteed time to invoke `raise_dispute`!
    pub fn reject_finding(ctx: Context<RejectFinding>) -> Result<()> {
        let bounty = &mut ctx.accounts.bounty_vault;
        let finding = &mut ctx.accounts.finding_report;
        let cooldown = &mut ctx.accounts.vault_cooldown;

        require!(
            finding.status == FindingStatus::Committed || finding.status == FindingStatus::Revealed,
            AegisError::FindingAlreadyResolved
        );

        let was_revealed = finding.status == FindingStatus::Revealed;
        let clock = Clock::get()?;

        finding.status = FindingStatus::Rejected;
        finding.resolved_at = clock.unix_timestamp;
        bounty.pending_findings = bounty
            .pending_findings
            .checked_sub(1)
            .ok_or(AegisError::ArithmeticOverflow)?;

        if cooldown.bounty == Pubkey::default() {
            cooldown.bounty = bounty.key();
            cooldown.bump = ctx.bumps.vault_cooldown;
        }

        if was_revealed {
            let min_unlock = clock
                .unix_timestamp
                .checked_add(REVEALED_REJECT_COOLDOWN_SECS)
                .ok_or(AegisError::ArithmeticOverflow)?;
            if min_unlock > cooldown.unlock_at {
                cooldown.unlock_at = min_unlock;
            }
            cooldown.last_rejected_finding = finding.key();
        }

        emit!(FindingRejectedEvent {
            bounty: bounty.key(),
            finding: finding.key(),
            researcher: finding.researcher,
            was_revealed,
            cooldown_unlock_at: cooldown.unlock_at,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    /// Whitehat challenges an unfair rejection of a cryptographically Revealed finding.
    /// Re-locks `pending_findings += 1` (freezing escrow withdrawal) and opens on-chain arbitration.
    pub fn raise_dispute(ctx: Context<RaiseDispute>, reason_uri: String) -> Result<()> {
        require!(
            !reason_uri.is_empty() && reason_uri.len() <= MAX_URI_LEN,
            AegisError::InvalidReportUri
        );

        let bounty = &mut ctx.accounts.bounty_vault;
        let finding = &mut ctx.accounts.finding_report;
        let ticket = &mut ctx.accounts.dispute_ticket;

        require!(bounty.is_active, AegisError::BountyClosed);
        require!(
            finding.status == FindingStatus::Rejected,
            AegisError::InvalidDisputeState
        );
        require!(
            !finding.revealed_summary.is_empty(),
            AegisError::MustRevealBeforeDispute
        );

        let clock = Clock::get()?;
        let deadline = finding
            .resolved_at
            .checked_add(DISPUTE_WINDOW_SECS)
            .ok_or(AegisError::ArithmeticOverflow)?;
        require!(
            clock.unix_timestamp <= deadline,
            AegisError::DisputeWindowExpired
        );

        finding.status = FindingStatus::Disputed;
        bounty.pending_findings = bounty
            .pending_findings
            .checked_add(1)
            .ok_or(AegisError::ArithmeticOverflow)?;

        ticket.bounty = bounty.key();
        ticket.finding = finding.key();
        ticket.researcher = finding.researcher;
        ticket.reason_uri = reason_uri;
        ticket.opened_at = clock.unix_timestamp;
        ticket.resolved = false;
        ticket.upheld = false;
        ticket.awarded_lamports = 0;
        ticket.resolved_at = 0;
        ticket.bump = ctx.bumps.dispute_ticket;

        emit!(DisputeRaisedEvent {
            bounty: bounty.key(),
            finding: finding.key(),
            dispute_ticket: ticket.key(),
            researcher: finding.researcher,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    /// Independent AEGIS Arbitration Oracle resolves a disputed finding (authorized via direct
    /// arbitrator signature OR inline Ed25519Program Sysvar signature). If upheld, releases the
    /// bounty directly from PDA escrow to the researcher even if the protocol owner refuses to pay.
    pub fn resolve_dispute(
        ctx: Context<ResolveDispute>,
        uphold_researcher: bool,
        award_lamports: u64,
    ) -> Result<()> {
        let expected_arbitrator = resolve_expected_arbitrator(&ctx.accounts.arb_config, ctx.program_id)?;

        let direct_auth = ctx.accounts.caller.key().to_bytes() == expected_arbitrator;
        let ed25519_auth = if direct_auth {
            true
        } else {
            let ruling_msg = build_canonical_ruling_msg(
                &ctx.accounts.finding_report.key(),
                uphold_researcher,
                award_lamports,
            );
            verify_ed25519_oracle_instruction(
                &ctx.accounts.instructions_sysvar.to_account_info(),
                &expected_arbitrator,
                &ruling_msg,
            )?
        };
        require!(ed25519_auth, AegisError::UnauthorizedArbitrator);

        let bounty = &mut ctx.accounts.bounty_vault;
        let finding = &mut ctx.accounts.finding_report;
        let ticket = &mut ctx.accounts.dispute_ticket;
        let profile = &mut ctx.accounts.whitehat_profile;

        require!(
            finding.status == FindingStatus::Disputed && !ticket.resolved,
            AegisError::InvalidDisputeState
        );

        let clock = Clock::get()?;
        let final_payout: u64;

        if uphold_researcher {
            require!(award_lamports > 0, AegisError::ZeroAmount);
            require!(
                award_lamports <= bounty.max_payout_per_finding,
                AegisError::ExceedsMaxPayout
            );
            require!(
                award_lamports <= bounty.remaining_pool,
                AegisError::InsufficientVaultFunds
            );

            let rent_min = Rent::get()?.minimum_balance(0);
            let escrow_balance = ctx.accounts.escrow_sol_vault.lamports();
            require!(
                award_lamports <= escrow_balance,
                AegisError::InsufficientVaultFunds
            );
            let escrow_after = escrow_balance
                .checked_sub(award_lamports)
                .ok_or(AegisError::ArithmeticOverflow)?;
            require!(
                escrow_after == 0 || escrow_after >= rent_min,
                AegisError::RentExemptViolation
            );

            let researcher_after = ctx
                .accounts
                .researcher
                .lamports()
                .checked_add(award_lamports)
                .ok_or(AegisError::ArithmeticOverflow)?;
            require!(researcher_after >= rent_min, AegisError::RentExemptViolation);

            let bounty_key = bounty.key();
            let signer_seeds: &[&[&[u8]]] = &[&[
                b"escrow_vault",
                bounty_key.as_ref(),
                &[bounty.vault_bump],
            ]];

            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.escrow_sol_vault.to_account_info(),
                    to: ctx.accounts.researcher.to_account_info(),
                },
                signer_seeds,
            );
            system_program::transfer(cpi_ctx, award_lamports)?;

            bounty.remaining_pool = bounty
                .remaining_pool
                .checked_sub(award_lamports)
                .ok_or(AegisError::ArithmeticOverflow)?;
            bounty.approved_count = bounty
                .approved_count
                .checked_add(1)
                .ok_or(AegisError::ArithmeticOverflow)?;

            finding.status = FindingStatus::Approved;
            finding.payout_lamports = award_lamports;

            let rep_gain = compute_reputation_gain(bounty.authority, finding.researcher, finding.severity);
            profile.approved_findings = profile
                .approved_findings
                .checked_add(1)
                .ok_or(AegisError::ArithmeticOverflow)?;
            profile.total_earned_lamports = profile
                .total_earned_lamports
                .checked_add(award_lamports)
                .ok_or(AegisError::ArithmeticOverflow)?;
            profile.reputation_score = profile
                .reputation_score
                .checked_add(rep_gain)
                .ok_or(AegisError::ArithmeticOverflow)?;

            final_payout = award_lamports;
        } else {
            finding.status = FindingStatus::Rejected;
            final_payout = 0;
        }

        bounty.pending_findings = bounty
            .pending_findings
            .checked_sub(1)
            .ok_or(AegisError::ArithmeticOverflow)?;
        finding.resolved_at = clock.unix_timestamp;

        ticket.resolved = true;
        ticket.upheld = uphold_researcher;
        ticket.awarded_lamports = final_payout;
        ticket.resolved_at = clock.unix_timestamp;

        emit!(DisputeResolvedEvent {
            bounty: bounty.key(),
            finding: finding.key(),
            dispute_ticket: ticket.key(),
            researcher: finding.researcher,
            upheld: uphold_researcher,
            awarded_lamports: final_payout,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    /// Protocol authority closes the bounty vault ONLY when zero unresolved findings remain
    /// AND any post-Reveal anti-poaching cooldown window has expired, sweeping 100% of escrow SOL.
    pub fn close_bounty(ctx: Context<CloseBounty>) -> Result<()> {
        let bounty = &mut ctx.accounts.bounty_vault;
        require!(bounty.is_active, AegisError::BountyClosed);
        require!(
            bounty.pending_findings == 0,
            AegisError::PendingFindingsExist
        );

        let cd_info = &ctx.accounts.vault_cooldown;
        if !cd_info.data_is_empty() && cd_info.owner == ctx.program_id {
            let mut data_slice: &[u8] = &cd_info.try_borrow_data()?;
            let cd = VaultCooldown::try_deserialize(&mut data_slice)?;
            let clock = Clock::get()?;
            require!(
                clock.unix_timestamp >= cd.unlock_at,
                AegisError::AntiPoachingCooldownActive
            );
        }

        let refund_amount = ctx.accounts.escrow_sol_vault.lamports();
        bounty.is_active = false;
        bounty.remaining_pool = 0;

        if refund_amount > 0 {
            let bounty_key = bounty.key();
            let signer_seeds: &[&[&[u8]]] = &[&[
                b"escrow_vault",
                bounty_key.as_ref(),
                &[bounty.vault_bump],
            ]];

            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.escrow_sol_vault.to_account_info(),
                    to: ctx.accounts.authority.to_account_info(),
                },
                signer_seeds,
            );
            system_program::transfer(cpi_ctx, refund_amount)?;
        }

        emit!(BountyClosedEvent {
            bounty: bounty.key(),
            authority: bounty.authority,
            refunded_lamports: refund_amount,
        });

        Ok(())
    }

    /// Seals an x402 security audit attestation permanently on Solana Devnet.
    /// Inspects the Solana Instructions Sysvar for a preceding Ed25519Program signature from
    /// AEGIS_ATTESTER_PUBKEY over the exact canonical report+source hash payload.
    pub fn record_audit_attestation(
        ctx: Context<RecordAuditAttestation>,
        scan_id: u64,
        target_program_id: Pubkey,
        source_code_hash: [u8; 32],
        report_hash: [u8; 32],
        security_score: u8,
        critical_count: u8,
        high_count: u8,
        x402_payment_sig: String,
    ) -> Result<()> {
        require!(security_score <= 100, AegisError::InvalidSecurityScore);
        require!(source_code_hash != [0u8; 32], AegisError::InvalidCommitHash);
        require!(report_hash != [0u8; 32], AegisError::InvalidCommitHash);
        require!(
            !x402_payment_sig.is_empty() && x402_payment_sig.len() <= MAX_SIG_LEN,
            AegisError::InvalidPaymentSig
        );

        let expected_msg = build_canonical_attestation_msg(
            &target_program_id,
            &source_code_hash,
            &report_hash,
            security_score,
            critical_count,
            high_count,
            &x402_payment_sig,
        );

        let is_verified_oracle = verify_ed25519_oracle_instruction(
            &ctx.accounts.instructions_sysvar.to_account_info(),
            &AEGIS_ATTESTER_PUBKEY,
            &expected_msg,
        )?;

        let clock = Clock::get()?;
        let attestation = &mut ctx.accounts.audit_attestation;

        attestation.auditor = ctx.accounts.auditor.key();
        attestation.scan_id = scan_id;
        attestation.target_program_id = target_program_id;
        attestation.source_code_hash = source_code_hash;
        attestation.report_hash = report_hash;
        attestation.security_score = security_score;
        attestation.critical_count = critical_count;
        attestation.high_count = high_count;
        attestation.x402_payment_sig = x402_payment_sig.clone();
        attestation.is_verified_oracle = is_verified_oracle;
        attestation.audited_at = clock.unix_timestamp;
        attestation.bump = ctx.bumps.audit_attestation;

        emit!(AuditAttestedEvent {
            attestation: attestation.key(),
            auditor: attestation.auditor,
            target_program_id,
            source_code_hash,
            report_hash,
            security_score,
            critical_count,
            high_count,
            is_verified_oracle,
            x402_payment_sig,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }
}

fn compute_reputation_gain(authority: Pubkey, researcher: Pubkey, severity: u8) -> u64 {
    if authority == researcher {
        0
    } else {
        match severity {
            1 => 10,
            2 => 25,
            3 => 60,
            4 => 120,
            _ => 10,
        }
    }
}

fn resolve_expected_arbitrator(
    arb_config_info: &UncheckedAccount,
    program_id: &Pubkey,
) -> Result<[u8; 32]> {
    if !arb_config_info.data_is_empty() && arb_config_info.owner == program_id {
        let mut slice: &[u8] = &arb_config_info.try_borrow_data()?;
        let cfg = ArbitrationConfig::try_deserialize(&mut slice)?;
        return Ok(cfg.arbitrator.to_bytes());
    }
    Ok(AEGIS_ATTESTER_PUBKEY)
}

fn build_canonical_ruling_msg(
    finding_pubkey: &Pubkey,
    uphold_researcher: bool,
    award_lamports: u64,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(21 + 32 + 1 + 8);
    msg.extend_from_slice(b"AEGIS_ARBITRATION_V1:");
    msg.extend_from_slice(finding_pubkey.as_ref());
    msg.push(u8::from(uphold_researcher));
    msg.extend_from_slice(&award_lamports.to_le_bytes());
    msg
}

/// Builds the deterministic message signed by the AEGIS x402 Oracle Attester.
fn build_canonical_attestation_msg(
    target_program_id: &Pubkey,
    source_code_hash: &[u8; 32],
    report_hash: &[u8; 32],
    security_score: u8,
    critical_count: u8,
    high_count: u8,
    x402_payment_sig: &str,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(15 + 32 + 32 + 32 + 3 + x402_payment_sig.len());
    msg.extend_from_slice(b"AEGIS_AUDIT_V2:");
    msg.extend_from_slice(target_program_id.as_ref());
    msg.extend_from_slice(source_code_hash);
    msg.extend_from_slice(report_hash);
    msg.push(security_score);
    msg.push(critical_count);
    msg.push(high_count);
    msg.extend_from_slice(x402_payment_sig.as_bytes());
    msg
}

/// Inspects the immediately preceding transaction instruction via the Solana Instructions Sysvar.
fn verify_ed25519_oracle_instruction(
    ix_sysvar: &AccountInfo,
    expected_pubkey: &[u8; 32],
    expected_msg: &[u8],
) -> Result<bool> {
    let current_idx = load_current_index_checked(ix_sysvar)
        .map_err(|_| error!(AegisError::InvalidSysvarInstruction))?;
    if current_idx == 0 {
        return Ok(false);
    }

    let prev_ix = load_instruction_at_checked((current_idx - 1) as usize, ix_sysvar)
        .map_err(|_| error!(AegisError::InvalidSysvarInstruction))?;

    if prev_ix.program_id != ed25519_program::ID || !prev_ix.accounts.is_empty() {
        return Ok(false);
    }

    let data = prev_ix.data.as_slice();
    if data.len() < 16 || data[0] != 1 {
        return Ok(false);
    }

    let sig_ix_idx = u16::from_le_bytes([data[4], data[5]]);
    let pk_offset = u16::from_le_bytes([data[6], data[7]]) as usize;
    let pk_ix_idx = u16::from_le_bytes([data[8], data[9]]);
    let msg_offset = u16::from_le_bytes([data[10], data[11]]) as usize;
    let msg_size = u16::from_le_bytes([data[12], data[13]]) as usize;
    let msg_ix_idx = u16::from_le_bytes([data[14], data[15]]);

    if sig_ix_idx != u16::MAX || pk_ix_idx != u16::MAX || msg_ix_idx != u16::MAX {
        return Ok(false);
    }

    let pk_end = pk_offset.checked_add(32).ok_or(AegisError::ArithmeticOverflow)?;
    let msg_end = msg_offset
        .checked_add(msg_size)
        .ok_or(AegisError::ArithmeticOverflow)?;
    if pk_end > data.len() || msg_end > data.len() {
        return Ok(false);
    }

    let signer_pk = &data[pk_offset..pk_end];
    let signed_msg = &data[msg_offset..msg_end];

    Ok(signer_pk == expected_pubkey && signed_msg == expected_msg)
}

// ============================================================================
// Account Contexts
// ============================================================================

#[derive(Accounts)]
pub struct InitializeArbitrator<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = ArbitrationConfig::SPACE,
        seeds = [b"arb_config"],
        bump
    )]
    pub arb_config: Account<'info, ArbitrationConfig>,

    /// CHECK: Verified by exact program ID address constraint.
    #[account(address = crate::ID)]
    pub program_account: UncheckedAccount<'info>,

    /// CHECK: Verified against program_account bytes 4..36 when owned by BPFLoaderUpgradeable.
    #[account(address = program_data.key())]
    pub program_data: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(bounty_id: u64)]
pub struct CreateBounty<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = BountyVault::SPACE,
        seeds = [b"bounty", authority.key().as_ref(), &bounty_id.to_le_bytes()],
        bump
    )]
    pub bounty_vault: Account<'info, BountyVault>,

    /// CHECK: Pure SOL PDA vault controlled strictly via PDA signer seeds.
    #[account(
        mut,
        seeds = [b"escrow_vault", bounty_vault.key().as_ref()],
        bump
    )]
    pub escrow_sol_vault: SystemAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct TopUpBounty<'info> {
    #[account(mut)]
    pub funder: Signer<'info>,

    #[account(
        mut,
        seeds = [b"bounty", bounty_vault.authority.as_ref(), &bounty_vault.bounty_id.to_le_bytes()],
        bump = bounty_vault.bump
    )]
    pub bounty_vault: Account<'info, BountyVault>,

    /// CHECK: Pure SOL PDA vault controlled strictly via PDA signer seeds.
    #[account(
        mut,
        seeds = [b"escrow_vault", bounty_vault.key().as_ref()],
        bump = bounty_vault.vault_bump
    )]
    pub escrow_sol_vault: SystemAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(finding_id: u64)]
pub struct SubmitFindingCommit<'info> {
    #[account(mut)]
    pub researcher: Signer<'info>,

    #[account(
        mut,
        seeds = [b"bounty", bounty_vault.authority.as_ref(), &bounty_vault.bounty_id.to_le_bytes()],
        bump = bounty_vault.bump
    )]
    pub bounty_vault: Account<'info, BountyVault>,

    #[account(
        init,
        payer = researcher,
        space = FindingReport::SPACE,
        seeds = [b"finding", bounty_vault.key().as_ref(), researcher.key().as_ref(), &finding_id.to_le_bytes()],
        bump
    )]
    pub finding_report: Account<'info, FindingReport>,

    #[account(
        init_if_needed,
        payer = researcher,
        space = WhitehatProfile::SPACE,
        seeds = [b"whitehat", researcher.key().as_ref()],
        bump
    )]
    pub whitehat_profile: Account<'info, WhitehatProfile>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevealFinding<'info> {
    pub researcher: Signer<'info>,

    #[account(
        mut,
        has_one = researcher @ AegisError::ResearcherMismatch,
        seeds = [b"finding", finding_report.bounty.as_ref(), researcher.key().as_ref(), &finding_report.finding_id.to_le_bytes()],
        bump = finding_report.bump
    )]
    pub finding_report: Account<'info, FindingReport>,
}

#[derive(Accounts)]
pub struct ApproveAndPayout<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        mut,
        has_one = authority @ AegisError::Unauthorized,
        seeds = [b"bounty", authority.key().as_ref(), &bounty_vault.bounty_id.to_le_bytes()],
        bump = bounty_vault.bump
    )]
    pub bounty_vault: Account<'info, BountyVault>,

    /// CHECK: Pure SOL PDA vault controlled strictly via PDA signer seeds.
    #[account(
        mut,
        seeds = [b"escrow_vault", bounty_vault.key().as_ref()],
        bump = bounty_vault.vault_bump
    )]
    pub escrow_sol_vault: SystemAccount<'info>,

    #[account(
        mut,
        has_one = researcher @ AegisError::ResearcherMismatch,
        constraint = finding_report.bounty == bounty_vault.key() @ AegisError::BountyMismatch,
        seeds = [b"finding", bounty_vault.key().as_ref(), researcher.key().as_ref(), &finding_report.finding_id.to_le_bytes()],
        bump = finding_report.bump
    )]
    pub finding_report: Account<'info, FindingReport>,

    #[account(
        mut,
        has_one = researcher @ AegisError::ResearcherMismatch,
        seeds = [b"whitehat", researcher.key().as_ref()],
        bump = whitehat_profile.bump
    )]
    pub whitehat_profile: Account<'info, WhitehatProfile>,

    /// CHECK: Verified via `has_one = researcher` on both `finding_report` and `whitehat_profile`.
    #[account(mut)]
    pub researcher: SystemAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RejectFinding<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        mut,
        has_one = authority @ AegisError::Unauthorized,
        seeds = [b"bounty", authority.key().as_ref(), &bounty_vault.bounty_id.to_le_bytes()],
        bump = bounty_vault.bump
    )]
    pub bounty_vault: Account<'info, BountyVault>,

    #[account(
        mut,
        constraint = finding_report.bounty == bounty_vault.key() @ AegisError::BountyMismatch,
        seeds = [b"finding", bounty_vault.key().as_ref(), finding_report.researcher.as_ref(), &finding_report.finding_id.to_le_bytes()],
        bump = finding_report.bump
    )]
    pub finding_report: Account<'info, FindingReport>,

    #[account(
        init_if_needed,
        payer = authority,
        space = VaultCooldown::SPACE,
        seeds = [b"cooldown", bounty_vault.key().as_ref()],
        bump
    )]
    pub vault_cooldown: Account<'info, VaultCooldown>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RaiseDispute<'info> {
    #[account(mut)]
    pub researcher: Signer<'info>,

    #[account(
        mut,
        seeds = [b"bounty", bounty_vault.authority.as_ref(), &bounty_vault.bounty_id.to_le_bytes()],
        bump = bounty_vault.bump
    )]
    pub bounty_vault: Account<'info, BountyVault>,

    #[account(
        mut,
        has_one = researcher @ AegisError::ResearcherMismatch,
        constraint = finding_report.bounty == bounty_vault.key() @ AegisError::BountyMismatch,
        seeds = [b"finding", bounty_vault.key().as_ref(), researcher.key().as_ref(), &finding_report.finding_id.to_le_bytes()],
        bump = finding_report.bump
    )]
    pub finding_report: Account<'info, FindingReport>,

    #[account(
        init,
        payer = researcher,
        space = DisputeTicket::SPACE,
        seeds = [b"dispute", finding_report.key().as_ref()],
        bump
    )]
    pub dispute_ticket: Account<'info, DisputeTicket>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ResolveDispute<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,

    #[account(
        mut,
        seeds = [b"bounty", bounty_vault.authority.as_ref(), &bounty_vault.bounty_id.to_le_bytes()],
        bump = bounty_vault.bump
    )]
    pub bounty_vault: Account<'info, BountyVault>,

    /// CHECK: Pure SOL PDA vault controlled strictly via PDA signer seeds.
    #[account(
        mut,
        seeds = [b"escrow_vault", bounty_vault.key().as_ref()],
        bump = bounty_vault.vault_bump
    )]
    pub escrow_sol_vault: SystemAccount<'info>,

    #[account(
        mut,
        has_one = researcher @ AegisError::ResearcherMismatch,
        constraint = finding_report.bounty == bounty_vault.key() @ AegisError::BountyMismatch,
        seeds = [b"finding", bounty_vault.key().as_ref(), researcher.key().as_ref(), &finding_report.finding_id.to_le_bytes()],
        bump = finding_report.bump
    )]
    pub finding_report: Account<'info, FindingReport>,

    #[account(
        mut,
        constraint = dispute_ticket.finding == finding_report.key() @ AegisError::InvalidDisputeState,
        seeds = [b"dispute", finding_report.key().as_ref()],
        bump = dispute_ticket.bump
    )]
    pub dispute_ticket: Account<'info, DisputeTicket>,

    #[account(
        mut,
        has_one = researcher @ AegisError::ResearcherMismatch,
        seeds = [b"whitehat", researcher.key().as_ref()],
        bump = whitehat_profile.bump
    )]
    pub whitehat_profile: Account<'info, WhitehatProfile>,

    /// CHECK: Verified via `has_one = researcher` on both `finding_report` and `whitehat_profile`.
    #[account(mut)]
    pub researcher: SystemAccount<'info>,

    /// CHECK: Verified by canonical PDA seeds `[b"arb_config"]`.
    #[account(
        seeds = [b"arb_config"],
        bump
    )]
    pub arb_config: UncheckedAccount<'info>,

    /// CHECK: Verified by exact Solana Instructions Sysvar address constraint.
    #[account(address = IX_SYSVAR_ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CloseBounty<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        mut,
        has_one = authority @ AegisError::Unauthorized,
        seeds = [b"bounty", authority.key().as_ref(), &bounty_vault.bounty_id.to_le_bytes()],
        bump = bounty_vault.bump
    )]
    pub bounty_vault: Account<'info, BountyVault>,

    /// CHECK: Pure SOL PDA vault controlled strictly via PDA signer seeds.
    #[account(
        mut,
        seeds = [b"escrow_vault", bounty_vault.key().as_ref()],
        bump = bounty_vault.vault_bump
    )]
    pub escrow_sol_vault: SystemAccount<'info>,

    /// CHECK: Verified by canonical PDA seeds `[b"cooldown", bounty_vault.key().as_ref()]`.
    #[account(
        seeds = [b"cooldown", bounty_vault.key().as_ref()],
        bump
    )]
    pub vault_cooldown: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(scan_id: u64)]
pub struct RecordAuditAttestation<'info> {
    #[account(mut)]
    pub auditor: Signer<'info>,

    #[account(
        init,
        payer = auditor,
        space = AuditAttestation::SPACE,
        seeds = [b"audit", auditor.key().as_ref(), &scan_id.to_le_bytes()],
        bump
    )]
    pub audit_attestation: Account<'info, AuditAttestation>,

    /// CHECK: Verified by exact Solana Instructions Sysvar address constraint.
    #[account(address = IX_SYSVAR_ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

// ============================================================================
// State Accounts (100% Binary-Compatible with Live v2 PDAs on Devnet!)
// ============================================================================

#[account]
pub struct BountyVault {
    pub authority: Pubkey,
    pub bounty_id: u64,
    pub target_name: String,
    pub scope_uri: String,
    pub total_deposited: u64,
    pub remaining_pool: u64,
    pub max_payout_per_finding: u64,
    pub findings_count: u32,
    pub pending_findings: u32,
    pub approved_count: u32,
    pub is_active: bool,
    pub created_at: i64,
    pub bump: u8,
    pub vault_bump: u8,
}

impl BountyVault {
    pub const SPACE: usize = 8  // discriminator
        + 32                    // authority
        + 8                     // bounty_id
        + 4 + MAX_NAME_LEN      // target_name
        + 4 + MAX_URI_LEN       // scope_uri
        + 8                     // total_deposited
        + 8                     // remaining_pool
        + 8                     // max_payout_per_finding
        + 4                     // findings_count
        + 4                     // pending_findings
        + 4                     // approved_count
        + 1                     // is_active
        + 8                     // created_at
        + 1                     // bump
        + 1;                    // vault_bump (367 bytes)
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum FindingStatus {
    Committed, // 0
    Revealed,  // 1
    Approved,  // 2
    Rejected,  // 3
    Disputed,  // 4
}

#[account]
pub struct FindingReport {
    pub bounty: Pubkey,
    pub researcher: Pubkey,
    pub finding_id: u64,
    pub commit_hash: [u8; 32],
    pub severity: u8,
    pub encrypted_report_uri: String,
    pub revealed_summary: String,
    pub status: FindingStatus,
    pub payout_lamports: u64,
    pub submitted_at: i64,
    pub resolved_at: i64,
    pub bump: u8,
}

impl FindingReport {
    pub const SPACE: usize = 8  // discriminator
        + 32                    // bounty
        + 32                    // researcher
        + 8                     // finding_id
        + 32                    // commit_hash
        + 1                     // severity
        + 4 + MAX_URI_LEN       // encrypted_report_uri
        + 4 + MAX_REVEAL_LEN    // revealed_summary
        + 1                     // status (u8 enum)
        + 8                     // payout_lamports
        + 8                     // submitted_at
        + 8                     // resolved_at
        + 1;                    // bump (507 bytes)
}

#[account]
pub struct WhitehatProfile {
    pub researcher: Pubkey,
    pub handle: String,
    pub total_submissions: u32,
    pub approved_findings: u32,
    pub total_earned_lamports: u64,
    pub reputation_score: u64,
    pub bump: u8,
}

impl WhitehatProfile {
    pub const SPACE: usize = 8  // discriminator
        + 32                    // researcher
        + 4 + MAX_HANDLE_LEN    // handle
        + 4                     // total_submissions
        + 4                     // approved_findings
        + 8                     // total_earned_lamports
        + 8                     // reputation_score
        + 1;                    // bump (93 bytes)
}

#[account]
pub struct AuditAttestation {
    pub auditor: Pubkey,
    pub scan_id: u64,
    pub target_program_id: Pubkey,
    pub source_code_hash: [u8; 32],
    pub report_hash: [u8; 32],
    pub security_score: u8,
    pub critical_count: u8,
    pub high_count: u8,
    pub x402_payment_sig: String,
    pub is_verified_oracle: bool,
    pub audited_at: i64,
    pub bump: u8,
}

impl AuditAttestation {
    pub const SPACE: usize = 8  // discriminator
        + 32                    // auditor
        + 8                     // scan_id
        + 32                    // target_program_id
        + 32                    // source_code_hash
        + 32                    // report_hash
        + 1                     // security_score
        + 1                     // critical_count
        + 1                     // high_count
        + 4 + MAX_SIG_LEN       // x402_payment_sig
        + 1                     // is_verified_oracle
        + 8                     // audited_at
        + 1;                    // bump (257 bytes)
}

#[account]
pub struct VaultCooldown {
    pub bounty: Pubkey,
    pub unlock_at: i64,
    pub last_rejected_finding: Pubkey,
    pub bump: u8,
}

impl VaultCooldown {
    pub const SPACE: usize = 8 + 32 + 8 + 32 + 1; // 81 bytes
}

#[account]
pub struct DisputeTicket {
    pub bounty: Pubkey,
    pub finding: Pubkey,
    pub researcher: Pubkey,
    pub reason_uri: String,
    pub opened_at: i64,
    pub resolved: bool,
    pub upheld: bool,
    pub awarded_lamports: u64,
    pub resolved_at: i64,
    pub bump: u8,
}

impl DisputeTicket {
    pub const SPACE: usize = 8 + 32 + 32 + 32 + (4 + MAX_URI_LEN) + 8 + 1 + 1 + 8 + 8 + 1; // 335 bytes
}

#[account]
pub struct ArbitrationConfig {
    pub authority: Pubkey,
    pub arbitrator: Pubkey,
    pub bump: u8,
}

impl ArbitrationConfig {
    pub const SPACE: usize = 8 + 32 + 32 + 1; // 73 bytes
}

// ============================================================================
// Events & Errors
// ============================================================================

#[event]
pub struct BountyCreatedEvent {
    pub bounty: Pubkey,
    pub authority: Pubkey,
    pub bounty_id: u64,
    pub target_name: String,
    pub reward_lamports: u64,
    pub timestamp: i64,
}

#[event]
pub struct BountyFundedEvent {
    pub bounty: Pubkey,
    pub funder: Pubkey,
    pub amount_lamports: u64,
    pub new_pool: u64,
}

#[event]
pub struct FindingCommittedEvent {
    pub bounty: Pubkey,
    pub finding: Pubkey,
    pub researcher: Pubkey,
    pub finding_id: u64,
    pub commit_hash: [u8; 32],
    pub severity: u8,
    pub timestamp: i64,
}

#[event]
pub struct FindingRevealedEvent {
    pub bounty: Pubkey,
    pub finding: Pubkey,
    pub researcher: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct FindingApprovedEvent {
    pub bounty: Pubkey,
    pub finding: Pubkey,
    pub researcher: Pubkey,
    pub payout_lamports: u64,
    pub reputation_score: u64,
    pub timestamp: i64,
}

#[event]
pub struct FindingRejectedEvent {
    pub bounty: Pubkey,
    pub finding: Pubkey,
    pub researcher: Pubkey,
    pub was_revealed: bool,
    pub cooldown_unlock_at: i64,
    pub timestamp: i64,
}

#[event]
pub struct DisputeRaisedEvent {
    pub bounty: Pubkey,
    pub finding: Pubkey,
    pub dispute_ticket: Pubkey,
    pub researcher: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct DisputeResolvedEvent {
    pub bounty: Pubkey,
    pub finding: Pubkey,
    pub dispute_ticket: Pubkey,
    pub researcher: Pubkey,
    pub upheld: bool,
    pub awarded_lamports: u64,
    pub timestamp: i64,
}

#[event]
pub struct BountyClosedEvent {
    pub bounty: Pubkey,
    pub authority: Pubkey,
    pub refunded_lamports: u64,
}

#[event]
pub struct AuditAttestedEvent {
    pub attestation: Pubkey,
    pub auditor: Pubkey,
    pub target_program_id: Pubkey,
    pub source_code_hash: [u8; 32],
    pub report_hash: [u8; 32],
    pub security_score: u8,
    pub critical_count: u8,
    pub high_count: u8,
    pub is_verified_oracle: bool,
    pub x402_payment_sig: String,
    pub timestamp: i64,
}

#[error_code]
pub enum AegisError {
    #[msg("Unauthorized caller for this bounty vault.")]
    Unauthorized,
    #[msg("Target name must be between 1 and 64 characters.")]
    InvalidTargetName,
    #[msg("Scope URI must be between 1 and 200 characters.")]
    InvalidScopeUri,
    #[msg("Amount must be greater than zero.")]
    ZeroAmount,
    #[msg("Deposit is below Solana's rent-exempt minimum for a SOL vault.")]
    BelowRentExemptMinimum,
    #[msg("Transfer would leave an account with non-zero dust below rent-exempt minimum.")]
    RentExemptViolation,
    #[msg("Max payout per finding must be > 0 and <= total deposit.")]
    InvalidMaxPayout,
    #[msg("This bounty vault is closed.")]
    BountyClosed,
    #[msg("Cannot close bounty vault while unresolved findings are still pending.")]
    PendingFindingsExist,
    #[msg("Anti-poaching 24h cooldown is active after rejecting a Revealed PoC; whitehat may raise arbitration.")]
    AntiPoachingCooldownActive,
    #[msg("Only cryptographically Revealed findings can be escalated to arbitration.")]
    MustRevealBeforeDispute,
    #[msg("Finding is not in a valid state for dispute or arbitration.")]
    InvalidDisputeState,
    #[msg("The 7-day dispute challenge window for this rejection has expired.")]
    DisputeWindowExpired,
    #[msg("Caller is not the authorized AEGIS arbitration oracle.")]
    UnauthorizedArbitrator,
    #[msg("Arbitrator public key cannot be default zeroes.")]
    InvalidArbitrator,
    #[msg("Severity must be 1 (Low), 2 (Medium), 3 (High), or 4 (Critical).")]
    InvalidSeverity,
    #[msg("Encrypted report URI must be between 1 and 200 characters.")]
    InvalidReportUri,
    #[msg("Researcher handle must be between 1 and 32 characters.")]
    InvalidHandle,
    #[msg("Commit hash cannot be all zeroes.")]
    InvalidCommitHash,
    #[msg("Reveal summary must be between 1 and 160 characters.")]
    InvalidRevealSummary,
    #[msg("Salt must be between 1 and 64 characters.")]
    InvalidSalt,
    #[msg("Revealed PoC + salt SHA-256 digest does not match on-chain commit_hash.")]
    CommitHashMismatch,
    #[msg("This finding has already been resolved.")]
    FindingAlreadyResolved,
    #[msg("Payout exceeds the bounty's max payout per finding.")]
    ExceedsMaxPayout,
    #[msg("Escrow vault has insufficient funds for this payout.")]
    InsufficientVaultFunds,
    #[msg("Finding does not belong to this bounty vault.")]
    BountyMismatch,
    #[msg("Researcher account does not match finding record.")]
    ResearcherMismatch,
    #[msg("Arithmetic overflow or underflow detected.")]
    ArithmeticOverflow,
    #[msg("Security score must be between 0 and 100.")]
    InvalidSecurityScore,
    #[msg("x402 payment signature must be between 1 and 96 characters.")]
    InvalidPaymentSig,
    #[msg("Invalid Solana Instructions Sysvar lookup.")]
    InvalidSysvarInstruction,
}
