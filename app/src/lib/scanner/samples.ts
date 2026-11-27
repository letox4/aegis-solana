export interface ContractSample {
  id: string;
  label: string;
  badge: string;
  description: string;
  programId: string;
  code: string;
}

export const CONTRACT_SAMPLES: ContractSample[] = [
  {
    id: "vulnerable-defi-vault",
    label: "Vulnerable DeFi Vault (6 Critical/High Bugs)",
    badge: "VULNERABLE",
    description:
      "Deliberately vulnerable Solana Anchor vault demonstrating missing signer check, unchecked arithmetic, arbitrary CPI, account revival, and unwrap panic.",
    programId: "Vu1nVau1t1111111111111111111111111111111111",
    code: `use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;

declare_id!("Vu1nVau1t1111111111111111111111111111111111");

#[program]
pub mod vulnerable_defi_vault {
    use super::*;

    pub fn withdraw_treasury(ctx: Context<WithdrawTreasury>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        // BUG 1: Unchecked arithmetic (underflow drains vault!)
        vault.balance = vault.balance - amount;

        // BUG 2: Division before multiplication (precision loss)
        let fee = (amount / 100) * 3;
        let payout = amount - fee;

        // BUG 3: Unchecked unwrap panic
        let _clock = Clock::get().unwrap();

        // BUG 4: Arbitrary CPI without verifying target program ID
        invoke(
            &anchor_lang::solana_program::system_instruction::transfer(
                ctx.accounts.vault.to_account_info().key,
                ctx.accounts.recipient.key,
                payout,
            ),
            &[
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.recipient.to_account_info(),
                ctx.accounts.token_or_sys_program.to_account_info(),
            ],
        )?;
        Ok(())
    }

    pub fn close_vault_unsafe(ctx: Context<CloseVaultUnsafe>) -> Result<()> {
        // BUG 5: Manual lamport drain without clearing discriminator (Revival attack)
        let lamports = **ctx.accounts.vault.to_account_info().lamports.borrow();
        **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? = 0;
        **ctx.accounts.authority.try_borrow_mut_lamports()? += lamports;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct WithdrawTreasury<'info> {
    // BUG 6: Missing Signer check on authority!
    pub authority: AccountInfo<'info>,
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
    pub recipient: AccountInfo<'info>,
    pub token_or_sys_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CloseVaultUnsafe<'info> {
    pub authority: Signer<'info>,
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
}

#[account]
pub struct VaultState {
    pub authority: Pubkey,
    pub balance: u64,
}`,
  },
  {
    id: "aegis402-hardened",
    label: "AEGIS Hardened Escrow Contract (Self-Audit)",
    badge: "HARDENED",
    description:
      "Production snippet from AEGIS's own Anchor program using Signer constraints, has_one, canonical PDA bumps, checked arithmetic, and typed SystemProgram CPI.",
    programId: "8AaU3VSHXHyKcVTe9JCA67oRR5djpjfAUgcM1cCtpe7p",
    code: `use anchor_lang::prelude::*;
use anchor_lang::system_program;

#[program]
pub mod aegis_hardened_vault {
    use super::*;

    pub fn approve_and_payout(
        ctx: Context<ApproveAndPayout>,
        payout_lamports: u64,
    ) -> Result<()> {
        let bounty = &mut ctx.accounts.bounty_vault;
        let finding = &mut ctx.accounts.finding_report;

        require!(payout_lamports > 0, AegisError::ZeroAmount);
        require!(payout_lamports <= bounty.remaining_pool, AegisError::InsufficientVaultFunds);

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
        finding.payout_lamports = payout_lamports;

        Ok(())
    }
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
        constraint = finding_report.bounty == bounty_vault.key()
    )]
    pub finding_report: Account<'info, FindingReport>,

    #[account(mut)]
    pub researcher: SystemAccount<'info>,
    pub system_program: Program<'info, System>,
}`,
  },
];
