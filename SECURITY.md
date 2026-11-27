# Security Policy — AEGIS Protocol

AEGIS is an offensive-security and zero-trust bug bounty protocol built for Solana. Security of both our on-chain Anchor program and our off-chain x402 verification pipeline is a first-class invariant.

## Scope

| Component | Location | Deployment / Cluster |
| :--- | :--- | :--- |
| Anchor Smart Contract (v3.0) | [`programs/aegis402/src/lib.rs`](programs/aegis402/src/lib.rs) | Solana Devnet: `8AaU3VSHXHyKcVTe9JCA67oRR5djpjfAUgcM1cCtpe7p` |
| On-Chain Anchor IDL | [`idl/aegis402.json`](idl/aegis402.json) | `4eqNqueh9JDD7j614TynsRPCtXSBRvzCs4XVdHXbjNa9` |
| x402 V2 Payment & Oracle API | [`app/src/lib/x402/protocol.ts`](app/src/lib/x402/protocol.ts) | Next.js API Routes (`/api/x402/*`) |
| SolSec Static Engine v3.0 | [`app/src/lib/scanner/solanaRules.ts`](app/src/lib/scanner/solanaRules.ts) | Client / Server Scanner |
| Client-Side PoC Vault | [`app/src/lib/crypto/pocVault.ts`](app/src/lib/crypto/pocVault.ts) | WebCrypto `AES-256-GCM` |

## Reporting a Vulnerability

Please **do not** open public GitHub issues for exploitable smart contract, cryptographic, or SSRF vulnerabilities.

1. **On-Chain Zero-Trust Disclosure (Preferred):** Submit a SHA-256 commit (`submit_finding_commit`) with a client-side `AES-256-GCM` encrypted PoC directly into the live AEGIS Devnet Bounty Vault (`8AaU3VSHXHyKcVTe9JCA67oRR5djpjfAUgcM1cCtpe7p`).
2. **GitHub Private Vulnerability Reporting:** Use the **Security → Advisories → Report a vulnerability** tab in this repository.

## Core Security Invariants Verified by Test Suite (`17/17` Passing)

- **Escrow Rent-Exemption & Anti-Rug-Pull:** `close_bounty` is blocked whenever `pending_findings > 0` or a 24-hour `VaultCooldown` is active following rejection of a `Revealed` finding.
- **Anti-Poaching Arbitration:** Researchers have a 7-day dispute window (`raise_dispute`) to freeze escrow and trigger independent `Ed25519Program` Oracle arbitration (`resolve_dispute`).
- **Front-Run-Proof Cluster Initialization:** `initialize_arbitrator` validates `ProgramData.upgrade_authority` under `BPFLoaderUpgradeable`.
- **Anti-Sniping x402 Verification:** Paid scans require an exact SPL Memo binding (`aegis:<sha256(code)[0..16]>`) and atomic anti-replay signature locks.
- **SSRF & Traversal Defense:** `/api/scanner/github` restricts fetches strictly to public `github.com/<owner>/<repo>` URLs and rejects path traversal (`..`).
