"use client";

import React, { useMemo } from "react";
import {
  ConnectionProvider as SolanaConnectionProvider,
  WalletProvider as SolanaWalletAdapterProvider,
} from "@solana/wallet-adapter-react";
import { WalletModalProvider as SolanaWalletModalProvider } from "@solana/wallet-adapter-react-ui";
import "@solana/wallet-adapter-react-ui/styles.css";

const RPC_ENDPOINT =
  process.env.NEXT_PUBLIC_SOLANA_RPC_URL || "https://api.devnet.solana.com";

// Bridge React 18 / 19 @types/react JSX return type compatibility for wallet-adapter FC wrappers
const ConnectionProvider = SolanaConnectionProvider as React.ComponentType<any>;
const WalletProvider = SolanaWalletAdapterProvider as React.ComponentType<any>;
const WalletModalProvider = SolanaWalletModalProvider as React.ComponentType<any>;

/**
 * Modern Phantom, Solflare, Backpack, and Coinbase Wallet all auto-register via the
 * Solana Wallet Standard — no legacy adapter bloat required.
 */
export function SolanaWalletProvider({ children }: { children: React.ReactNode }) {
  const wallets = useMemo(() => [], []);

  return (
    <ConnectionProvider endpoint={RPC_ENDPOINT}>
      <WalletProvider wallets={wallets} autoConnect>
        <WalletModalProvider>{children}</WalletModalProvider>
      </WalletProvider>
    </ConnectionProvider>
  );
}
