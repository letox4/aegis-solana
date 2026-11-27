import type { Metadata } from "next";
import { Archivo, Instrument_Sans, Fragment_Mono } from "next/font/google";
import "./globals.css";
import { SolanaWalletProvider } from "@/components/WalletProvider";

const archivo = Archivo({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-display",
});

const instrumentSans = Instrument_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-sans",
});

const fragmentMono = Fragment_Mono({
  subsets: ["latin"],
  weight: ["400"],
  variable: "--font-mono",
});

export const metadata: Metadata = {
  title: "AEGIS — On-Chain Solana Security",
  description:
    "Commit-reveal bug bounties, x402 contract audits, and cross-chain settlement on Solana.",
  icons: {
    icon: "/aegis-mark.svg",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      className={`${archivo.variable} ${instrumentSans.variable} ${fragmentMono.variable} dark`}
    >
      <body className="font-sans antialiased">
        <SolanaWalletProvider>{children}</SolanaWalletProvider>
      </body>
    </html>
  );
}
