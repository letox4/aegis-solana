export interface ChainOption {
  id: string;
  lifiId: string;
  hexChainId: string;
  name: string;
  symbol: string;
  tokenSymbol: string;
  tokenAddress: string;
  decimals: number;
  explorerTxPrefix: string;
  sampleAddress: string;
  accent: string;
}

export const LIFI_SOLANA_CHAIN_ID = "SOL"; // LI.FI Solana Mainnet ID (1151111081099710)
export const SOL_NATIVE_ADDRESS = "11111111111111111111111111111111";
export const SOL_USDC_ADDRESS = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

export const EVM_CHAINS: ChainOption[] = [
  {
    id: "ARB",
    lifiId: "42161",
    hexChainId: "0xa4b1",
    name: "Arbitrum One",
    symbol: "ARB",
    tokenSymbol: "USDC",
    tokenAddress: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
    decimals: 6,
    explorerTxPrefix: "https://arbiscan.io/tx/",
    sampleAddress: "0x552008c0f6870c2f77e5cC1d2eb9bdff03e30Ea0",
    accent: "#28A0F0",
  },
  {
    id: "BASE",
    lifiId: "8453",
    hexChainId: "0x2105",
    name: "Base",
    symbol: "BASE",
    tokenSymbol: "USDC",
    tokenAddress: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    decimals: 6,
    explorerTxPrefix: "https://basescan.org/tx/",
    sampleAddress: "0x552008c0f6870c2f77e5cC1d2eb9bdff03e30Ea0",
    accent: "#0052FF",
  },
  {
    id: "POL",
    lifiId: "137",
    hexChainId: "0x89",
    name: "Polygon",
    symbol: "POL",
    tokenSymbol: "USDC",
    tokenAddress: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
    decimals: 6,
    explorerTxPrefix: "https://polygonscan.com/tx/",
    sampleAddress: "0x552008c0f6870c2f77e5cC1d2eb9bdff03e30Ea0",
    accent: "#8247E5",
  },
  {
    id: "ETH",
    lifiId: "1",
    hexChainId: "0x1",
    name: "Ethereum",
    symbol: "ETH",
    tokenSymbol: "USDC",
    tokenAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    decimals: 6,
    explorerTxPrefix: "https://etherscan.io/tx/",
    sampleAddress: "0x552008c0f6870c2f77e5cC1d2eb9bdff03e30Ea0",
    accent: "#627EEA",
  },
];

export const SOLANA_TOKENS = [
  {
    symbol: "SOL",
    name: "Native Solana",
    address: SOL_NATIVE_ADDRESS,
    decimals: 9,
  },
  {
    symbol: "USDC",
    name: "USD Coin (Solana SPL)",
    address: SOL_USDC_ADDRESS,
    decimals: 6,
  },
];

export interface LifiTransactionRequest {
  from?: string;
  to?: string;
  chainId?: number;
  data?: string;
  value?: string;
  gasPrice?: string;
  gasLimit?: string;
}

export interface LifiNormalizedQuote {
  id: string;
  tool: string;
  toolName: string;
  toolLogoURI?: string;
  fromChain: string;
  toChain: string;
  fromChainId: string;
  toChainId: string;
  fromTokenSymbol: string;
  toTokenSymbol: string;
  fromAmountFormatted: string;
  toAmountFormatted: string;
  toAmountMinFormatted: string;
  fromAmountUSD: string;
  toAmountUSD: string;
  executionDurationSec: number;
  gasCostUSD: string;
  feeCostUSD: string;
  approvalAddress?: string;
  steps: Array<{
    type: string;
    tool: string;
    toolName: string;
    fromChainId: number | string;
    toChainId: number | string;
  }>;
  hasTransactionRequest: boolean;
  transactionRequest?: LifiTransactionRequest;
}

export interface LifiStatusResult {
  status: "NOT_FOUND" | "INVALID" | "PENDING" | "DONE" | "FAILED";
  substatus?: string;
  substatusMessage?: string;
  sendingTxLink?: string;
  receivingTxLink?: string;
  lifiExplorerLink?: string;
}

export function formatTokenUnits(raw: string, decimals: number): string {
  if (!raw || raw === "0") return "0";
  const padded = raw.padStart(decimals + 1, "0");
  const intPart = padded.slice(0, padded.length - decimals);
  const fracPart = padded
    .slice(padded.length - decimals)
    .slice(0, 6)
    .replace(/0+$/, "");
  return fracPart ? `${intPart}.${fracPart}` : intPart;
}

export function toBaseUnits(humanAmount: string, decimals: number): string {
  const clean = humanAmount.replace(/[^0-9.]/g, "");
  if (!clean) return "0";
  const [intPart, fracPart = ""] = clean.split(".");
  const normalizedFrac = fracPart.slice(0, decimals).padEnd(decimals, "0");
  const combined = `${intPart || "0"}${normalizedFrac}`.replace(/^0+/, "");
  return combined || "0";
}
