#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/share/solana/install/active_release/bin:$HOME/.cargo/bin:$HOME/.avm/bin:$PATH"

echo ">>> [1/4] Checking Rust..."
if [ ! -f "$HOME/.cargo/env" ]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
# shellcheck source=/dev/null
source "$HOME/.cargo/env"
rustc --version
cargo --version

echo ">>> [2/4] Checking Solana CLI (Agave)..."
if [ ! -x "$HOME/.local/share/solana/install/active_release/bin/solana" ]; then
  sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
fi
export PATH="$HOME/.local/share/solana/install/active_release/bin:$HOME/.cargo/bin:$HOME/.avm/bin:$PATH"
if ! grep -q "solana/install/active_release/bin" "$HOME/.bashrc" 2>/dev/null; then
  echo 'export PATH="$HOME/.local/share/solana/install/active_release/bin:$HOME/.cargo/bin:$HOME/.avm/bin:$PATH"' >> "$HOME/.bashrc"
fi
solana --version

echo ">>> [3/4] Checking AVM & Anchor CLI..."
if ! command -v avm >/dev/null 2>&1; then
  cargo install --git https://github.com/coral-xyz/anchor avm --locked --force
fi
avm --version
if ! command -v anchor >/dev/null 2>&1; then
  avm install latest
  avm use latest
fi
anchor --version

echo ">>> [4/4] Setting up Solana Devnet keypair..."
solana config set --url devnet
if [ ! -f "$HOME/.config/solana/id.json" ]; then
  solana-keygen new --no-bip39-passphrase --silent --outfile "$HOME/.config/solana/id.json"
fi
echo "Wallet address: $(solana address)"
echo "=== WSL SOLANA TOOLCHAIN COMPLETE ==="
