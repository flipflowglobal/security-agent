#!/usr/bin/env bash
# setup.sh — one-time setup for Security-Agent.
# Makes `sa` available globally from any directory.
#
# Usage: bash setup.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_LINK="$HOME/.local/bin/sa"

echo "Security-Agent setup"
echo "===================="
echo "  Repo:    $REPO_DIR"
echo "  Link:    $BIN_LINK"
echo ""

# Ensure ~/.local/bin exists
mkdir -p "$HOME/.local/bin"

# Create symlink (force if already exists)
ln -sf "$REPO_DIR/sa" "$BIN_LINK"
chmod +x "$REPO_DIR/sa"

echo "  Linked $BIN_LINK -> $REPO_DIR/sa"

# Add to PATH in .bashrc if not already there
BASHRC="$HOME/.bashrc"
PATH_MARKER="# Security-Agent PATH"
if ! grep -qF "$PATH_MARKER" "$BASHRC" 2>/dev/null; then
  echo "" >> "$BASHRC"
  echo "$PATH_MARKER" >> "$BASHRC"
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$BASHRC"
  echo "  Added PATH entry to $BASHRC"
else
  echo "  PATH entry already in $BASHRC"
fi

# Build the binary if not present
if [ ! -f "$REPO_DIR/target/release/security-agent" ]; then
  echo ""
  echo "Building release binary..."
  cargo build --release --manifest-path "$REPO_DIR/Cargo.toml"
fi

echo ""
echo "Setup complete."
echo ""
echo "  Run now:   source ~/.bashrc && sa --about"
echo "  Or new shell: sa --about"
echo ""
echo "Quick reference:"
echo "  sa                        # status (default)"
echo "  sa --about                # mission & roadmap"
echo "  sa --tui                  # interactive terminal UI"
echo "  sa --list-tools           # all cataloged tools"
echo "  sa --list-skills          # all embedded skills"
echo "  sa --ask 'what tools do you have'  # plain English"
