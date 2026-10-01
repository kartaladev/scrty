#!/usr/bin/env bash
# Setup script for a Claude Code cloud environment working on scrty.
#
# Paste it into the environment's "Setup script" field on claude.ai/code, or run
# it there as `bash .claude/cloud-setup.sh`. It is idempotent: re-running it
# skips what is already in place.
#
# It installs:
#   - the official marketplace and the plugins .claude/settings.json enables
#     (superpowers, gopls-lsp, security-guidance);
#   - the samber marketplace (samber/cc) and its Go plugin, cc-skills-golang;
#   - gopls into /usr/local/bin, which the gopls-lsp plugin drives;
#   - the OpenSpec CLI (@fission-ai/openspec).
set -euo pipefail

log() { printf '==> %s\n' "$*"; }

# Add a marketplace unless one of that name is already configured.
add_marketplace() {
  local name=$1 source=$2
  if claude plugin marketplace list 2>/dev/null | grep -q "❯ ${name}\$"; then
    log "marketplace ${name} already configured; updating"
    claude plugin marketplace update "${name}" || true
  else
    log "adding marketplace ${name} (${source})"
    claude plugin marketplace add "${source}"
  fi
}

install_plugin() {
  log "installing plugin $1"
  claude plugin install "$1" --scope user
}

# --- Claude Code plugins ---------------------------------------------------

add_marketplace claude-plugins-official anthropics/claude-plugins-official
add_marketplace samber samber/cc

for plugin in \
  superpowers@claude-plugins-official \
  gopls-lsp@claude-plugins-official \
  security-guidance@claude-plugins-official \
  cc-skills-golang@samber; do
  install_plugin "${plugin}"
done

# --- Go tooling ------------------------------------------------------------

# Go is pre-installed in the cloud image, at a version the docs do not state.
# go.mod requires Go 1.27; with GOTOOLCHAIN=auto an older go downloads it from
# proxy.golang.org, which the default "Trusted" network level allows. An export
# here lasts only for this script, so set GOTOOLCHAIN=auto in the environment's
# environment variables as well, for the sessions themselves.
export GOTOOLCHAIN=auto
if command -v go >/dev/null 2>&1; then
  log "go found: $(go version)"
  # Installed into /usr/local/bin (the script runs as root), which is already
  # on every session's PATH, so nothing needs to persist a PATH change.
  log "installing gopls"
  GOBIN=/usr/local/bin go install golang.org/x/tools/gopls@latest
else
  log "go not found; skipping gopls (the gopls-lsp plugin needs it)"
fi

# --- OpenSpec --------------------------------------------------------------

log "installing the OpenSpec CLI"
npm install -g @fission-ai/openspec@latest

log "done: $(claude plugin list 2>/dev/null | grep -c '@' || true) plugins listed; openspec $(openspec --version)"
