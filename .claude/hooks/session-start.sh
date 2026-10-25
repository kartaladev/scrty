#!/usr/bin/env bash
# SessionStart hook: prepares a Claude Code cloud session for scrty. It is the
# project's only setup script. It runs synchronously, so the session starts only
# once everything below is in place, and it is idempotent: re-running it skips
# what is already installed. Local sessions skip it.
#
# It installs, most critical first:
#   - Go (GO_VERSION below) into /usr/local/go, checksum-verified, replacing an
#     older go;
#   - gopls into /usr/local/bin, which the gopls-lsp plugin drives;
#   - the pinned tools of tools/go.mod into ./.bin (`make tools`);
#   - the OpenSpec CLI (@fission-ai/openspec);
#   - the official marketplace and the plugins .claude/settings.json enables
#     (superpowers, gopls-lsp, security-guidance);
#   - the samber marketplace (samber/cc) and its Go plugin, cc-skills-golang.
#
# Progress goes to stderr; the one-line summary on stdout reaches the session.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

log() { printf '==> %s\n' "$*" >&2; }

REPO_DIR=${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}

# --- Go --------------------------------------------------------------------

# go.mod requires Go 1.27. The cloud image ships an older go; GOTOOLCHAIN=auto
# would fetch 1.27 on the fly, but only inside the module. Install a pinned
# release instead, so `go` is the same everywhere. Bump the version and both
# checksums together, from https://go.dev/dl/?mode=json&include=all.
GO_VERSION=1.27.3
declare -A GO_SHA256=(
  [amd64]=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40
  [arm64]=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49
)

install_go() {
  local arch
  case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) log "unsupported architecture $(uname -m); skipping go install"; return 0 ;;
  esac

  if [ -x /usr/local/go/bin/go ] &&
    [ "$(GOTOOLCHAIN=local /usr/local/go/bin/go env GOVERSION)" = "go${GO_VERSION}" ]; then
    log "go${GO_VERSION} already installed"
    return 0
  fi

  local tmp archive="go${GO_VERSION}.linux-${arch}.tar.gz"
  tmp=$(mktemp -d)
  log "installing go${GO_VERSION} (${arch})"
  curl -fsSLo "${tmp}/${archive}" "https://go.dev/dl/${archive}"
  echo "${GO_SHA256[$arch]}  ${tmp}/${archive}" | sha256sum -c - >&2
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "${tmp}/${archive}"
  rm -rf "${tmp}"
}

install_go
export PATH="/usr/local/go/bin:${PATH}"
log "go: $(go version)"

# Installed into /usr/local/bin (the script runs as root), which is already on
# every session's PATH, so nothing needs to persist a PATH change.
log "installing gopls"
GOBIN=/usr/local/bin go install golang.org/x/tools/gopls@latest >&2

log "installing the pinned Go tools (make tools)"
make -C "${REPO_DIR}" --no-print-directory tools >&2

# --- OpenSpec --------------------------------------------------------------

if command -v openspec >/dev/null 2>&1; then
  log "OpenSpec CLI already installed: $(openspec --version)"
else
  log "installing the OpenSpec CLI"
  npm install -g @fission-ai/openspec@latest >&2
fi

# --- Claude Code plugins ---------------------------------------------------

# Add a marketplace unless one of that name is already configured. The list
# prints each name on its own line after a marker (`>` or `❯`).
add_marketplace() {
  local name=$1 source=$2
  if claude plugin marketplace list 2>/dev/null | grep -qE "^[[:space:]]*(>|❯) ${name}[[:space:]]*\$"; then
    log "marketplace ${name} already configured; updating"
    claude plugin marketplace update "${name}" >&2 || true
  else
    log "adding marketplace ${name} (${source})"
    claude plugin marketplace add "${source}" >&2
  fi
}

install_plugin() {
  log "installing plugin $1"
  claude plugin install "$1" --scope user >&2
}

add_marketplace claude-plugins-official anthropics/claude-plugins-official
add_marketplace samber samber/cc

for plugin in \
  superpowers@claude-plugins-official \
  gopls-lsp@claude-plugins-official \
  security-guidance@claude-plugins-official \
  cc-skills-golang@samber; do
  install_plugin "${plugin}"
done

# --- Docker ----------------------------------------------------------------

# The testcontainers suites under test/ need a Docker daemon. Report, don't fail:
# everything else works without it.
if docker info >/dev/null 2>&1; then
  docker_state="available"
else
  docker_state="unavailable (testcontainers suites under test/ will not run)"
fi

printf 'scrty setup done: %s, %s, openspec %s, Docker %s\n' \
  "$(go version | cut -d' ' -f3)" "$(gopls version | head -1 | cut -d' ' -f2)" \
  "$(openspec --version)" "${docker_state}"
