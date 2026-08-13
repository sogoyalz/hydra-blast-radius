#!/usr/bin/env bash
# One-command setup: starts HydraDB, loads a real demo graph, serves the UI.
#
#   ./setup.sh
#
# Idempotent — safe to re-run. Re-running reuses a healthy container and skips
# ingestion if the graph is already loaded. Use ./setup.sh --fresh to wipe the
# database and start over.
set -euo pipefail

# Run from the repo root regardless of where the script was invoked from, so
# the cwd-relative `node src/...` calls below and the script-relative data dir
# always agree. Without this, running e.g. `./hack-hydra/setup.sh` from a
# parent directory would ingest into a graph the server never reads.
cd "$(dirname "${BASH_SOURCE[0]}")"

CONTAINER=hydradb
PORT=${PORT:-8787}
DATA_DIR="$PWD/hydradb-data"
TOKEN='local-development-token-32-bytes'
FRESH=0
[[ "${1:-}" == "--fresh" ]] && FRESH=1

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
fail() { printf '\n\033[31mERROR: %s\033[0m\n' "$1" >&2; exit 1; }

# ---------------------------------------------------------------- prereqs
command -v docker >/dev/null || fail "docker not found. Install Docker Desktop, or on macOS: brew install colima docker && colima start"
command -v node   >/dev/null || fail "node not found. Node 18+ is required (it supplies the built-in fetch this project uses)."

node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 18 ? 0 : 1)' \
  || fail "Node 18+ required; found $(node --version). Older versions lack global fetch."

if ! docker info >/dev/null 2>&1; then
  fail "Docker is installed but no daemon is running.
       Docker Desktop: open it and wait for it to start.
       Colima:         colima start"
fi

# The published image is amd64-only; Apple Silicon needs explicit emulation.
# Expanded below as ${PLATFORM_ARG[@]+"${PLATFORM_ARG[@]}"} rather than a bare
# "${PLATFORM_ARG[@]}" because the latter is an "unbound variable" error under
# `set -u` in bash 3.2 (the /bin/bash that ships on macOS) whenever the array
# is empty — which is exactly the non-arm64 path.
PLATFORM_ARG=()
if [[ "$(uname -m)" == "arm64" || "$(uname -m)" == "aarch64" ]]; then
  PLATFORM_ARG=(--platform linux/amd64)
fi

# ---------------------------------------------------------------- database
if [[ $FRESH -eq 1 ]]; then
  step "Wiping existing database (--fresh)"
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$DATA_DIR/store" "$DATA_DIR/cache"
fi

# LOCAL_PATH must already exist; graph-node will not create it.
mkdir -p "$DATA_DIR/store" "$DATA_DIR/cache"
printf '%s\n' "$TOKEN" > "$DATA_DIR/auth-token"

if docker ps --filter "name=^${CONTAINER}$" --format '{{.Names}}' | grep -q "$CONTAINER"; then
  step "HydraDB already running — reusing it"
else
  step "Starting HydraDB"
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$CONTAINER" ${PLATFORM_ARG[@]+"${PLATFORM_ARG[@]}"} \
    --user "$(id -u):$(id -g)" \
    -p 7687:7687 -p 8443:8443 -p 9090:9090 \
    -v "$DATA_DIR:/data" \
    -e CLOUD_PROVIDER=local \
    -e LOCAL_PATH=/data/store \
    -e GRAPH_NAMESPACE=default \
    -e GRAPH_ID=default \
    -e GRAPH_CELL_ID=cell-0 \
    -e GRAPH_CELLS=cell-0 \
    -e GRAPH_NODE_ID=node-0 \
    -e GRAPH_DATA_CACHE_DIR=/data/cache \
    -e GRAPH_AUTH_TOKEN_FILE=/data/auth-token \
    -e GRAPH_ALLOW_PLAINTEXT=true \
    -e RUST_MIN_STACK=33554432 \
    ghcr.io/hydra-db/hydradb:latest >/dev/null
fi

step "Waiting for HydraDB to accept queries"
for i in $(seq 1 60); do
  if curl -fsS -m 2 http://127.0.0.1:9090/readyz >/dev/null 2>&1; then
    echo "ready after ${i}s"
    break
  fi
  # Fail fast if the container already died rather than waiting out the full
  # timeout on a process that is never coming back. The common cause is the
  # bind mount: the container writes its store as the host user, so if the
  # repo sits on a path the Docker VM shares read-only or as root (some
  # /tmp locations under Colima, or a directory outside Docker Desktop's
  # File Sharing list), graph-node exits immediately with EACCES.
  if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" == "false" ]]; then
    docker logs --tail 30 "$CONTAINER" >&2 || true
    if docker logs "$CONTAINER" 2>&1 | grep -qi "permission denied"; then
      fail "HydraDB could not write to $DATA_DIR (permission denied, logs above).
       The container writes as your user, so the repo must live on a path your
       Docker VM shares writably — a directory under your home folder is the
       safe choice. Re-clone there and re-run, or add this path to Docker
       Desktop's File Sharing settings."
    fi
    fail "HydraDB exited during startup (logs above)."
  fi
  if [[ $i -eq 60 ]]; then
    docker logs --tail 30 "$CONTAINER" >&2 || true
    fail "HydraDB did not become ready in 60s (logs above)."
  fi
  sleep 1
done

# ---------------------------------------------------------------- data
ALREADY=$(node -e '
import("./src/hydra.js").then(async ({ runQuery }) => {
  try {
    const rows = await runQuery("MATCH (p:Package) RETURN DISTINCT p.name AS name");
    console.log(rows.length);
  } catch { console.log(0); }
}).catch(() => console.log(0));
' 2>/dev/null || echo 0)

if [[ "${ALREADY:-0}" -gt 20 ]]; then
  step "Graph already loaded (${ALREADY} packages) — skipping ingestion"
else
  step "Ingesting a real npm dependency graph (this hits the public npm registry)"
  # No `| grep || true` here: piping into a filter discards ingest's exit code,
  # so a total failure (npm unreachable, every write rejected) would slip past
  # and the script would cheerfully serve an empty graph. Run it directly so a
  # non-zero exit trips `set -e` and stops with a real error.
  node src/ingest.js express --depth=4 --max-nodes=250
  node src/ingest.js webpack --depth=3 --max-nodes=150

  LOADED=$(node -e '
  import("./src/hydra.js").then(async ({ runQuery }) => {
    const rows = await runQuery("MATCH (p:Package) RETURN DISTINCT p.name AS name");
    console.log(rows.length);
  }).catch(() => { console.log(0); });
  ' 2>/dev/null || echo 0)
  if [[ "${LOADED:-0}" -lt 20 ]]; then
    fail "Ingestion finished but the graph has only ${LOADED} packages — something went wrong (npm unreachable, or HydraDB rejected the writes). Not starting the server over an empty graph."
  fi
  step "Ingested ${LOADED} packages"
fi

# ---------------------------------------------------------------- serve
step "Starting the demo server"
cat <<EOF

  Setup complete. Open:  http://127.0.0.1:${PORT}

  Things worth trying:
    body-parser   1 package exposed via dependencies, ~36 via shared publish
                  rights — the gap a dependency-only scanner cannot see
    qs            a package with 7 real GHSA advisories, reached through the
                  genuine express -> body-parser -> qs chain
    debug         a deeper multi-hop blast radius

  From the command line instead:
    node src/blastRadius.js qs
    node src/sharedMaintainers.js body-parser
    node src/typosquat.js
    node src/eval.js koa --depth=3 --max-nodes=200   # run after ./setup.sh --fresh

  Ctrl-C stops the server (HydraDB keeps running; 'docker rm -f hydradb' stops it).

EOF

exec node src/server.js --port="$PORT"
