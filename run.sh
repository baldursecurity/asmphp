#!/usr/bin/env bash
# run.sh — thin convenience wrapper around the Docker image.
#
#   ./run.sh -t example.com --crtsh --php-deep
#   ./run.sh -a assets.txt --all-sources
#
# Mounts (all live — host edits are reflected immediately, no rebuild):
#   * ./data        -> /data           input/output directory
#   * ./assets.txt  -> /data/assets.txt a single bind-mounted input file,
#                                       editable from the host, so `-a assets.txt`
#                                       always sees your latest edits.
# Override the assets file with:  ASSETS_FILE=/path/to/list.txt ./run.sh -a assets.txt
set -euo pipefail

IMAGE="asm-recon:latest"
DATA_DIR="$(pwd)/data"
ASSETS_FILE="${ASSETS_FILE:-$(pwd)/assets.txt}"
EXTRA_DOCKER_ARGS="${EXTRA_DOCKER_ARGS:-}"

mkdir -p "$DATA_DIR"

# Build the image on first run (or if it's missing).
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[*] Building $IMAGE (first run only)..." >&2
    docker build -t "$IMAGE" "$(dirname "$0")"
fi

# Base mounts. Bind-mount the assets file directly so edits on the host take
# effect on the very next run with no rebuild and no copy to keep in sync.
DOCKER_ARGS=( --rm -it -v "$DATA_DIR:/data" )
if [ -f "$ASSETS_FILE" ]; then
    DOCKER_ARGS+=( -v "$ASSETS_FILE:/data/assets.txt:ro" )
    echo "[*] Mounting $ASSETS_FILE -> /data/assets.txt (live, read it with: -a assets.txt)" >&2
fi

exec docker run "${DOCKER_ARGS[@]}" \
    ${EXTRA_DOCKER_ARGS} \
    "$IMAGE" "$@"
