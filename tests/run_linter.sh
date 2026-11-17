#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LINTER_DIR="$SCRIPT_DIR/webext-linter"

UPDATE_LINTER=false
KEEP_REVIEW=false
LINTER_ARGS=()

for arg in "$@"; do
    case "$arg" in
        --update)
            UPDATE_LINTER=true
            ;;
        --keep-review|--no-clean)
            KEEP_REVIEW=true
            ;;
        *)
            LINTER_ARGS+=("$arg")
            ;;
    esac
done

if [ ! -d "$LINTER_DIR" ]; then
    echo "Cloning thunderbird/webext-linter into $LINTER_DIR..."
    git clone --depth 1 https://github.com/thunderbird/webext-linter.git "$LINTER_DIR"
elif [ "$UPDATE_LINTER" = true ]; then
    echo "Updating thunderbird/webext-linter..."
    git -C "$LINTER_DIR" pull --ff-only
fi

if [ ! -d "$LINTER_DIR/node_modules" ]; then
    echo "Installing dependencies in $LINTER_DIR..."
    npm --prefix "$LINTER_DIR" install
fi

cd "$ROOT_DIR"
./pack.sh

cd "$SCRIPT_DIR"
cleanup() {
    if [ "$KEEP_REVIEW" = false ]; then
        rm -rf "$SCRIPT_DIR"/xpi-review-* "$LINTER_DIR"/xpi-review-* "$ROOT_DIR"/xpi-review-*
    fi
}
trap cleanup EXIT

echo "Running Thunderbird webext-linter on ../spam.shield.xpi..."
node "$LINTER_DIR/verify.js" "$ROOT_DIR/spam.shield.xpi" "${LINTER_ARGS[@]}"
