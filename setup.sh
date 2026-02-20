#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "  dir: $DIR"
echo ""

check_cmd() {
    if ! command -v "$1" &>/dev/null; then
        echo "[!] $1 not found. install it first."
        exit 1
    fi
}

check_cmd g++
check_cmd python3
echo "[ok] g++ and python3 found"

echo ""
echo "--- building libpvac (HFHE + ZK lib) ---"
cd "$DIR/pvac"
make clean 2>/dev/null || true
make
echo "[ok] libpvac built"

UNAME_S=$(uname -s)
if [ "$UNAME_S" = "Darwin" ]; then
    LIB="$DIR/pvac/build/libpvac.dylib"
else
    LIB="$DIR/pvac/build/libpvac.so"
fi

if [ ! -f "$LIB" ]; then
    echo "[!] build failed — $LIB not found"
    exit 1
fi
echo "[ok] $LIB"

echo ""
echo "--- python dependencies ---"

if [ ! -d "$DIR/venv" ]; then
    echo "creating venv..."
    python3 -m venv "$DIR/venv" 2>/dev/null || true
fi

if [ -f "$DIR/venv/bin/pip" ]; then
    echo "installing in venv..."
    "$DIR/venv/bin/pip" install --quiet pynacl cryptography aiohttp
    PYTHON="$DIR/venv/bin/python3"
    echo "[ok] venv deps installed"
else
    echo "venv not available, installing system-wide..."
    pip3 install pynacl cryptography aiohttp 2>/dev/null || \
    pip3 install pynacl cryptography aiohttp --break-system-packages 2>/dev/null || \
    echo "[!] pip install failed — install manually: pip3 install pynacl cryptography aiohttp"
    PYTHON="python3"
fi

echo ""
echo "  run:  $PYTHON $DIR/cli.py"
echo ""
echo "  wallet.json will be created on first launch"
echo "  default RPC: https://devnet.octra.com"
echo ""
echo "  faucet: https://faucet-devnet.octra.com"
echo "  scanner: https://scan.octra.com"
echo ""
