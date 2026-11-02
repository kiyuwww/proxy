#!/bin/sh
# Downloads the pinned browser-side bundles (Scramjet, libcurl transport, bare-mux)
# and lays them out for the server:  <out>/scram, <out>/libcurl, <out>/baremux
# Versions match the original project's package.json.
# Usage: sh scripts/fetch-assets.sh [out_dir]   (needs node/npm and tar)
set -eu

OUT="${1:-static}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fetch() { # <npm spec> <dir name>
    mkdir -p "$TMP/$2"
    (cd "$TMP/$2" && npm pack "$1" --silent >/dev/null 2>&1 && tar -xzf ./*.tgz --strip-components=1)
}

fetch "https://github.com/MercuryWorkshop/scramjet/releases/download/v1.1.0/mercuryworkshop-scramjet-1.1.0.tgz" scramjet
fetch "@mercuryworkshop/libcurl-transport@1.5.2" libcurl
fetch "@mercuryworkshop/bare-mux@2.1.9" baremux

mkdir -p "$OUT/scram" "$OUT/libcurl" "$OUT/baremux"
cp "$TMP/scramjet/dist/scramjet.all.js" "$TMP/scramjet/dist/scramjet.sync.js" \
   "$TMP/scramjet/dist/scramjet.wasm.wasm" "$OUT/scram/"
cp "$TMP/libcurl/dist/index.mjs" "$TMP/libcurl/dist/index.cjs" "$OUT/libcurl/"
cp "$TMP/baremux/dist/index.js" "$TMP/baremux/dist/index.mjs" "$TMP/baremux/dist/worker.js" "$OUT/baremux/"
echo "assets written to $OUT"
