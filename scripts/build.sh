#!/bin/sh
# Builds the static binary and copies the systemd units into ./dist.
set -eu
cd "$(dirname "$0")/.."
export CGO_ENABLED=0
rm -rf dist
mkdir -p dist/system
go mod download
go build -trimpath -ldflags "-s -w" -o dist/secure-notes ./cmd/secure-notes
cp system/*.service dist/system/
