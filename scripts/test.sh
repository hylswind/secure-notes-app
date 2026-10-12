#!/bin/sh
# Offline test run: dependencies come from the module cache filled by build.sh.
set -eu
cd "$(dirname "$0")/.."
export CGO_ENABLED=0 DEV_INSECURE_HTTP=1 GOFLAGS=-mod=readonly GOPROXY=off
DATA_DIR="$(mktemp -d)"
export DATA_DIR
trap 'rm -rf "$DATA_DIR"' EXIT
go vet ./...
go test ./...
