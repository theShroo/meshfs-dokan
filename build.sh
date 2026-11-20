#!/usr/bin/env bash
# Builds meshfs_dokan.dll (and the test host) on the Windows build machine.
# The machine has Rust + MSVC but no git: the sources are copied over.
#
#   meshfs-dokan/build.sh [host] [cargo args...]
#
# host: the first argument or $MD_WINDOWS_HOST; the tree lands in %USERPROFILE%\meshfs-dokan (or
# %USERPROFILE%\$MD_REMOTE_DIR, so parallel branches build apart) and the DLL
# in target\release\meshfs_dokan.dll there. Every remote command is
# bounded (alarm), so a hung build cannot hang the caller.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
HOST="${1:-${MD_WINDOWS_HOST:?usage: build.sh <windows-build-host> or set MD_WINDOWS_HOST}}"
shift || true
ARGS="${*:---release --all-targets}"
DIR="${MD_REMOTE_DIR:-meshfs-dokan}"
bounded() { perl -e 'alarm shift; exec @ARGV' "$@"; }
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/$DIR"
(cd "$HERE" && tar cf - Cargo.toml Cargo.lock rustfmt.toml src examples include tests NOTICE COPYING COPYING.LESSER) |
    (cd "$STAGE/$DIR" && tar xf -)
bounded 60 ssh -o ConnectTimeout=8 "$HOST" \
    "powershell -NoProfile -Command \"Remove-Item -Recurse -Force \$env:USERPROFILE\\$DIR\\src,\$env:USERPROFILE\\$DIR\\examples -ErrorAction SilentlyContinue\"" || true
bounded 120 scp -q -r "$STAGE/$DIR" "$HOST":
bounded 900 ssh -o ConnectTimeout=8 "$HOST" \
    "powershell -NoProfile -Command \"cd \$env:USERPROFILE\\$DIR; & \$env:USERPROFILE\\.cargo\\bin\\cargo.exe build $ARGS 2>&1 | Select-Object -Last 15\""
