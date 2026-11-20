#!/usr/bin/env bash
# The sweep for meshfs-dokan:
#
#   1. here (any OS): rustfmt, clippy with every warning an error for this
#      host and for x86_64-pc-windows-msvc, and the marshal unit tests;
#   2. on the Windows build machine (no git there; sources copied by
#      build.sh): clippy -D warnings, cargo test (unit tests plus the layout
#      tests against the SDK's structures), the driver-structure check
#      (tests/c/layout.c compiled by MSVC from Dokany's own public.h, diffed
#      against examples/layout_dump), and the release build.
#
# It does not mount anything; the driver tests run against a live mount
# with examples/mdtest (they need a free test letter and leave nothing behind).
#
#   meshfs-dokan/sweep.sh [host]          (host: the first argument or $MD_WINDOWS_HOST)
#
# MD_REMOTE_DIR names the build tree under %USERPROFILE% (build.sh).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
HOST="${1:-${MD_WINDOWS_HOST:?usage: sweep.sh <windows-build-host> or set MD_WINDOWS_HOST}}"
bounded() { perl -e 'alarm shift; exec @ARGV' "$@"; }
cd "$HERE"
echo "== 1. local: fmt, clippy (host + windows target), unit tests"
cargo fmt --check
cargo clippy -q --all-targets -- -D warnings
cargo clippy -q --all-targets --target x86_64-pc-windows-msvc -- -D warnings
cargo test -q --lib 2>&1 | grep -E "^test result"
cargo run -q --example layout_dump > /tmp/meshfs-dokan-layout-rust.txt
echo "== 2. $HOST: copy and build"
./build.sh "$HOST" --release --all-targets | grep -E "^error|warning:|Finished" || true
PS='
$ErrorActionPreference = "Continue"
cd $env:USERPROFILE\'"${MD_REMOTE_DIR:-meshfs-dokan}"'
$cargo = "$env:USERPROFILE\.cargo\bin\cargo.exe"
"== clippy"
& $cargo clippy -q --all-targets -- -D warnings 2>&1 | ForEach-Object { "$_" } | Select-Object -Last 20
"exit $LASTEXITCODE"
"== tests"
& $cargo test -q 2>&1 | ForEach-Object { "$_" } | Select-String "test result|FAILED|panicked"
"== public.h layout"
$vc = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cmd /c "`"$vc`" >nul && cd tests\c && cl /nologo /W3 layout.c /Fe:layout.exe >nul && layout.exe > ..\..\layout-c.txt"
& $cargo run -q --release --example layout_dump > layout-rust.txt
$a = Get-Content layout-c.txt; $b = Get-Content layout-rust.txt
"C lines $($a.Count), Rust lines $($b.Count)"
$diff = Compare-Object $a $b
if (-not $a -or -not $b) { "layout check did not run" } elseif ($diff) { $diff | Out-String } else { "layouts identical" }
'
OUT="$(bounded 900 ssh -o ConnectTimeout=8 "$HOST" 'powershell -NoProfile -Command -' <<< "$PS"$'\n\n')"
echo "$OUT"
if grep -q "^exit 0" <<< "$OUT" && grep -q "layouts identical" <<< "$OUT" \
    && ! grep -qE "FAILED|panicked" <<< "$OUT"; then
    echo "SWEEP CLEAN"
else
    echo "SWEEP FAILED"
    exit 1
fi
