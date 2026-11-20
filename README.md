# meshfs-dokan

A Rust port of the user-mode protocol of [Dokany](https://github.com/dokan-dev/dokany)
2.3.1 (the part `dokan2.dll` implements), built as `meshfs_dokan.dll` behind a small,
versioned C ABI (`include/meshfs_dokan.h`). It talks to the **unmodified** `dokan2.sys`
kernel driver from Dokany's own signed release; it never changes the driver.

It is the LGPL part of [MeshFS](https://meshfs.harlandconsulting.au)'s Windows client:
the client's host implements the callback table in `meshfs_dokan.h`, loads this library
by its full path, and serves the file system. This library holds the driver protocol
only: no caching, no access policy, no MeshFS logic.

## What it does

- Version handshake with the driver (pinned to Dokany 2.3.1.1000's protocol), mount,
  keepalive, change notifications, unmount.
- The request pull/reply loop, large writes (`FSCTL_EVENT_WRITE`), timeout resets, and
  deferred replies (a callback returns `STATUS_PENDING` and answers later with `md_reply`;
  replies are sent from a pool of reply threads, never on the caller's thread).
- Request decoding and reply encoding for every operation: create dispositions, file and
  volume information classes, directory listings with pattern matching, security
  descriptors, and named streams (ABI 1.1).

## Building

Windows, Rust (MSVC toolchain): `cargo build --release` produces `meshfs_dokan.dll`.
`sweep.sh <windows-build-host>` runs formatting, clippy for the host and the MSVC
target, the unit tests, and a layout check against Dokany's own `public.h`.
Running a mount needs Dokany 2.3.1.1000's driver installed.

## Licence

LGPL-3.0-or-later (see `COPYING.LESSER` and `COPYING`). The protocol logic is ported
from Dokany's `dokan2.dll`; Dokany's copyright notices are kept in `NOTICE` and in the
ported files. MeshFS ships this library as a separate DLL that you may replace with a
modified build of this source.
