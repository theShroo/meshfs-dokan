// meshfs-dokan: a port of Dokany's user-mode protocol (dokan2.dll).
// Copyright (C) 2026 Harland Consulting
//
// Ported from Dokany v2.3.1.1000 dokan/directory.c (DokanIsNameInExpression):
//   Copyright (C) 2020 - 2025 Google, Inc.
//   Copyright (C) 2015 - 2019 Adrien J. <liryna.stark@gmail.com> and Maxime C. <maxime@islog.com>
//   Copyright (C) 2007 - 2011 Hiroki Asakawa <info@dokan-dev.net>
//
// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3 of the License, or (at your
// option) any later version. See COPYING.LESSER.

//! Wildcard matching with FsRtlIsNameInExpression semantics: `*`, `?` and the
//! DOS wildcards `<` (DOS_STAR), `>` (DOS_QM) and `"` (DOS_DOT).

const DOS_STAR: u16 = b'<' as u16;
const DOS_QM: u16 = b'>' as u16;
const DOS_DOT: u16 = b'"' as u16;
const STAR: u16 = b'*' as u16;
const QM: u16 = b'?' as u16;
const DOT: u16 = b'.' as u16;

/// towupper for one UTF-16 unit (surrogates and multi-char mappings unchanged).
fn upcase(c: u16) -> u16 {
    match char::from_u32(c as u32) {
        Some(ch) => {
            let mut up = ch.to_uppercase();
            match (up.next(), up.next()) {
                (Some(u), None) if (u as u32) <= 0xFFFF => u as u16,
                _ => c,
            }
        }
        None => c,
    }
}

/// Whether `name` matches `expression`. Both are taken without terminators;
/// reading past either end yields NUL, as the C original reads its terminator.
pub fn is_name_in_expression(expression: &[u16], name: &[u16], ignore_case: bool) -> bool {
    matches(expression, name, ignore_case)
}

fn matches(e: &[u16], n: &[u16], ignore_case: bool) -> bool {
    let ec = |i: usize| e.get(i).copied().unwrap_or(0);
    let nc = |i: usize| n.get(i).copied().unwrap_or(0);
    let (mut ei, mut ni) = (0usize, 0usize);
    while ec(ei) != 0 {
        let x = ec(ei);
        if x == STAR {
            ei += 1;
            if ec(ei) == 0 {
                return true;
            }
            while nc(ni) != 0 {
                if matches(&e[ei..], &n[ni..], ignore_case) {
                    return true;
                }
                ni += 1;
            }
        } else if x == DOS_STAR {
            let mut p = ni;
            let mut last_dot = 0usize;
            ei += 1;
            while nc(p) != 0 {
                if nc(p) == DOT {
                    last_dot = p;
                }
                p += 1;
            }
            loop {
                let end_reached = nc(ni) == 0 || ni == last_dot;
                if end_reached {
                    break;
                }
                if matches(e.get(ei..).unwrap_or(&[]), n.get(ni..).unwrap_or(&[]), ignore_case) {
                    return true;
                }
                ni += 1;
            }
        } else if x == DOS_QM {
            ei += 1;
            if nc(ni) != DOT {
                ni += 1;
            } else {
                let mut p = ni + 1;
                while nc(p) != 0 {
                    if nc(p) == DOT {
                        break;
                    }
                    p += 1;
                }
                if nc(p) == DOT {
                    ni += 1;
                }
            }
        } else if x == DOS_DOT {
            ei += 1;
            if nc(ni) == DOT {
                ni += 1;
            }
        } else if x == QM || (ignore_case && upcase(x) == upcase(nc(ni))) || (!ignore_case && x == nc(ni)) {
            ei += 1;
            ni += 1;
        } else {
            return false;
        }
    }
    let elen = e.iter().position(|&c| c == 0).unwrap_or(e.len());
    let nlen = n.iter().position(|&c| c == 0).unwrap_or(n.len());
    ei == elen && ni == nlen
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }
    fn m(e: &str, n: &str) -> bool {
        is_name_in_expression(&w(e), &w(n), true)
    }

    #[test]
    fn star_and_question() {
        assert!(m("*", "anything.txt"));
        assert!(m("*.txt", "a.txt"));
        assert!(!m("*.txt", "a.txt2"));
        assert!(m("a?c", "abc"));
        assert!(!m("a?c", "ac"));
        assert!(m("*b*", "abc"));
        assert!(!m("*z*", "abc"));
        assert!(m("ABC", "abc"));
        assert!(!is_name_in_expression(&w("ABC"), &w("abc"), false));
        assert!(m("", ""));
        assert!(!m("", "a"));
    }

    #[test]
    fn dos_wildcards() {
        // What cmd's "dir *.*" and "dir a*" send after RtlTranslate: "<.<" etc.
        assert!(m("<.<", "file.txt"));
        assert!(m("file\"txt", "file.txt"));
        assert!(m("file\"", "file"));
        assert!(m("a>>.txt", "ab.txt"));
        // dokan2.dll's DOS_QM consumes past the end of the name, so a trailing
        // '>' does not match "nothing" (FsRtl would); the port keeps that.
        assert!(!m("a>>", "a"));
        assert!(!m("a>.txt", "abc.txt"));
    }

    #[test]
    fn never_reads_out_of_bounds() {
        for e in ["?", "??", ">", ">>", "\"", "<", "*?", "?*", "<.", ">.>"] {
            for n in ["", "a", ".", "a.b", "..", "abc.def.ghi"] {
                let _ = m(e, n);
            }
        }
    }
}
