use crate::io::{Bytes, append_bounded, put_vint};
use anyhow::{Result, ensure};
use memchr::{memchr, memmem};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Plain,
    Exact,
    Slots,
    Title,
}

impl Kind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Exact => "exact",
            Self::Slots => "slots",
            Self::Title => "title",
        }
    }
    pub(crate) fn tag(self) -> u8 {
        match self {
            Self::Plain => 0,
            Self::Exact => 128,
            Self::Slots => 129,
            Self::Title => 130,
        }
    }
}

const ESC: u8 = 251;
const SLOT: u8 = 252;

fn title_slot(line: &[u8]) -> bool {
    let mut i = 0;
    while i < line.len() {
        let b = line[i];
        if (SLOT..=SLOT + 2).contains(&b) {
            return true;
        }
        i += if b == ESC { 2 } else { 1 };
    }
    false
}

fn pattern(line: &[u8], kind: Kind) -> Option<Vec<&[u8]>> {
    let named = kind == Kind::Title && line.len() >= 16 && title_slot(line);
    if !named && line.len() < 64 {
        return None;
    }
    let mut parts = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < line.len() {
        if line[i].is_ascii_digit() {
            parts.push(&line[start..i]);
            while i < line.len() && line[i].is_ascii_digit() {
                i += 1;
            }
            start = i;
        } else {
            i += 1;
        }
    }
    parts.push(&line[start..]);
    if !named && parts.len() < 4 {
        return None;
    }
    if kind == Kind::Exact {
        Some(vec![line])
    } else {
        Some(parts)
    }
}

pub(crate) fn tape(raw: &[u8], kind: Kind) -> Option<Vec<u8>> {
    let mut dictionary: HashMap<Vec<&[u8]>, usize> = HashMap::new();
    let mut output = Vec::new();
    let mut used = false;
    for line in raw.split_inclusive(|&b| b == b'\n') {
        let parts = pattern(line, kind);
        if let Some(id) = parts.as_ref().and_then(|parts| dictionary.get(parts)) {
            output.push(255);
            put_vint(&mut output, *id as u64);
            used = true;
            if kind != Kind::Exact {
                for digits in line
                    .split(|b| !b.is_ascii_digit())
                    .filter(|run| !run.is_empty())
                {
                    put_vint(&mut output, digits.len() as u64);
                    output.extend_from_slice(digits);
                }
            }
        } else {
            if line.first() == Some(&255) {
                output.extend_from_slice(&[255, 0]);
            }
            output.extend_from_slice(line);
            if let Some(parts) = parts {
                let id = dictionary.len() + 1;
                dictionary.insert(parts, id);
            }
        }
    }
    (used || kind == Kind::Title).then_some(output)
}

pub(crate) fn expand(tape: &[u8], kind: Kind, length: usize) -> Result<Vec<u8>> {
    let mut input = Bytes::new(tape);
    let mut dict = Vec::<Vec<&[u8]>>::new();
    let mut out = Vec::with_capacity(length);
    while let Some(&first) = input.left().first() {
        let id = if first == 255 {
            input.byte()?;
            let id = input.vint(14)? as usize;
            ensure!(
                id > 0 || input.left().first() == Some(&255),
                "Invalid template literal escape"
            );
            id
        } else {
            0
        };
        if id == 0 {
            let len = memchr(b'\n', input.left()).map_or(input.left().len(), |i| i + 1);
            let line = input.take(len)?;
            append_bounded(&mut out, line, length)?;
            if let Some(parts) = pattern(line, kind) {
                dict.push(parts);
            }
        } else {
            let parts = dict
                .get(id - 1)
                .ok_or_else(|| anyhow::anyhow!("Unknown template reference"))?;
            append_bounded(&mut out, parts[0], length)?;
            for part in &parts[1..] {
                let n = input.vint(14)? as usize;
                let digits = input.take(n)?;
                ensure!(
                    n > 0 && digits.iter().all(u8::is_ascii_digit),
                    "Invalid numeric template slot"
                );
                append_bounded(&mut out, digits, length)?;
                append_bounded(&mut out, part, length)?;
            }
        }
    }
    ensure!(out.len() == length, "Template group length mismatch");
    Ok(out)
}

fn trim_start(line: &[u8]) -> &[u8] {
    &line[line
        .iter()
        .take_while(|b| matches!(b, b' ' | b'\t'))
        .count()..]
}

fn trim_end(line: &[u8]) -> &[u8] {
    let n = line
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\t'))
        .map_or(0, |i| i + 1);
    &line[..n]
}

fn control(line: &[u8]) -> bool {
    let Some(line) = trim_start(line).strip_prefix(b"<") else {
        return false;
    };
    let line = line.strip_prefix(b"/").unwrap_or(line);
    let suffix = line
        .strip_prefix(b"page")
        .or_else(|| line.strip_prefix(b"title"));
    suffix.is_some_and(|tail| {
        tail.first()
            .is_none_or(|b| matches!(b, b' ' | b'\t' | b'/' | b'>' | b'\r' | b'\n'))
    })
}

fn bindings(line: &[u8]) -> [Option<&[u8]>; 3] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let Some(full) = trim_end(trim_start(line))
        .strip_prefix(b"<title>")
        .and_then(|s| s.strip_suffix(b"</title>"))
    else {
        return [None; 3];
    };
    if full.is_empty()
        || full.len() > 1024
        || full
            .iter()
            .any(|b| matches!(b, b'<' | b'>' | b'\r' | b'\n'))
    {
        return [None; 3];
    }
    let mut names = [Some(full), None, None];
    if let Some(at) = memmem::find(full, b", ").filter(|&i| i > 0) {
        names[1] = Some(&full[..at]);
        names[2] = Some(&full[memmem::rfind(full, b", ").unwrap() + 2..]);
    } else if let Some(at) = memmem::rfind(full, b" (").filter(|&i| i > 0 && full.ends_with(b")")) {
        names[1] = Some(&full[..at]);
        names[2] = Some(&full[at + 2..full.len() - 1]);
    }
    std::array::from_fn(|i| {
        names[i].filter(|name| name.len() >= 3 && !names[..i].contains(&Some(*name)))
    })
}

fn word(b: u8) -> bool {
    b >= 128 || b.is_ascii_alphanumeric() || b == b'_'
}

fn literal(out: &mut Vec<u8>, bytes: &[u8]) {
    for &b in bytes {
        if (ESC..=SLOT + 2).contains(&b) {
            out.push(ESC);
        }
        out.push(b);
    }
}

pub(crate) fn bind_titles(raw: &[u8], full_only: bool) -> Option<(Vec<u8>, [usize; 3])> {
    memmem::find(raw, b"<title>")?;
    let mut out = Vec::new();
    let mut uses = [0; 3];
    let mut names = [None; 3];
    for line in raw.split_inclusive(|&b| b == b'\n') {
        if control(line) {
            literal(&mut out, line);
            names = bindings(line);
            if full_only {
                names[1..].fill(None);
            }
            continue;
        }
        let mut next = names.map(|name| name.and_then(|s| memmem::find(line, s)));
        let mut from = 0;
        loop {
            let mut best: Option<(usize, usize, &[u8])> = None;
            for (k, &pos) in next.iter().enumerate() {
                if let Some(at) = pos {
                    let name = names[k].unwrap();
                    if best.is_none_or(|(_, j, old)| at < j || (at == j && name.len() > old.len()))
                    {
                        best = Some((k, at, name));
                    }
                }
            }
            let Some((k, at, name)) = best else {
                break;
            };
            let after = at + name.len();
            if (at > 0 && word(line[at - 1]) && word(name[0]))
                || (line.get(after).is_some_and(|&b| word(b)) && word(name[name.len() - 1]))
            {
                next[k] = memmem::find(&line[at + 1..], name).map(|i| at + 1 + i);
                continue;
            }
            literal(&mut out, &line[from..at]);
            out.push(SLOT + k as u8);
            uses[k] += 1;
            from = after;
            for (j, pos) in next.iter_mut().enumerate() {
                if pos.is_some_and(|at| at < from) {
                    *pos = memmem::find(&line[from..], names[j].unwrap()).map(|i| from + i);
                }
            }
        }
        literal(&mut out, &line[from..]);
    }
    uses.iter().any(|&n| n > 0).then_some((out, uses))
}

pub(crate) fn expand_titles(bound: &[u8], length: usize) -> Result<Vec<u8>> {
    let mut names: [Option<Vec<u8>>; 3] = [None, None, None];
    let mut out = Vec::with_capacity(length);
    for line in bound.split_inclusive(|&b| b == b'\n') {
        let start = out.len();
        let mut input = Bytes::new(line);
        let mut used = false;
        while !input.left().is_empty() {
            let b = input.byte()?;
            if b == ESC {
                let replacement = input.take(1)?;
                ensure!(
                    (ESC..=SLOT + 2).contains(&replacement[0]),
                    "Invalid title literal escape"
                );
                append_bounded(&mut out, replacement, length)?;
            } else if (SLOT..=SLOT + 2).contains(&b) {
                let name = names[(b - SLOT) as usize]
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("Title slot without a binding"))?;
                append_bounded(&mut out, name, length)?;
                used = true;
            } else {
                append_bounded(&mut out, &[b], length)?;
            }
        }
        if control(&out[start..]) {
            ensure!(!used, "Title binding depends on a slot");
            names = bindings(&out[start..]).map(|s| s.map(<[u8]>::to_vec));
        }
    }
    ensure!(out.len() == length, "Title group length mismatch");
    Ok(out)
}
