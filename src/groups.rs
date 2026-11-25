use std::collections::HashMap;
use std::io::Read;
use std::ops::Range;

use crate::io::{hash, put32};
use crate::pages::{self, MODES, TextPolicy};
use crate::templates::{self, Kind};
use crate::text::{self, GROUP, PAGE, WIDE, Window};
use anyhow::{Result, ensure};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TemplatePolicy {
    Off,
    Exact,
    Numeric,
    FullTitle,
    Auto,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    #[serde(deserialize_with = "Option::deserialize")]
    pub width: Option<usize>,
    pub text: TextPolicy,
    pub templates: TemplatePolicy,
    pub text_window: Window,
}

impl Profile {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.width.is_none_or(|width| (3..=1024).contains(&width)),
            "Width must be 3–1024 bits"
        );
        Ok(())
    }
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            width: None,
            text: TextPolicy::Span,
            templates: TemplatePolicy::Auto,
            text_window: Window::Group,
        }
    }
}

#[derive(Clone)]
pub(crate) struct Record {
    pub mode: u8,
    pub length: usize,
    pub body: Range<usize>,
}

pub(crate) struct Group {
    pub kind: Kind,
    pub length: usize,
    pub tape_length: usize,
    pub bound_length: usize,
    pub hashes: Vec<[u8; 16]>,
    pub records: Vec<Record>,
    pub wire: Vec<u8>,
}

fn take(input: &mut impl Read, wire: &mut Vec<u8>, n: usize) -> Result<Range<usize>> {
    let start = wire.len();
    wire.resize(start + n, 0);
    input.read_exact(&mut wire[start..])?;
    Ok(start..start + n)
}

pub(crate) fn read(input: &mut impl Read, length: usize) -> Result<Group> {
    ensure!((1..=GROUP).contains(&length), "Invalid output group size");
    let mut wire = Vec::new();
    let mut hashes = Vec::new();
    let mut records = Vec::new();
    take(input, &mut wire, 1)?;
    let first = wire[0];
    let kind = match first {
        128 => Kind::Exact,
        129 => Kind::Slots,
        130 => Kind::Title,
        _ => Kind::Plain,
    };
    let mut tape_length = length;
    let mut bound_length = length;
    if kind != Kind::Plain {
        let range = take(input, &mut wire, 4)?;
        tape_length = u32::from_le_bytes(wire[range].try_into().unwrap()) as usize;
        if kind == Kind::Title {
            let range = take(input, &mut wire, 4)?;
            bound_length = u32::from_le_bytes(wire[range].try_into().unwrap()) as usize;
            ensure!(
                (1..=2 * length).contains(&bound_length),
                "Invalid title binding length"
            );
        }
        ensure!(
            (1..=3 * bound_length).contains(&tape_length),
            "Invalid template tape length"
        );
        for _ in 0..length.div_ceil(PAGE) {
            let range = take(input, &mut wire, 16)?;
            hashes.push(wire[range].try_into().unwrap());
        }
    }
    let mut at = 0;
    while at < tape_length {
        let mode = if kind == Kind::Plain && at == 0 {
            first
        } else {
            let range = take(input, &mut wire, 1)?;
            wire[range.start]
        };
        let wide = pages::wide(mode);
        let large = pages::large(mode);
        let n = (tape_length - at).min(if large {
            GROUP
        } else if wide {
            WIDE
        } else {
            PAGE
        });
        ensure!(
            !large || (kind != Kind::Plain && at % GROUP == 0 && n > WIDE),
            "Invalid template-window placement or length"
        );
        ensure!(
            !wide || (at % WIDE == 0 && n > PAGE),
            "Invalid wide record alignment or length"
        );
        let count = if large {
            let range = take(input, &mut wire, 4)?;
            u32::from_le_bytes(wire[range].try_into().unwrap()) as usize
        } else {
            let range = take(input, &mut wire, 2)?;
            u16::from_le_bytes(wire[range].try_into().unwrap()) as usize
        };
        ensure!(
            (mode as usize) < MODES.len()
                && count <= n
                && (!large || count >= 4)
                && (mode != 0 || count == n),
            "Invalid page record"
        );
        if kind == Kind::Plain {
            for _ in 0..n.div_ceil(PAGE) {
                let range = take(input, &mut wire, 16)?;
                hashes.push(wire[range].try_into().unwrap());
            }
        }
        let body = take(input, &mut wire, count)?;
        records.push(Record {
            mode,
            length: n,
            body,
        });
        at += n;
    }
    Ok(Group {
        kind,
        length,
        tape_length,
        bound_length,
        hashes,
        records,
        wire,
    })
}

pub(crate) fn parse(mut wire: &[u8], length: usize) -> Result<Group> {
    let group = read(&mut wire, length)?;
    ensure!(wire.is_empty(), "Trailing group bytes");
    Ok(group)
}

pub(crate) fn tag(bytes: &[u8]) -> [u8; 16] {
    hash(bytes)[..16].try_into().unwrap()
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Replay {
    #[serde(skip)]
    pub bytes: Vec<u8>,
    pub reused_pages: usize,
    pub rebuilt_pages: usize,
    pub replayed_bytes: u64,
    pub decoded_tape_bytes: u64,
}

impl Replay {
    pub fn add(&mut self, other: &Self) {
        self.reused_pages += other.reused_pages;
        self.rebuilt_pages += other.rebuilt_pages;
        self.replayed_bytes += other.replayed_bytes;
        self.decoded_tape_bytes += other.decoded_tape_bytes;
    }
}

pub(crate) fn restore(group: &Group, damaged: &[u8]) -> Result<Replay> {
    let Group {
        length,
        hashes,
        records,
        kind,
        tape_length,
        bound_length,
        wire,
    } = group;
    let trusted: Vec<_> = hashes
        .iter()
        .enumerate()
        .map(|(i, expected)| {
            damaged
                .get(i * PAGE..((i + 1) * PAGE).min(*length))
                .filter(|b| tag(b) == *expected)
        })
        .collect();
    let reused_pages = trusted.iter().filter(|page| page.is_some()).count();
    let mut result = Replay {
        reused_pages,
        rebuilt_pages: hashes.len() - reused_pages,
        ..Replay::default()
    };
    if result.rebuilt_pages == 0 {
        result.bytes.extend_from_slice(&damaged[..*length]);
        return Ok(result);
    }
    result.bytes.reserve(*length);
    let mut emit = |i: usize, decoded: &[u8]| -> Result<()> {
        if let Some(old) = trusted[i] {
            result.bytes.extend_from_slice(old);
        } else {
            ensure!(
                tag(decoded) == hashes[i],
                "Restored content mismatch in group"
            );
            result.bytes.extend_from_slice(decoded);
        }
        Ok(())
    };
    if *kind == Kind::Plain {
        let mut page = 0;
        for record in records {
            let count = record.length.div_ceil(PAGE);
            if trusted[page..page + count].iter().all(Option::is_some) {
                for i in page..page + count {
                    emit(i, &[])?;
                }
            } else {
                let bytes = pages::restore(record.mode, &wire[record.body.clone()], record.length)?;
                for (j, decoded) in bytes.chunks(PAGE).enumerate() {
                    emit(page + j, decoded)?;
                }
                result.replayed_bytes += record.length as u64;
                result.decoded_tape_bytes += record.length as u64;
            }
            page += count;
        }
    } else {
        let mut tape = Vec::with_capacity(*tape_length);
        for r in records {
            tape.extend(pages::restore(r.mode, &wire[r.body.clone()], r.length)?);
        }
        let expanded = templates::expand(&tape, *kind, *bound_length)?;
        let original = if *kind == Kind::Title {
            templates::expand_titles(&expanded, *length)?
        } else {
            expanded
        };
        for (i, b) in original.chunks(PAGE).enumerate() {
            emit(i, b)?;
        }
        result.replayed_bytes = *length as u64;
        result.decoded_tape_bytes = *tape_length as u64;
    }
    ensure!(
        result.bytes.len() == *length,
        "Restored group length mismatch"
    );
    Ok(result)
}

fn instruction(out: &mut Vec<u8>, mode: u8, tags: &[[u8; 16]], body: &[u8]) {
    out.push(mode);
    if pages::large(mode) {
        put32(out, body.len());
    } else {
        out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    }
    for tag in tags {
        out.extend_from_slice(tag);
    }
    out.extend_from_slice(body);
}

type PageCache<'a> = HashMap<&'a [u8], (u8, Vec<u8>)>;

fn bundle<'a>(
    data: &'a [u8],
    plain_tags: Option<&[[u8; 16]]>,
    profile: &Profile,
    window: Window,
    cache: &mut PageCache<'a>,
    out: &mut Vec<u8>,
) -> Result<()> {
    let copies = profile.text == TextPolicy::Span;
    for (i, part) in data.chunks(WIDE).enumerate() {
        let mut narrow = Vec::new();
        let tags = plain_tags.map_or(&[][..], |all| {
            &all[i * 4..(i * 4 + part.len().div_ceil(PAGE))]
        });
        for (j, page) in part.chunks(PAGE).enumerate() {
            let packed = match cache.entry(page) {
                std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(pages::pack(page, profile.width, profile.text)?)
                }
            };
            let page_tag = tags.get(j).map_or(&[][..], std::slice::from_ref);
            instruction(&mut narrow, packed.0, page_tag, &packed.1);
        }
        let cost = narrow.len() - 16 * tags.len();
        if window != Window::Page
            && profile.text != TextPolicy::Off
            && part.len() > PAGE
            && cost > 7
            && part.chunks(PAGE).any(pages::likely_text)
        {
            let body = text::pack(part, copies, window)?;
            if body.len() <= part.len().min(65_535) && body.len() + 3 < cost {
                let mode = if window == Window::Wide { 9 } else { 7 } + u8::from(copies);
                instruction(out, mode, tags, &body);
                continue;
            }
        }
        out.extend(narrow);
    }
    Ok(())
}

fn extend_tape(
    wire: Vec<u8>,
    data: &[u8],
    original_length: usize,
    copies: bool,
    window: Window,
) -> Result<Vec<u8>> {
    let group = parse(&wire, original_length)?;
    let mut pos = group.records[0].body.start - 3;
    let mut i = 0;
    let mut out = wire[..pos].to_vec();
    for part in data.chunks(GROUP) {
        let start = pos;
        let mut n = 0;
        while n < part.len() {
            n += group.records[i].length;
            pos = group.records[i].body.end;
            i += 1;
        }
        if part.len() > WIDE && part.chunks(PAGE).any(pages::likely_text) {
            let body = text::pack(part, copies, window)?;
            if body.len() <= part.len() && 5 + body.len() < pos - start {
                let mode = if window == Window::Group { 13 } else { 11 } + u8::from(copies);
                instruction(&mut out, mode, &[], &body);
                continue;
            }
        }
        out.extend_from_slice(&wire[start..pos]);
    }
    Ok(out)
}

pub(crate) fn pack(raw: &[u8], profile: &Profile) -> Result<Vec<u8>> {
    ensure!(
        (1..=GROUP).contains(&raw.len()),
        "Invalid source group size"
    );
    let tags: Vec<_> = raw.chunks(PAGE).map(tag).collect();
    let large = matches!(profile.text_window, Window::Reset256 | Window::Group);
    let window = if large {
        Window::Wide
    } else {
        profile.text_window
    };
    let mut best = Vec::new();
    let mut best_tape = None;
    bundle(
        raw,
        Some(&tags),
        profile,
        window,
        &mut HashMap::new(),
        &mut best,
    )?;

    let kinds: &[(Kind, bool)] = match profile.templates {
        TemplatePolicy::Off => &[],
        TemplatePolicy::Exact => &[(Kind::Exact, false)],
        TemplatePolicy::Numeric => &[(Kind::Exact, false), (Kind::Slots, false)],
        TemplatePolicy::FullTitle => &[
            (Kind::Exact, false),
            (Kind::Slots, false),
            (Kind::Title, true),
        ],
        TemplatePolicy::Auto => &[
            (Kind::Exact, false),
            (Kind::Slots, false),
            (Kind::Title, true),
            (Kind::Title, false),
        ],
    };
    for &(kind, full_only) in kinds {
        let bound = if kind == Kind::Title {
            let Some((bound, uses)) = templates::bind_titles(raw, full_only) else {
                continue;
            };
            if !full_only && uses[1] == 0 && uses[2] == 0 {
                continue;
            }
            Some(bound)
        } else {
            None
        };
        let Some(tape) = templates::tape(bound.as_deref().unwrap_or(raw), kind) else {
            continue;
        };
        let mut wire = vec![kind.tag()];
        put32(&mut wire, tape.len());
        if let Some(bound) = &bound {
            put32(&mut wire, bound.len());
        }
        for tag in &tags {
            wire.extend_from_slice(tag);
        }
        bundle(&tape, None, profile, window, &mut HashMap::new(), &mut wire)?;
        if wire.len() < best.len() {
            best = wire;
            best_tape = Some(tape);
        }
    }
    if large
        && profile.text != TextPolicy::Off
        && let Some(tape) = best_tape
        && tape.len() > WIDE
    {
        return extend_tape(
            best,
            &tape,
            raw.len(),
            profile.text == TextPolicy::Span,
            profile.text_window,
        );
    }
    Ok(best)
}
