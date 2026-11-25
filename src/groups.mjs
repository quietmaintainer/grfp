import { createHash } from 'node:crypto';
import { PAGE, modes, packPage, restorePage, likelyText, wideMode, tapeWindowMode } from './codec.mjs';
import { TEXT_WINDOW, TAPE_WINDOW, textWindows, textEvents, encodeTextEvents, packText } from './text.mjs';
import { templateTape, expandTape } from './templates.mjs';
import { bindTitles, expandTitles } from './titles.mjs';

export const GROUP = TAPE_WINDOW;
const candidates = {off:[], exact:['exact'], numeric:['exact','slots'], 'full-title':['exact','slots','full'], auto:['exact','slots','full','title']};
export const templatePolicies = Object.keys(candidates);
const tags = { exact: 128, slots: 129, title: 130 };
const hash = data => createHash('sha256').update(data).digest().subarray(0, 16);

function pages(data) {
  const result = [];
  for (let i = 0; i < data.length; i += PAGE) result.push(data.subarray(i, i + PAGE));
  return result;
}

// All candidates share original-page hashes. Plain uses the original GRF1
// records verbatim. Group opcodes sit only at 256 KiB boundaries and contain
// ordinary page instructions for the transformed tape, never nested groups.
export function groupChoices(raw, width, text, policy, window = '256') {
  return groupWindowChoices(raw, width, text, policy, [window])[window];
}

// Construct paired arms from the same template tapes and short-page tries.
// `64-reset` shares framing/entropy state only; `64` also shares the predictor.
export function groupWindowChoices(raw, width, text, policy, requested) {
  if (!raw.length || raw.length > GROUP) throw Error('Invalid source group size');
  if (!requested.length || requested.some(w => !textWindows.includes(w))) throw Error('Invalid text window');
  const longer = requested.filter(w => w === '256' || w === '256-reset');
  const windows = [...new Set(requested.map(w => longer.includes(w) ? '64' : w))], tapes = new Map();
  const original = pages(raw), hashes = original.map(hash), cache = new Map(), wideCache = new Map();
  const trials = windows.filter(w => w !== '16'), traces = trials.includes('64-reset'), copies = text === 'span';
  const byWindow = Object.fromEntries(windows.map(w => [w, {}]));
  function encode(page, signature = hash(page)) {
    const key = signature.toString('hex'), hit = cache.get(key);
    if (hit && page.equals(hit.raw)) return hit;
    let events;
    const encoder = traces ? b => { events = textEvents(b, copies); return encodeTextEvents([events]); } : undefined;
    const {mode, body} = packPage(page, width, text, encoder), h = Buffer.alloc(3);
    h[0] = mode; h.writeUInt16LE(body.length, 1);
    const result = {raw:page, h, body, events}; cache.set(key, result); return result;
  }
  function bundle(key, kind, data, prefix, refs, titleUses) {
    if (longer.length && kind !== 'plain') tapes.set(key,data);
    const outputs = windows.map(() => ({pieces:[...prefix], wideRecords:0, wideBytes:0, firstWide:-1}));
    for (let at = 0; at < data.length; at += TEXT_WINDOW) {
      const part = data.subarray(at, at + TEXT_WINDOW), first = at / PAGE;
      const small = pages(part).map((p, i) => encode(p, kind === 'plain' ? hashes[first+i] : undefined));
      const narrow = small.flatMap((s,i) => kind === 'plain' ? [s.h, hashes[first+i], s.body] : [s.h, s.body]);
      const cost = small.reduce((n,s) => n + 3 + s.body.length, 0); // page hashes cost the same on both sides
      let alternatives;
      if (trials.length && text !== 'off' && part.length > PAGE && cost > 7 && small.some(s => likelyText(s.raw))) {
        const id = hash(part).toString('hex'); alternatives = wideCache.get(id);
        if (!alternatives || !part.equals(alternatives.raw)) {
          alternatives = {raw:part}; wideCache.set(id, alternatives);
          for (const w of trials) {
            const body = w === '64' ? packText(part,copies,w) : encodeTextEvents(small.map(s => s.events ??= textEvents(s.raw,copies)));
            if (body.length > Math.min(part.length,65535) || body.length + 3 >= cost) continue;
            const h = Buffer.alloc(3); h[0] = (w === '64' ? 9 : 7) + Number(copies); h.writeUInt16LE(body.length,1);
            alternatives[w] = {h,body};
          }
        }
      }
      for (const [j,w] of windows.entries()) {
        const wide = alternatives?.[w], out = outputs[j];
        if (!wide) { out.pieces.push(...narrow); continue; }
        out.pieces.push(wide.h, ...(kind === 'plain' ? hashes.slice(first,first+small.length) : []), wide.body);
        out.wideRecords++; out.wideBytes += part.length;
        if (out.firstWide < 0 && part.length === TEXT_WINDOW) out.firstWide = at;
      }
    }
    windows.forEach((w,j) => {
      const {pieces,wideRecords,wideBytes,firstWide} = outputs[j];
      byWindow[w][key] = {kind,bytes:Buffer.concat(pieces),refs,wideRecords,wideBytes,firstWide,...(titleUses && {titleUses})};
    });
  }
  bundle('plain','plain',raw,[],0);
  for (const key of candidates[policy]) {
    const kind = key === 'full' ? 'title' : key;
    const bound = kind === 'title' ? bindTitles(raw, key === 'full') : null;
    if (kind === 'title' && !bound) continue;
    if (key === 'title' && !bound.uses[1] && !bound.uses[2]) continue; // identical to full-only
    const tape = templateTape(bound?.bytes ?? raw, kind);
    if (!tape) continue;
    const h = Buffer.alloc(bound ? 9 : 5); h[0] = tags[kind]; h.writeUInt32LE(tape.bytes.length, 1);
    if (bound) h.writeUInt32LE(bound.bytes.length, 5);
    bundle(key,kind,tape.bytes,[h,...hashes],tape.refs,bound?.uses);
  }
  if (longer.length) {
    // Freeze the winning 64 KiB layout first: previously plain groups stay
    // byte-identical, and an existing template group keeps the very same tape.
    const base = byWindow['64'], winner = chooseGroup(base,policy);
    const key = Object.keys(base).find(k => base[k] === winner), data = tapes.get(key);
    const layout = text !== 'off' && data?.length > TEXT_WINDOW ? parseGroup(winner.bytes,raw.length) : null;
    for (const w of longer) {
      byWindow[w] = layout ? {...base,[key]:extendTape(winner,layout,data,copies,w)} : base;
    }
    if (!requested.includes('64')) delete byWindow['64'];
  }
  return byWindow;
}

// Replace a run of the baseline's nested records only when the entire new
// instruction (including its larger length field) wins. Transforms can expand,
// so a tape may need another independent window beyond the first 256 KiB.
function extendTape(base, layout, data, copies, window) {
  const {records} = layout;
  let pos = base.bytes.length - records.reduce((n,r) => n + 3 + r.body.length,0), i = 0;
  const pieces = [base.bytes.subarray(0,pos)];
  let tapeWindowRecords = 0, tapeWindowBytes = 0, wideRecords = 0, wideBytes = 0, firstWide = -1;
  for (let at = 0; at < data.length; at += TAPE_WINDOW) {
    const part = data.subarray(at,at+TAPE_WINDOW), start = pos, first = i;
    for (let n = 0; n < part.length; i++) { n += records[i].length; pos += 3 + records[i].body.length; }
    if (part.length > TEXT_WINDOW && pages(part).some(likelyText)) {
      const body = packText(part,copies,window);
      if (body.length <= part.length && 5 + body.length < pos-start) {
        const h = Buffer.alloc(5); h[0] = (window === '256' ? 13 : 11) + Number(copies); h.writeUInt32LE(body.length,1);
        pieces.push(h,body); tapeWindowRecords++; tapeWindowBytes += part.length; continue;
      }
    }
    pieces.push(base.bytes.subarray(start,pos));
    for (let j = first, offset = at; j < i; offset += records[j++].length) if (wideMode(records[j].mode)) {
      wideRecords++; wideBytes += records[j].length;
      if (firstWide < 0 && records[j].length === TEXT_WINDOW) firstWide = offset;
    }
  }
  return tapeWindowRecords ? {...base, bytes:Buffer.concat(pieces), tapeWindowRecords, tapeWindowBytes, wideRecords, wideBytes, firstWide} : base;
}

export function chooseGroup(choices, policy) {
  let best = choices.plain;
  for (const key of candidates[policy]) {
    if (choices[key]?.bytes.length < best.bytes.length) best = choices[key];
  }
  return best;
}

// `take` must return exactly n bytes or throw. `length` comes from the file
// header/remaining bytes, not from the template stream.
export function readGroup(length, take) {
  if (!Number.isInteger(length) || length < 1 || length > GROUP) throw Error('Invalid output group size');
  const first = take(1)[0], count = Math.ceil(length / PAGE), hashes = [], records = [];
  const kind = first === tags.exact ? 'exact' : first === tags.slots ? 'slots' : first === tags.title ? 'title' : 'plain';
  let tapeLength = length, boundLength = length, wireBytes = 0;
  if (kind !== 'plain') {
    tapeLength = take(4).readUInt32LE();
    if (kind === 'title') {
      boundLength = take(4).readUInt32LE();
      if (!boundLength || boundLength > 2 * length) throw Error('Invalid title binding length');
    }
    if (!tapeLength || tapeLength > 3 * boundLength) throw Error('Invalid template tape length');
    for (let i = 0; i < count; i++) hashes.push(take(16));
    wireBytes = (kind === 'title' ? 9 : 5) + 16 * count;
  }
  for (let at = 0; at < tapeLength;) {
    const mode = kind === 'plain' && !at ? first : take(1)[0], wide = wideMode(mode), large = tapeWindowMode(mode);
    const n = Math.min(large ? TAPE_WINDOW : wide ? TEXT_WINDOW : PAGE, tapeLength-at);
    if (large && (kind === 'plain' || at % TAPE_WINDOW || n <= TEXT_WINDOW)) throw Error('Invalid template-window placement or length');
    if (wide && (at % TEXT_WINDOW || n <= PAGE)) throw Error('Invalid wide text record alignment or length');
    const size = large ? take(4).readUInt32LE() : take(2).readUInt16LE();
    if (!modes[mode] || size > n || (large && size < 4) || (mode === 0 && size !== n)) throw Error('Invalid page record');
    if (kind === 'plain') for (let i = 0; i < n; i += PAGE) { hashes.push(take(16)); wireBytes += 16; }
    records.push({mode, length:n, body:take(size)}); wireBytes += (large ? 5 : 3) + size;
    at += n;
  }
  return {kind, length, tapeLength, boundLength, hashes, records, wireBytes};
}

export function parseGroup(buffer, length) {
  let pos = 0;
  const result = readGroup(length, n => {
    if (pos + n > buffer.length) throw Error('Truncated group record');
    const part = buffer.subarray(pos, pos + n); pos += n; return part;
  });
  if (pos !== buffer.length) throw Error('Trailing group bytes');
  return result;
}

export function restoreGroup(group, damaged, assemble) {
  const {hashes, kind, length, tapeLength, records} = group, out = Buffer.allocUnsafe(length);
  const trusted = hashes.map((expected, i) => {
    const start = i * PAGE, n = Math.min(PAGE, length - start), old = damaged?.subarray(start, start + n);
    return old?.length === n && hash(old).equals(expected);
  });
  const reusedPages = trusted.filter(Boolean).length, rebuiltPages = hashes.length - reusedPages;
  if (!rebuiltPages) return {bytes:damaged, rebuiltPages, reusedPages, replayedBytes:0, decodedTapeBytes:0};
  let replayedBytes = 0, decodedTapeBytes = 0;
  function emit(page, mode, body) {
    const start = page * PAGE, n = Math.min(PAGE,length-start), old = damaged?.subarray(start,start+n);
    if (trusted[page]) { old.copy(out,start); return; }
    const bytes = assemble ? assemble(mode,body,n,old) : restorePage(mode,body,n);
    if (bytes.length !== n || !hash(bytes).equals(hashes[page])) throw Error('Restored content mismatch in group');
    bytes.copy(out,start);
  }
  if (kind === 'plain') {
    let page = 0;
    for (const r of records) {
      const span = Math.ceil(r.length/PAGE);
      let decoded;
      if (!trusted.slice(page,page+span).every(Boolean)) {
        replayedBytes += r.length; decodedTapeBytes += r.length;
        if (wideMode(r.mode)) decoded = restorePage(r.mode,r.body,r.length);
      }
      for (let j = 0; j < span; j++,page++) emit(page, decoded ? 0 : r.mode, decoded ? decoded.subarray(j*PAGE,(j+1)*PAGE) : r.body);
    }
  } else {
    const tape = Buffer.concat(records.map(r => restorePage(r.mode,r.body,r.length)),tapeLength);
    let expanded = expandTape(tape,kind,group.boundLength);
    if (kind === 'title') expanded = expandTitles(expanded,length);
    replayedBytes = length; decodedTapeBytes = tapeLength;
    hashes.forEach((_,i) => emit(i,0,expanded.subarray(i*PAGE,(i+1)*PAGE)));
  }
  return {bytes:out, rebuiltPages, reusedPages, replayedBytes, decodedTapeBytes};
}
