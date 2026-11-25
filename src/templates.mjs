// A dictionary entry is learned from the first literal line in a group. The
// decoder has exactly the same line. Latin-1 here is a bijection on bytes,
// not an assumption about the input's character encoding.
import { hasTitleSlot } from './titles.mjs';
const MARK = '\xff', SEP = '\u0100'; // SEP cannot occur in a Latin-1 string

function pattern(line, kind) {
  const named = kind === 'title' && line.length >= 16 && hasTitleSlot(line);
  if (!named && line.length < 64) return null;
  const parts = line.split(/[0-9]+/);
  if (!named && parts.length < 4) return null;
  return kind === 'exact' ? { key: line, parts: [line] } : { key: parts.join(SEP), parts };
}

function vint(value) {
  let s = '';
  while (value >= 128) { s += String.fromCharCode(128 | (value & 127)); value >>>= 7; }
  return s + String.fromCharCode(value);
}

export function templateTape(raw, kind) {
  const input = raw.toString('latin1'), ids = new Map(), chunks = [];
  let refs = 0;
  for (let i = 0; i < input.length;) {
    const nl = input.indexOf('\n', i), end = nl < 0 ? input.length : nl + 1;
    const line = input.slice(i, end), p = pattern(line, kind);
    const id = p && ids.get(p.key);
    if (id) {
      chunks.push(MARK, vint(id)); refs++;
      if (kind !== 'exact') for (const digits of line.match(/[0-9]+/g) ?? []) chunks.push(vint(digits.length), digits);
    } else {
      if (line.startsWith(MARK)) chunks.push(MARK, '\0');
      chunks.push(line);
      if (p) ids.set(p.key, ids.size + 1);
    }
    i = end;
  }
  return refs || kind === 'title' ? { bytes: Buffer.from(chunks.join(''), 'latin1'), refs } : null;
}

// Bound every expansion by its declared original group length, independently
// of how small or repetitive the instruction stream is.
export function expandTape(tape, kind, length, maxShift=14) {
  const dict = [], out = Buffer.alloc(length);
  let r = 0, w = 0;
  function integer() {
    let n = 0;
    for (let shift = 0; shift <= maxShift && r < tape.length; shift += 7) {
      const b = tape[r++]; n |= (b & 127) << shift;
      if (b < 128) {
        if (shift && !b) throw Error('Noncanonical template integer');
        return n;
      }
    }
    throw Error('Invalid template integer');
  }
  function append(bytes) {
    if (bytes.length > length - w) throw Error('Template exceeds output group');
    bytes.copy(out, w); w += bytes.length;
  }
  while (r < tape.length) {
    let id = 0;
    if (tape[r] === 255) {
      r++; id = integer();
      if (!id && tape[r] !== 255) throw Error('Invalid template literal escape');
    }
    if (id) {
      const parts = dict[id - 1];
      if (!parts) throw Error('Unknown template reference');
      append(parts[0]);
      for (let j = 1; j < parts.length; j++) {
        const n = integer();
        if (!n || n > tape.length - r || n > length - w) throw Error('Invalid numeric slot length');
        const digits = tape.subarray(r, r + n); r += n;
        for (const b of digits) if (b < 48 || b > 57) throw Error('Non-digit in numeric slot');
        append(digits); append(parts[j]);
      }
    } else {
      const nl = tape.indexOf(10, r), end = nl < 0 ? tape.length : nl + 1, line = tape.subarray(r, end);
      append(line); r = end;
      const p = pattern(line.toString('latin1'), kind);
      if (p) dict.push(p.parts.map(s => Buffer.from(s, 'latin1')));
    }
  }
  if (w !== length) throw Error('Template group length mismatch');
  return out;
}
