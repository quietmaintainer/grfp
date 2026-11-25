// Bind exact byte strings from a title already decoded inside this checkpoint.
// The string view is Latin-1 so byte values (including malformed UTF-8) survive.
const ESC = 251, SLOT = 252; // FB escapes a literal FB..FE; FC/FD/FE select a binding.
const literal = s => s.replace(/[\xfb-\xfe]/g, b => '\xfb' + b);
const word = c => c >= 128 || c === 95 || (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
const control = /^[ \t]*<\/?(?:page|title)(?=[ \t/>\r\n]|$)/;

function bindings(line) {
  const m = /^[ \t]*<title>([^<>\r\n]{1,1024})<\/title>[ \t]*\r?\n?$/.exec(line);
  if (!m) return []; // a page boundary or unusable title also clears the old one
  const full = m[1], comma = full.indexOf(', '), paren = full.lastIndexOf(' (');
  let place, qualifier;
  if (comma > 0) { place = full.slice(0, comma); qualifier = full.slice(full.lastIndexOf(', ') + 2); }
  else if (paren > 0 && full.endsWith(')')) { place = full.slice(0, paren); qualifier = full.slice(paren + 2, -1); }
  const names = [full, place, qualifier];
  return names.map((s, i) => s?.length >= 3 && names.indexOf(s) === i ? s : null);
}

export function hasTitleSlot(line) {
  for (let i = 0; i < line.length; i++) {
    const c = line.charCodeAt(i);
    if (c === ESC) i++;
    else if (c >= SLOT && c <= SLOT + 2) return true;
  }
  return false;
}

export function bindTitles(raw, fullOnly = false) {
  if (raw.indexOf('<title>') < 0) return null;
  const input = raw.toString('latin1'), out = [], uses = [0, 0, 0];
  let names = [];
  for (let r = 0; r < input.length;) {
    const nl = input.indexOf('\n', r), end = nl < 0 ? input.length : nl + 1, line = input.slice(r, end); r = end;
    if (control.test(line)) {
      out.push(literal(line)); names = bindings(line);
      if (fullOnly) names = names.slice(0, 1);
      continue;
    }
    // Earliest whole-word match wins, longest first at the same position.
    // Cache each next position so an absent qualifier isn't rescanned per hit.
    const next = names.map(s => s ? line.indexOf(s) : -1);
    let from = 0;
    for (;;) {
      let best = -1;
      for (let k = 0; k < next.length; k++) if (next[k] >= 0 && (best < 0 || next[k] < next[best]
          || (next[k] === next[best] && names[k].length > names[best].length))) best = k;
      if (best < 0) break;
      const at = next[best], name = names[best], after = at + name.length;
      if ((word(line.charCodeAt(at - 1)) && word(name.charCodeAt(0))) ||
          (word(line.charCodeAt(after)) && word(name.charCodeAt(name.length - 1)))) {
        next[best] = line.indexOf(name, at + 1); continue;
      }
      out.push(literal(line.slice(from, at)), String.fromCharCode(SLOT + best)); uses[best]++; from = after;
      for (let k = 0; k < next.length; k++) if (next[k] >= 0 && next[k] < from) next[k] = line.indexOf(names[k], from);
    }
    out.push(literal(line.slice(from)));
  }
  return uses.some(Boolean) ? {bytes:Buffer.from(out.join(''), 'latin1'), uses} : null;
}

export function expandTitles(bound, length) {
  const out = Buffer.alloc(length); let w = 0, names = [];
  function append(b) {
    if (b.length > length - w) throw Error('Title expansion exceeds original group');
    b.copy(out, w); w += b.length;
  }
  for (let r = 0; r < bound.length;) {
    const nl = bound.indexOf(10, r), end = nl < 0 ? bound.length : nl + 1, start = w;
    let literalStart = r, used = false;
    while (r < end) {
      const c = bound[r++];
      if (c < ESC || c > SLOT + 2) continue;
      append(bound.subarray(literalStart, r - 1));
      if (c === ESC) {
        if (r >= end || bound[r] < ESC || bound[r] > SLOT + 2) throw Error('Invalid title literal escape');
        append(bound.subarray(r, r + 1)); r++;
      } else {
        const value = names[c - SLOT];
        if (!value) throw Error('Title slot without a current binding');
        append(value); used = true;
      }
      literalStart = r;
    }
    append(bound.subarray(literalStart, end));
    const line = out.toString('latin1', start, w);
    if (control.test(line)) {
      if (used) throw Error('Title binding depends on another title slot');
      names = bindings(line).map(s => s && Buffer.from(s, 'latin1'));
    }
  }
  if (w !== length) throw Error('Title group length mismatch');
  return out;
}
