// GRF1 page instructions. No filenames, external dictionaries or executable payloads.
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { TEXT_PAGE, TEXT_WINDOW, TAPE_WINDOW, packText, restoreText } from './text.mjs';

export const PAGE = TEXT_PAGE;
export const modes = ['literal', 'deflate', 'links', 'links-deflate', 'row-ca', 'text-context', 'text-span',
  'text-context-64-reset', 'text-span-64-reset', 'text-context-64', 'text-span-64',
  'text-context-256-reset', 'text-span-256-reset', 'text-context-256', 'text-span-256'];
export const wideMode = mode => Number.isInteger(mode) && mode >= 7 && mode <= 10;
export const tapeWindowMode = mode => Number.isInteger(mode) && mode >= 11 && mode <= 14;
export const textPolicies = ['off', 'context', 'span'];
const zip = bytes => deflateRawSync(bytes, { level: 9 });
const bit = (bytes, i) => (bytes[i >> 3] >> (i & 7)) & 1;
const flip = (bytes, i) => { bytes[i >> 3] ^= 1 << (i & 7); };

function unzip(body, length) {
  const { buffer, engine } = inflateRawSync(body, { maxOutputLength: length, info: true });
  if (buffer.length !== length || engine.bytesWritten !== body.length) throw Error('Invalid DEFLATE page length');
  return buffer;
}

function putGap(out, n) {
  while (n >= 128) { out.push(128 | (n & 127)); n >>>= 7; }
  out.push(n);
}

// Strictly increasing positions. A bit exception implicitly means XOR 1;
// a byte exception carries one additional nonzero XOR mask.
function readPatches(body, pos, limit, byteMasks, put) {
  let index = -1;
  while (pos < body.length) {
    let gap = 0, shift = 0, b;
    do {
      if (pos >= body.length || shift > 14) throw Error('Invalid patch gap');
      b = body[pos++]; gap |= (b & 127) << shift; shift += 7;
    } while (b & 128);
    index += 1 + gap;
    if ((shift > 7 && !b) || index >= limit) throw Error('Patch outside page or noncanonical gap');
    if (byteMasks && (pos >= body.length || !body[pos])) throw Error('Missing XOR mask');
    put(index, byteMasks ? body[pos++] : 1);
  }
}

// Eight independent copy/flip bits per link, as in the viewer. First row
// grows east from the anchor; subsequent rows grow from the byte above.
function linksOf(data, stride) {
  const links = Buffer.alloc(data.length - 1);
  for (let i = 1; i < data.length; i++) links[i - 1] = data[i] ^ data[i < stride ? i - 1 : i - stride];
  return links;
}

function growLinks(seed, stride, links) {
  const data = Buffer.alloc(links.length + 1);
  data[0] = seed;
  for (let i = 1; i < data.length; i++) data[i] = data[i < stride ? i - 1 : i - stride] ^ links[i - 1];
  return data;
}

function readLinks(mode, body, length) {
  if (length < 2 || length > PAGE || body.length < 3 || body.length > length) throw Error('Invalid link page size');
  const stride = body.readUInt16LE(0);
  if (!stride || stride >= length) throw Error('Invalid link stride');
  const links = mode === 3 ? unzip(body.subarray(3), length - 1) : Buffer.alloc(length - 1);
  if (mode === 2) readPatches(body, 3, links.length, true, (i, mask) => { links[i] = mask; });
  return { stride, seed: body[2], links };
}

function growRows(length, width, rule, seed) {
  const out = Buffer.alloc(length);
  const rows = Math.floor(length * 8 / width);
  let above = new Uint8Array(width + 2), next = new Uint8Array(width + 2);
  if (seed) for (let x = 0; x < width; x++) above[x + 1] = bit(seed, x);
  else above[1 + Math.floor(width / 2)] = 1;
  for (let y = 0; y < rows; y++) {
    for (let x = 1; x <= width; x++) {
      if (above[x]) flip(out, y * width + x - 1);
      next[x] = (rule >> (4 * above[x - 1] + 2 * above[x] + above[x + 1])) & 1;
    }
    [above, next] = [next, above];
  }
  return out; // any partial last row is predicted zero, including padding bits
}

export function restorePage(mode, body, length) {
  if (tapeWindowMode(mode)) {
    if (!Number.isInteger(length) || length <= TEXT_WINDOW || length > TAPE_WINDOW || body.length > length) throw Error('Invalid template-window record');
    return restoreText(body, length, mode % 2 === 0, mode <= 12 ? '256-reset' : '256');
  }
  if (wideMode(mode)) {
    if (!Number.isInteger(length) || length <= PAGE || length > TEXT_WINDOW || body.length > Math.min(length, 65535)) throw Error('Invalid wide text record');
    return restoreText(body, length, mode % 2 === 0, mode <= 8 ? '64-reset' : '64');
  }
  if (!Number.isInteger(length) || length < 1 || length > PAGE || body.length > length) throw Error('Invalid page size');
  if (mode === 0 && body.length === length) return body;
  if (mode === 1) return unzip(body, length);
  if (mode === 5 || mode === 6) return restoreText(body, length, mode === 6);
  if ((mode === 2 || mode === 3) && body.length >= 3) {
    const { seed, stride, links } = readLinks(mode, body, length);
    return growLinks(seed, stride, links);
  }
  if (mode === 4 && body.length >= 4) {
    const width = body.readUInt16LE(0), literalSeed = body[3];
    if (width < 3 || width > 1024 || width * 2 > length * 8 || literalSeed > 1) throw Error('Invalid row recipe');
    const end = 4 + literalSeed * Math.ceil(width / 8);
    if (end > body.length) throw Error('Truncated seed row');
    const out = growRows(length, width, body[2], literalSeed ? body.subarray(4, end) : null);
    readPatches(body, end, length * 8, false, i => flip(out, i));
    return out;
  }
  throw Error('Invalid page instruction');
}

// For the Swarm backend: d[0] is the anchor and d[i] = byte[i] XOR byte[i-1].
// Convert north-link recipes to this edge basis *without growing the bytes*.
export function pageGradient(mode, body, length) {
  if (mode !== 2 && mode !== 3) {
    const d = Buffer.from(restorePage(mode, body, length));
    for (let i = length - 1; i > 0; i--) d[i] ^= d[i - 1];
    return d;
  }
  const { seed, stride, links } = readLinks(mode, body, length), d = Buffer.alloc(length);
  d[0] = seed;
  let across = 0;
  for (let i = 1; i < stride; i++) { d[i] = links[i - 1]; across ^= d[i]; }
  d[stride] = links[stride - 1] ^ across;
  // Across a rectangle the four edge XORs cancel. Walk the other three edges.
  for (let i = stride + 1; i < length; i++) d[i] = links[i - 1] ^ links[i - 2] ^ d[i - stride];
  return d;
}

function candidateStrides(data) {
  const strides = new Set([1, 2, 4, 8, 16, 32, 64, 128, 256]);
  const seen = new Map(), votes = new Map();
  for (let i = 0; i + 4 <= Math.min(data.length, 4096); i++) {
    const word = data.readUInt32LE(i), last = seen.get(word);
    if (last !== undefined) votes.set(i - last, 1 + (votes.get(i - last) ?? 0));
    seen.set(word, i);
  }
  for (const [stride] of [...votes].sort((a, b) => b[1] - a[1]).slice(0, 4)) strides.add(stride);
  return [...strides].filter(s => s < data.length).map(stride => {
    let misses = 0;
    for (let i = 1; i < Math.min(4096, data.length); i++) misses += Number(data[i] !== data[i < stride ? i - 1 : i - stride]);
    return { stride, misses };
  }).sort((a, b) => a.misses - b.misses).slice(0, 3);
}

// Vote on the output of each of the eight neighborhoods (the row-diagram
// experiment's inference step). Search widths, not an exhaustive program space.
function fitRows(bits, width) {
  const counts = new Uint32Array(16);
  const rows = Math.min(Math.floor(bits.length / width) - 1, Math.max(1, Math.floor(8192 / width)));
  for (let row = 0; row < rows * width; row += width) {
    const last = row + width - 1;
    let left = 0, center = bits[row];
    for (let i = row; i < last; i++) {
      const right = bits[i + 1];
      counts[(left << 3) | (center << 2) | (right << 1) | bits[i + width]]++;
      left = center;
      center = right;
    }
    counts[(left << 3) | (center << 2) | bits[last + width]]++;
  }
  let rule = 0, wrong = 0;
  for (let i = 0; i < 8; i++) {
    if (counts[2 * i + 1] > counts[2 * i]) rule |= 1 << i;
    wrong += Math.min(counts[2 * i], counts[2 * i + 1]);
  }
  return { width, rule, error: wrong / (width * rows) };
}

export function likelyText(data) {
  const n = Math.min(2048, data.length); let controls = 0;
  for (let i = 0; i < n; i++) {
    const b = data[i];
    if ((b < 32 && b !== 9 && b !== 10 && b !== 13) || b === 127) controls++;
  }
  return n >= 64 && controls * 20 <= n;
}

export function packPage(data, widthHint, text = 'span', textEncoder = packText) {
  if (!Buffer.isBuffer(data) || !data.length || data.length > PAGE) throw Error('Expected one nonempty data page');
  if (!textPolicies.includes(text)) throw Error('Text policy must be off, context or span');
  let best = { mode: 0, body: data };
  const offer = (mode, body) => { if (body.length < best.body.length) best = { mode, body }; };
  offer(1, zip(data));
  for (const { stride } of candidateStrides(data)) {
    const links = linksOf(data, stride), header = Buffer.from([stride & 255, stride >> 8, data[0]]);
    const sparse = []; let previous = -1;
    for (let i = 0; i < links.length && sparse.length + 3 < best.body.length; i++) if (links[i]) {
      putGap(sparse, i - previous - 1); sparse.push(links[i]); previous = i;
    }
    if (sparse.length + 3 < best.body.length) offer(2, Buffer.concat([header, Buffer.from(sparse)]));
    offer(3, Buffer.concat([header, zip(links)]));
  }

  const bits = new Uint8Array(8 * data.length);
  for (let i = 0; i < bits.length; i++) bits[i] = bit(data, i);
  const side = Math.floor(Math.sqrt(bits.length));
  const widths = new Set([side, side + 1, side - 1, 8, 16, 24, 31, 32, 48, 64, 65, 80, 96, 128, 256, 512, widthHint]);
  const fits = [...widths].filter(w => Number.isInteger(w) && w >= 3 && w <= 1024 && 2 * w <= bits.length)
    .map(w => fitRows(bits, w)).sort((a, b) => a.error - b.error);
  for (const fit of fits.filter((f, i) => (i < 3 && f.error <= 0.125) || f.width === widthHint)) {
    const { width, rule } = fit;
    const seed = Buffer.from(data.subarray(0, Math.ceil(width / 8)));
    if (width % 8) seed[seed.length - 1] &= (1 << (width % 8)) - 1;
    for (const first of [null, seed]) {
      const patches = [], header = Buffer.from([width & 255, width >> 8, rule, Number(Boolean(first))]);
      const base = 4 + (first?.length ?? 0);
      if (base >= best.body.length) continue;
      const prediction = growRows(data.length, width, rule, first);
      let previous = -1;
      for (let i = 0; i < data.length && base + patches.length < best.body.length; i++) {
        const mask = prediction[i] ^ data[i];
        if (!mask) continue;
        for (let b = 0; b < 8; b++) if ((mask >> b) & 1) {
          const index = 8 * i + b;
          putGap(patches, index - previous - 1); previous = index;
        }
      }
      if (base + patches.length < best.body.length) offer(4, Buffer.concat([header, ...(first ? [first] : []), Buffer.from(patches)]));
    }
  }
  if (text !== 'off' && best.body.length > 4 && likelyText(data)) {
    offer(text === 'span' ? 6 : 5, textEncoder(data, text === 'span'));
  }
  return best;
}
