// Window-local byte recipes. All prediction state, including copy offsets,
// is rebuilt from the bytes already restored in the current window.
import { correctVote } from './expert.mjs';
const SCALE = 32768, LOWER = 1 << 23, ORDER = 4;
export const TEXT_PAGE = 16384, TEXT_WINDOW = 4 * TEXT_PAGE, TAPE_WINDOW = 4 * TEXT_WINDOW;
export const LONG_WINDOW = 16*TAPE_WINDOW;
const sizes = {'16':TEXT_PAGE, '64-reset':TEXT_WINDOW, '64':TEXT_WINDOW, '256-reset':TAPE_WINDOW, '256':TAPE_WINDOW,
  '1024':4*TAPE_WINDOW,'4096':LONG_WINDOW};
export const textWindows = ['16', '64-reset', '64', '256-reset', '256'];
const scaled = (v, total) => Math.floor(v * SCALE / total);

class Writer {
  constructor(length) { this.events = new Uint32Array(length * (length>TAPE_WINDOW ? 2 : ORDER+2)); this.used = 0; }
  take(lo, mass, total) {
    if (mass === total) return;
    const start = scaled(lo, total), width = scaled(lo + mass, total) - start;
    if (this.used===this.events.length) {const a=new Uint32Array(this.used*2);a.set(this.events);this.events=a;}
    this.events[this.used++] = start * 65536 + width;
  }
}

// Independent predictor traces can share a single rANS state. This lets the
// framing control use exactly the probabilities of four separate short pages.
export function encodeTextEvents(traces) {
  let x = LOWER; const bytes = [];
  for (let k = traces.length - 1; k >= 0; k--) {
    const events = traces[k];
    for (let j = events.length - 1; j >= 0; j--) {
      const op = events[j], width = op & 65535;
      while (x >= width * 65536) { bytes.push(x & 255); x >>>= 8; }
      x = Math.floor(x / width) * SCALE + (x % width) + (op >>> 16);
    }
  }
  const body = Buffer.allocUnsafe(4 + bytes.length); body.writeUInt32LE(x);
  for (let j = 0; j < bytes.length; j++) body[j + 4] = bytes[bytes.length - 1 - j];
  return body;
}

class Reader {
  constructor(body) {
    if (body.length < 4) throw Error('Truncated text recipe');
    this.x = body.readUInt32LE(); this.pos = 4; this.body = body;
    if (this.x < LOWER || this.x >= LOWER * 256) throw Error('Invalid text recipe state');
  }
  peek(total) { return Math.floor((((this.x % SCALE) + 1) * total - 1) / SCALE); }
  take(lo, mass, total) {
    if (mass === total) return;
    const start = scaled(lo, total), width = scaled(lo + mass, total) - start;
    this.x = width * Math.floor(this.x / SCALE) + this.x % SCALE - start;
    while (this.x < LOWER) {
      if (this.pos === this.body.length) throw Error('Truncated text recipe stream');
      this.x = this.x * 256 + this.body[this.pos++];
    }
  }
  finish() {
    if (this.x !== LOWER || this.pos !== this.body.length) throw Error('Text recipe end-state or length mismatch');
  }
}

// A lexical anchor is a run of ASCII letters, digits or underscores followed
// by a delimiter. Remember the last continuation of each (folded word, exact
// delimiter) hash. Even a hash collision is lossless: it is just a bad guess.
const wordByte = b => (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || (b >= 48 && b <= 57) || b === 95;
class Span {
  constructor() {
    this.last = new Map(); this.hash = 0; this.len = 0; this.from = -1; this.run = 0;
    this.hits = new Uint16Array(20); this.trials = new Uint16Array(20); this.bin = -1;
  }
  bucket(mass, total) {
    const tier = this.run === 0 ? 0 : this.run < 3 ? 1 : this.run < 8 ? 2 : 3;
    return this.bin = tier * 5 + (mass === 0 ? 0 : mass * 16 < total ? 1 : mass * 4 < total ? 2 : mass * 4 < 3 * total ? 3 : 4);
  }
  bonus(mass, total) {
    const b=this.bucket(mass,total);
    const hits = this.hits[b] + 1, misses = this.trials[b] - this.hits[b] + 2;
    // Raise the candidate's probability towards its observed success rate.
    // Merge with its existing mass; don't charge a second flag for a match.
    return Math.max(0, Math.min(SCALE - total, 32 * total, Math.floor((hits * total - (hits + misses) * mass) / misses)));
  }
  observe(bytes, i, b) {
    if (this.from >= 0) {
      const hit = bytes[this.from] === b;
      if (this.bin >= 0) {
        if (this.trials[this.bin] >= 256) { this.trials[this.bin] >>= 1; this.hits[this.bin] >>= 1; }
        this.trials[this.bin]++; this.hits[this.bin] += Number(hit); this.bin = -1;
      }
      if (hit) { this.from++; this.run++; } else { this.from = -1; this.run = 0; }
    }
    if (wordByte(b)) {
      this.hash = (Math.imul(this.hash, 16777619) ^ (b >= 65 && b <= 90 ? b + 32 : b)) >>> 0; this.len++;
    } else {
      if (this.len >= 2) {
        const key = (Math.imul(this.hash, 257) ^ b) >>> 0;
        if (this.from < 0 || !this.run) { this.from = this.last.get(key) ?? -1; this.run = 0; }
        this.last.set(key, i + 1);
      }
      this.hash = 0; this.len = 0;
    }
  }
}

// An order-4 suffix model is the control. For each context, PPM-D gives an
// observed byte mass 2*count-1; the escape mass is the number of alternatives.
// Escaped alternatives are excluded from shorter contexts, down to literals.
function stepper(bytes,copies,prior,expert,observe) {
  const adjust=expert?.strength || observe;
  const initial=prior?.count??0,limit = initial+2 + (ORDER + 1) * bytes.length;
  let cap = bytes.length>TAPE_WINDOW ? initial+Math.ceil(bytes.length/3) : limit;
  let child = new Uint32Array(cap), sibling = new Uint32Array(cap), symbol = new Uint8Array(cap);
  let freq = bytes.length > TEXT_PAGE ? new Uint32Array(cap) : new Uint16Array(cap);
  function grow() {
    cap=Math.min(limit,cap*2);
    function copy(a) {const b=new a.constructor(cap);b.set(a);return b;}
    child=copy(child);sibling=copy(sibling);symbol=copy(symbol);freq=copy(freq);
  }
  const history = new Uint32Array(ORDER + 1), roots = new Uint32Array(256);
  const excluded = new Uint32Array(256), syms = new Uint8Array(256), masses = new Uint32Array(256);
  const span = copies ? new Span() : null;
  if(prior){child.set(prior.child);sibling.set(prior.sibling);symbol.set(prior.symbol);freq.set(prior.freq);roots.set(prior.roots);}
  let nodes = initial+1, pos=0; history[0] = 1;
  return function advance(end,io,decoding) {
  for (let i = pos; i < end; i++) {
    const depth = Math.min(i, ORDER), tag = i + 1;
    let value = bytes[i], done = false, skipped = 0;
    let candidate = span && span.from >= 0 ? bytes[span.from] : -1;
    // Known bytes need trie learning and span calibration only. No entropy
    // arithmetic, backoffs, exclusion passes or literal ranks are needed.
    for (let k = io || candidate>=0 ? depth : -1; k >= 0; k--) {
      let n = 0, sum = 0, candidateSlot = -1;
      for (let j = child[history[k]]; j; j = sibling[j]) {
        const v = symbol[j];
        if (excluded[v] === tag) continue;
        if (v === candidate) candidateSlot = n;
        syms[n] = v; masses[n] = 2 * freq[j] - 1; sum += masses[n++];
      }
      if (!n) continue;
      let escape = n;
      // A long-lived context may exceed the rANS scale. Quantize only the
      // current vote, retaining the learned counts and a positive mass for
      // each possibility. A 16 KiB predictor never takes this branch.
      while (sum + escape > SCALE) {
        sum = 0;
        for (let j = 0; j < n; j++) { masses[j] = (masses[j] + 1) >>> 1; sum += masses[j]; }
      }
      const offered=candidate;let boosted=false;
      if (candidate >= 0) {
        if(!io){span.bucket(candidateSlot<0 ? 0 : masses[candidateSlot],sum+escape);break;}
        const extra = span.bonus(candidateSlot < 0 ? 0 : masses[candidateSlot], sum + escape);
        if (extra) {
          boosted=true;
          if (candidateSlot < 0) { syms[n] = candidate; masses[n++] = extra; }
          else masses[candidateSlot] += extra;
          sum += extra;
        }
        candidate = -1;
      }
      if(adjust && io){const v=correctVote(expert,observe,i?bytes[i-1]:0,k,skipped!==0,offered,boosted,syms,masses,n,sum,escape,value);sum=v&65535;escape=v>>>16;}
      const total = sum + escape, target = decoding ? io.peek(total) : -1;
      let lo = 0;
      for (let j = 0; j < n; j++) {
        if (decoding ? target < lo + masses[j] : value === syms[j]) {
          value = syms[j]; io.take(lo, masses[j], total); done = true; break;
        }
        lo += masses[j];
      }
      if (done) break;
      io.take(sum, escape, total); skipped += n;
      for (let j = 0; j < n; j++) excluded[syms[j]] = tag;
    }
    if (!done && io) {
      const left = 256 - skipped;
      if (left < 1) throw Error('Impossible text recipe escape');
      const target = decoding ? io.peek(left) : -1;
      let rank = 0;
      for (let v = 0; v < 256; v++) if (excluded[v] !== tag) {
        if (decoding ? rank === target : v === value) { value = v; break; }
        rank++;
      }
      io.take(rank, 1, left);
    }
    if (decoding) bytes[i] = value;
    span?.observe(bytes, i, value);
    // Walk from longest suffix down so each update uses the old history.
    let learn = true;
    for (let k = depth; k >= 0; k--) {
      const parent = history[k];
      let j = k ? child[parent] : roots[value];
      while (j && symbol[j] !== value) j = sibling[j];
      if (!j) {
        j = ++nodes; if (j===cap) grow(); symbol[j] = value; sibling[j] = child[parent]; child[parent] = j;
        if (!k) roots[value] = j;
      }
      // Update exclusion: shorter contexts learn the exceptions that reach
      // them, rather than counting every match already known further up.
      if (!freq[j]) freq[j] = 1;
      else if (learn) { freq[j]++; learn = false; }
      if (k < ORDER) history[k + 1] = j;
    }
  }
  pos=end;
  };
}
function run(bytes,io,copies,decoding){stepper(bytes,copies)(bytes.length,io,decoding);}

// Predict one continuous instruction tape; only rANS is restarted per frame.
// Warm-up must consume the SAME transformed symbols as encode/decode.
export function frameModel(length,prior,expert) {
  if(!Number.isInteger(length)||length<1||length>LONG_WINDOW)throw Error('Invalid predictor history length');
  const tape=Buffer.alloc(length),advance=stepper(tape,true,prior,expert);let pos=0;
  function end(n){if(!Number.isInteger(n)||n<1||n>TAPE_WINDOW||n>length-pos)throw Error('Invalid predictor frame length');return pos+n;}
  function events(b){const next=end(b.length),w=new Writer(b.length);tape.set(b,pos);advance(next,w,false);pos=next;return w.events.subarray(0,w.used);}
  return {events,encode:b=>encodeTextEvents([events(b)]),
    warm(b){const next=end(b.length);tape.set(b,pos);advance(next,null,false);pos=next;},
    decode(body,n){const next=end(n),r=new Reader(body);advance(next,r,true);r.finish();const b=tape.subarray(pos,next);pos=next;return b;},
    close(){} };
}

export function observeVotes(tape,observer) {
  if(!tape.length || tape.length>LONG_WINDOW)throw Error('Invalid training checkpoint');
  stepper(tape,true,undefined,undefined,observer)(tape.length,{take(){}},false);
}

export function textEvents(bytes, copies) {
  if (bytes.length < 1 || bytes.length > LONG_WINDOW) throw Error('Invalid text page length');
  const writer = new Writer(bytes.length);
  run(bytes, writer, copies, false);
  return writer.events.subarray(0, writer.used);
}

function predictionStep(length, window) {
  if (typeof window!=='string' || !Object.hasOwn(sizes,window) || !Number.isInteger(length) || length < 1 || length > sizes[window]) throw Error('Invalid text page length');
  return window === '256-reset' ? TEXT_WINDOW : window === '64-reset' ? TEXT_PAGE : length;
}

export function packText(bytes, copies, window = '16') {
  const step = predictionStep(bytes.length, window), traces = [];
  for (let i = 0; i < bytes.length; i += step) traces.push(textEvents(bytes.subarray(i, i + step), copies));
  return encodeTextEvents(traces);
}

export function restoreText(body, length, copies, window = '16') {
  const step = predictionStep(length, window);
  const reader = new Reader(body), bytes = Buffer.alloc(length);
  for (let i = 0; i < length; i += step) run(bytes.subarray(i, i + step), reader, copies, true);
  reader.finish();
  return bytes;
}
