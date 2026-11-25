// Optional physical replay on the *same* compiled Wasm NCA used by the viewer.
// The caller supplies its web/ directory. No source file or network is used.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { pageGradient } from './codec.mjs';

// Rolling XOR gives the north edge over one row; west is just the linear
// byte gradient. Padding repeats the last byte and is never emitted.
function tileEdges(gradient, at, n, side, previousByte) {
  const west = Buffer.alloc(side * side), north = Buffer.alloc(side * side);
  const delta = i => i === 0 ? previousByte ^ gradient[at] : i < n ? gradient[at + i] : 0;
  let window = 0;
  for (let i = 0; i < west.length; i++) {
    window ^= delta(i);
    if (i >= side) window ^= delta(i - side);
    north[i] = window;
    west[i] = i % side ? delta(i) : (i ? west[i - side] : 0) ^ north[i];
  }
  return { west, north };
}

// A damaged copy has no trustworthy mask. Certify only surviving bits
// connected to the known anchor by consistent edges. A flipped island
// cannot certify itself. The NCA then regrows the uncertified region.
function survivors(old, side, mask, origin, originByte, west, north) {
  const ready = new Uint8Array(side * side);
  ready[origin] = 1;
  if (!old?.length) return ready;
  const queue = [origin];
  const tryEdge = (to, prediction) => {
    if (to < old.length && !ready[to] && !((old[to] ^ prediction) & mask)) { ready[to] = 1; queue.push(to); }
  };
  for (let j = 0; j < queue.length; j++) {
    const i = queue[j], v = i === origin ? originByte : old[i];
    if (i % side) tryEdge(i - 1, v ^ west[i]);
    if (i % side + 1 < side) tryEdge(i + 1, v ^ west[i + 1]);
    if (i >= side) tryEdge(i - side, v ^ north[i]);
    if (i + side < ready.length) tryEdge(i + side, v ^ north[i + side]);
  }
  return ready;
}

export async function swarmAssembler(web) {
  const moduleAt = name => import(pathToFileURL(resolve(web, name)).href);
  const [{ initSync, Nca }, { compileRule30, RULE30_CELL: A, RULE30_READY: C, countRule30Pending }] =
    await Promise.all([moduleAt('pkg/swarm.js'), moduleAt('rule30.js')]);
  initSync({ module: readFileSync(resolve(web, 'pkg/swarm_bg.wasm')) });
  const opts = compileRule30(), rule = JSON.stringify(opts);
  // D/E are west/north edge flips; F is the signed origin register.
  const D = 3, E = 4, F = 5;
  const stats = { planes: 0, scheduledTicks: 0, initiallyReadyFileBits: 0, outputBits: 0 };
  const assemble = (mode, body, length, damaged) => {
    const gradient = pageGradient(mode, body, length), result = Buffer.alloc(length);
    for (let at = 0; at < length; at += 1024) {
      const n = Math.min(1024, length - at), side = Math.max(16, Math.ceil(Math.sqrt(n)));
      const { west, north } = tileEdges(gradient, at, n, side, at ? result[at - 1] : 0);
      const origin = Math.min(n - 1, Math.floor(side / 2) * (side + 1));
      let anchor = 0;
      for (let i = origin - origin % side; i <= origin; i++) anchor ^= west[i];
      const old = damaged?.subarray(at, at + n);
      for (let mask = 1; mask < 256; mask <<= 1) {
        const ready = survivors(old, side, mask, origin, anchor, west, north);
        const grid = new Nca(side, 0, rule);
        try {
          for (let i = 0; i < side * side; i++) {
            if (west[i] & mask) grid.paint(i, 0, true, D, 1);
            if (north[i] & mask) grid.paint(i, 0, true, E, 1);
            if ((i === origin ? anchor : old?.[i] ?? 0) & mask) grid.paint(i, 0, true, A, 1);
            if (ready[i]) grid.paint(i, 0, true, C, 1);
          }
          grid.paint(origin, 0, true, F, anchor & mask ? 1 : -1);
          let field = grid.snapshot();
          while (countRule30Pending(field) && grid.tick() < 2 * side) {
            grid.advance(Math.min(4, 2 * side - grid.tick())); field = grid.snapshot();
          }
          if (countRule30Pending(field)) throw Error('File lattice did not settle');
          for (let i = 0; i < n; i++) if (field[i * opts.channels + A]) result[at + i] |= mask;
          stats.planes++; stats.scheduledTicks += grid.tick(); stats.outputBits += n;
          stats.initiallyReadyFileBits += ready.subarray(0, n).reduce((a, b) => a + b, 0);
        } finally { grid.free(); }
      }
    }
    return result;
  };
  assemble.stats = stats;
  return assemble;
}
