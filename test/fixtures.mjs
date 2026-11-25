// Independent data generators. No rule, width, or stride hints enter the encoder.
export function diagram(width = 65, height = 65, noise = 0) {
  const out = Buffer.alloc(Math.ceil(width * height / 8));
  let row = new Uint8Array(width); row[width >> 1] = 1;
  for (let y = 0; y < height; y++) {
    const next = new Uint8Array(width);
    for (let x = 0; x < width; x++) {
      const i = y * width + x;
      out[i >> 3] |= row[x] << (i & 7);
      next[x] = (row[x - 1] ?? 0) ^ (row[x] | (row[x + 1] ?? 0));
    }
    row = next;
  }
  const rng = random(8), changed = new Set();
  while (changed.size < noise) changed.add(rng() % (width * height));
  for (const i of changed) out[i >> 3] ^= 1 << (i & 7);
  return out;
}

function random(seed) {
  let x = seed;
  return () => { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; return x >>> 0; };
}
export function noiseBytes(length) {
  const rng = random(731);
  return Buffer.from(Array.from({ length }, () => rng() & 255));
}
export function records() {
  const width = 53, height = 300, rng = random(17001), data = Buffer.alloc(width * height);
  const row = noiseBytes(width);
  for (let y = 0; y < height; y++) {
    if (y) row[rng() % width] ^= 1 << (rng() % 8);
    row.copy(data, width * y);
  }
  return data;
}
