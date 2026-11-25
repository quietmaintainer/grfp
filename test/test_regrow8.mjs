import assert from 'node:assert/strict';
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { DATA, FRAME, digest, frameKey, scanFrames } from '../src/frames.mjs';
import { recoverProtected } from '../src/protected.mjs';
import { cutCopy } from './loss-fixtures.mjs';

const fixtures = {
  alu: '181c90d3bd92e7634d8a6bb4e504f02e988c31a8906afc3886910c73954ec0bb',
  cpu: '1090e19324489dee52122af18efe19fdef496c92cb86415f756dedcd4d67263a',
};

for (const [name, originalHash] of Object.entries(fixtures)) {
  test(`recovers the published Regrow-8 ${name} after deleting its recipe frame`, t => {
    const dir = mkdtempSync(join(tmpdir(), 'grfp-regrow8-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const archive = new URL(`./regrow8/${name}.grfp`, import.meta.url);
    const fd = openSync(archive, 'r');
    let entry;
    try {
      const { catalog, entries } = scanFrames(fd);
      assert.equal(catalog.groups.length, 1);
      entry = entries.get(frameKey(DATA, 0));
    } finally {
      closeSync(fd);
    }

    const damaged = join(dir, 'damaged.grfp');
    cutCopy(archive, damaged, [[entry.at, FRAME + entry.n]]);
    const out = join(dir, 'recovered');
    const result = recoverProtected(damaged, out);
    assert.equal(result.recipeGroupsFromParity, 1);
    assert.equal(digest(readFileSync(join(out, 'restored.bin'))), originalHash);
    assert.deepEqual(readFileSync(join(out, 'protected.grfp')), readFileSync(archive));
  });
}
