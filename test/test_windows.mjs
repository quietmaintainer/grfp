import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PAGE, restorePage, wideMode } from '../src/codec.mjs';
import { TEXT_WINDOW as WIDE, packText, restoreText } from '../src/text.mjs';
import { groupWindowChoices, parseGroup, restoreGroup } from '../src/groups.mjs';
import { packFile, restoreFile, inspectFile } from '../src/archive.mjs';
import { noiseBytes } from './fixtures.mjs';
import { swarmAssembler } from '../src/swarm.mjs';

// Few repeated spans within the first page, but a perfect earlier example
// across the old checkpoint. No external dictionary or seed is supplied.
const paragraph = noiseBytes(PAGE).map(b => 97 + b % 26);
const repeated = Buffer.concat(Array(4).fill(paragraph));

test('full 64 KiB entropy streams handle rare symbols after large counts and the final exclusion tag', () => {
  const rare = Buffer.alloc(WIDE, 97);
  for (const [p,b] of [[31000,0],[49000,255],[65533,97],[65534,98],[65535,253]]) rare[p] = b;
  for (const bytes of [rare, noiseBytes(WIDE), repeated.subarray(0,PAGE+1), repeated]) {
    for (const copies of [false,true]) for (const window of ['64-reset','64']) {
      const body = packText(bytes,copies,window);
      assert.deepEqual(restoreText(body,bytes.length,copies,window),bytes);
      if (body.length <= Math.min(bytes.length,65535)) {
        const mode = (window === '64' ? 9 : 7) + Number(copies);
        assert.deepEqual(restorePage(mode,body,bytes.length),bytes);
        assert.throws(()=>restorePage(mode,body.subarray(0,-1),bytes.length));
      }
    }
  }
});

test('one rANS frame gives little benefit on the repeated fixture unless the predictor can remember earlier pages', () => {
  const short = packText(paragraph,true), reset = packText(repeated,true,'64-reset'), long = packText(repeated,true,'64');
  assert.ok(Math.abs(4*short.length - reset.length) < 32);
  assert.ok(long.length < reset.length * 0.6);
  assert.deepEqual(restoreText(long,WIDE,true,'64'),repeated);
});

test('raw mixed-width archive preserves page hashes and replays each damaged record just once', t => {
  const dir=fs.mkdtempSync(join(tmpdir(),'grf-window-')); t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const p=n=>join(dir,n), raw=Buffer.concat([repeated, noiseBytes(WIDE), repeated.subarray(0,2*PAGE+19)]);
  fs.writeFileSync(p('in'),raw);
  const short=packFile(p('in'),p('short'),undefined,{templates:'off',textWindow:'16'});
  const wide=packFile(p('in'),p('wide'),undefined,{templates:'off',textWindow:'64'});
  assert.ok(wide.recipeBytes < short.recipeBytes); assert.equal(wide.pages,11); assert.equal(wide.methods['text-span-64'],2);
  const decoded=inspectFile(p('wide')); assert.equal(decoded.examples['literal'].page,4);
  assert.equal(decoded.examples['text-span-64'].bytes,WIDE);
  fs.unlinkSync(p('in'));
  restoreFile(p('wide'),p('all')); assert.deepEqual(fs.readFileSync(p('all')),raw);
  const bad=Buffer.from(raw); for (const i of [PAGE+7,3*PAGE+1,WIDE+2*PAGE+3]) bad[i]^=123;
  fs.writeFileSync(p('bad'),bad);
  for (const [name,replay] of [['wide',WIDE+PAGE],['short',3*PAGE]]) {
    const s=restoreFile(p(name),p(`${name}.out`),{damaged:p('bad')});
    assert.deepEqual([s.rebuiltPages,s.reusedPages,s.replayedBytes,s.decodedTapeBytes],[3,8,replay,replay]);
    assert.deepEqual(fs.readFileSync(p(`${name}.out`)),raw);
  }
  const s=restoreFile(p('wide'),p('copy'),{damaged:p('all')}); assert.equal(s.replayedBytes,0);
});

test('template tape can mix wide text and partial pages while retaining original-group repair bounds', () => {
  const head=Buffer.from('<page>\n<title>Mayfield, Kentucky</title>\nMayfield is in Kentucky.\n');
  const row=(a,b,c)=>Buffer.from(`\nThe official row of digits for Mayfield, Kentucky: value ${a}, verified ${b}, count ${c}.\n`);
  const raw=Buffer.concat([head,repeated,repeated.subarray(0,923),row(123,45,6),row('000','07','098'),Buffer.from('</page>\n')]);
  const trials=groupWindowChoices(raw,undefined,'span','auto',['16','64-reset','64']);
  for (const window of ['16','64-reset','64']) {
    const wire=trials[window].title.bytes, g=parseGroup(wire,raw.length);
    assert.equal(g.hashes.length,Math.ceil(raw.length/PAGE));
    if (window === '64') assert.ok(g.records.some(r=>wideMode(r.mode)));
    const damaged=Buffer.from(raw); damaged[PAGE+33]^=18;
    const r=restoreGroup(g,damaged); assert.deepEqual(r.bytes,raw);
    assert.deepEqual([r.rebuiltPages,r.replayedBytes,r.decodedTapeBytes],[1,raw.length,g.tapeLength]);
  }
});

test('bad wide framing is rejected; raw or link fallbacks keep the old bytes on incompressible/non-text windows', () => {
  const raw=noiseBytes(WIDE), trial=groupWindowChoices(raw,undefined,'span','off',['16','64']);
  assert.deepEqual(trial['16'].plain.bytes,trial['64'].plain.bytes);
  assert.throws(()=>parseGroup(Buffer.of(10),PAGE), /alignment or length/);
  assert.throws(()=>parseGroup(Buffer.concat([trial['16'].plain.bytes.subarray(0,19+PAGE),Buffer.of(10)]),2*WIDE), /alignment or length/);
  for (const n of [PAGE-1,PAGE,WIDE+1]) assert.throws(()=>restorePage(10,Buffer.alloc(5),n), /wide text record/);
  assert.throws(()=>restorePage(10,Buffer.alloc(WIDE),WIDE), /wide text record/);
  const wide=groupWindowChoices(repeated,undefined,'span','off',['64'])['64'].plain.bytes;
  assert.throws(()=>parseGroup(wide.subarray(0,-1),WIDE),/Truncated/);
});

test('Swarm repairs the affected original page of a wide record using the intact recipe', {skip:!process.env.SWARM_WEB}, async () => {
  const raw=repeated.subarray(0,2*PAGE+223), c=groupWindowChoices(raw,undefined,'span','off',['64'])['64'].plain;
  const g=parseGroup(c.bytes,raw.length); assert.equal(g.records[0].mode,10);
  const bad=Buffer.from(raw); bad[2*PAGE+7]^=31;
  const assemble=await swarmAssembler(process.env.SWARM_WEB), r=restoreGroup(g,bad,assemble);
  assert.deepEqual(r.bytes,raw); assert.deepEqual([r.rebuiltPages,r.reusedPages,r.replayedBytes],[1,2,raw.length]);
  assert.equal(assemble.stats.outputBits,223*8);
});
