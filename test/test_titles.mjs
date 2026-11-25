import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { packFile, inspectFile, restoreFile } from '../src/archive.mjs';
import { PAGE } from '../src/codec.mjs';
import { GROUP, groupChoices, chooseGroup, parseGroup, restoreGroup } from '../src/groups.mjs';
import { templateTape, expandTape } from '../src/templates.mjs';
import { bindTitles, expandTitles } from '../src/titles.mjs';
import { swarmAssembler } from '../src/swarm.mjs';

function places(n) {
  let x = 701, size = 0; const rows = [];
  const name = () => Array.from({length:12}, () => { x = (Math.imul(x, 1664525) + 1013904223) >>> 0; return String.fromCharCode(97 + ((x >>> 16) % 26)); }).join('');
  while (size < n) {
    const town = name(), state = name();
    const row = `<page>\n  <title>${town}, ${state}</title>\n  <id>${x}</id>\n` +
      `'''${town}''' is a town in [[${state}]]. Its full name is [[${town}, ${state}|${town}]].\n` +
      `A report for ${town} lists 0012 families and 07 stores in ${state}.\n[[Category:Towns in ${state}]]\n</page>\n`;
    rows.push(row); size += row.length;
  }
  return Buffer.from(rows.join('')).subarray(0,n);
}

test('longest literal title match, exact spelling, and independent full/place/qualifier bindings', () => {
  const prefix = 'Mayfield before header\n<page>\r\n  <title>Mayfield, Kentucky</title>\r\n';
  const line = 'Mayfield, Kentucky / Mayfield / Kentucky / Mayfielder / mayfield / xKentucky\n';
  const tail = '</page>\nMayfield, Kentucky', raw = Buffer.from(prefix + line + tail);
  const all = bindTitles(raw);
  assert.deepEqual(all.bytes,Buffer.from(prefix+'\xfc / \xfd / \xfe / Mayfielder / mayfield / xKentucky\n'+tail,'latin1'));
  assert.deepEqual(all.uses,[1,1,1]); assert.deepEqual(expandTitles(all.bytes,raw.length),raw);
  const full = bindTitles(raw,true);
  assert.deepEqual(full.uses,[1,0,0]); assert.deepEqual(expandTitles(full.bytes,raw.length),raw);
});

test('entity bytes, UTF-8, literal marker bytes, parentheses and digits inside a title survive both transforms', () => {
  const raw = Buffer.concat([Buffer.from('<page>\n<title>Café 012 &amp; Co. (Québec)</title>\nCafé 012 &amp; Co. (Québec) / Québec / Café 012 &amp; Co.\n'),
    Buffer.of(251,252,253,254,255,0,10),Buffer.from('</page>\n<title>São, County, Region</title>\nSão, County, Region / São / Region')]);
  const bound = bindTitles(raw); assert.deepEqual(bound.uses,[2,2,2]);
  const tape = templateTape(bound.bytes,'title');
  const intermediate = expandTape(tape.bytes,'title',bound.bytes.length);
  assert.deepEqual(intermediate,bound.bytes); assert.deepEqual(expandTitles(intermediate,raw.length),raw);
});

test('a learned skeleton inserts the new article’s name and still copies exact numeric strings', () => {
  const entry = (p, s, qty) => `<page>\n<title>${p}, ${s}</title>\nThe town of ${p} is in ${s}.\nFor ${p} the count was ${qty}.\n</page>\n`;
  const raw = Buffer.from(entry('Elk Lake','Michigan','001') + entry('Twin Lake','Colorado','08000'));
  const bound = bindTitles(raw), tape = templateTape(bound.bytes,'title');
  assert.equal(tape.refs,2, 'both the name-only and one-number skeleton are reused');
  assert.deepEqual(expandTitles(expandTape(tape.bytes,'title',bound.bytes.length),raw.length),raw);
});

test('no binding from outside a checkpoint or a previous page; malformed marker streams reject', () => {
  assert.equal(bindTitles(Buffer.from('field\nSomewhere, Northland\n')),null);
  const title = Buffer.from('<title>Somewhere, Northland</title>\n');
  for (const control of ['</page>\n','<page>\n','<title>incomplete\n','<title>'+ 'x'.repeat(1025) +'</title>\n']) {
    assert.throws(()=>expandTitles(Buffer.concat([title,Buffer.from(control),Buffer.of(253)]),2048),/without a current binding/);
  }
  for (const bad of [Buffer.of(251),Buffer.of(251,1),Buffer.of(252),Buffer.of(254),
    Buffer.concat([title,Buffer.from('<title>'),Buffer.of(252),Buffer.from('</title>\n')])]) {
    assert.throws(()=>expandTitles(bad,128),/title/i);
  }
  assert.throws(()=>expandTitles(Buffer.concat([title,Buffer.of(252)]),title.length),/exceeds/);
});

test('group costing includes both lengths and original hashes; rejects invalid intermediate lengths', () => {
  const raw = places(4*PAGE+19), trials = groupChoices(raw,undefined,'span','auto');
  assert.ok(trials.full && trials.title);
  const sizes = ['numeric','full-title','auto'].map(policy=>chooseGroup(trials,policy).bytes.length);
  assert.ok(sizes[0] >= sizes[1] && sizes[1] > sizes[2]);
  for (const key of ['full','title']) {
    const wire = trials[key].bytes, group = parseGroup(wire,raw.length);
    assert.equal(wire[0],130); assert.equal(group.wireBytes,wire.length); assert.equal(group.hashes.length,5);
    assert.deepEqual(restoreGroup(group).bytes,raw);
  }
  for (const bound of [0,raw.length*2+1]) {
    const bad = Buffer.from(trials.title.bytes); bad.writeUInt32LE(bound,5);
    assert.throws(()=>parseGroup(bad,raw.length),/binding length/);
  }
  const bad = Buffer.from(trials.title.bytes); bad.writeUInt32LE(3*bad.readUInt32LE(5)+1,1);
  assert.throws(()=>parseGroup(bad,raw.length),/tape length/);
});

test('mixed archives repair a page containing title definitions without trusting damaged name bytes', t => {
  const dir=fs.mkdtempSync(join(tmpdir(),'grf-title-test-')); t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const p=n=>join(dir,n), raw=Buffer.concat([places(GROUP),Buffer.from('no title header in this new checkpoint\n')]);
  fs.writeFileSync(p('in'),raw); const packed=packFile(p('in'),p('r')); fs.unlinkSync(p('in'));
  assert.deepEqual(packed.groupMethods,{title:1,plain:1}); assert.equal(inspectFile(p('r')).groupMethods.title,1);
  restoreFile(p('r'),p('out')); assert.deepEqual(fs.readFileSync(p('out')),raw);
  const damaged=Buffer.from(raw); damaged.fill(0,10,900);fs.writeFileSync(p('damaged'),damaged);
  const repair=restoreFile(p('r'),p('fixed'),{damaged:p('damaged')});
  assert.deepEqual([repair.rebuiltPages,repair.reusedPages,repair.replayedBytes],[1,16,GROUP]);
  assert.deepEqual(fs.readFileSync(p('fixed')),raw); assert.deepEqual(fs.readFileSync(p('damaged')),damaged);
});

test('actual Swarm lattice restores and repairs the file described by title slots', {skip:!process.env.SWARM_WEB}, async () => {
  const raw=places(4096), c=chooseGroup(groupChoices(raw,undefined,'span','auto'),'auto');
  assert.equal(c.kind,'title'); const group=parseGroup(c.bytes,raw.length), assemble=await swarmAssembler(process.env.SWARM_WEB);
  assert.deepEqual(restoreGroup(group,undefined,assemble).bytes,raw);
  const damaged=Buffer.from(raw.subarray(0,-11));damaged[97]^=192;
  assert.deepEqual(restoreGroup(group,damaged,assemble).bytes,raw);
});
