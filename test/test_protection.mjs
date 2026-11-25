import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { parityShards,recoverShards } from '../src/parity.mjs';
import { scanFrames,FRAME,DATA,PARITY,frameKey,frameHeader } from '../src/frames.mjs';
import { packProtected,recoverProtected,protectExisting } from '../src/protected.mjs';
import { packFile } from '../src/archive.mjs';
import { GROUP } from '../src/groups.mjs';
import { noiseBytes } from './fixtures.mjs';

test('any three erasures among five unequal data and three parity shards are recoverable',()=>{
  const src=[1,5,75,303,1024].map((n,i)=>noiseBytes(n).map(b=>b^i)),par=[...parityShards(src,60)];
  for (let mask=0;mask<256;mask++) {
    const data=src.map((b,i)=>mask&(1<<i) ? null : b),p=new Map(par.map((b,i)=>[i,b]).filter(([i])=>!(mask&(1<<(i+5)))));
    const lost=data.filter(b=>!b).length;
    if (lost>p.size) assert.throws(()=>recoverShards(data,src.map(b=>b.length),p),/Insufficient/);
    else {assert.equal(recoverShards(data,src.map(b=>b.length),p),lost);assert.deepEqual(data,src);}
  }
  const full=Array.from({length:100},(_,i)=>Buffer.of(i,i^255));const allParity=[...parityShards(full,100)], none=Array(100).fill(null);
  assert.equal(recoverShards(none,full.map(b=>b.length),new Map(allParity.entries())),100);assert.deepEqual(none,full);
});

let dir,raw,pristine,inner,scan;const path=name=>join(dir,name),opts={text:'off',parityPercent:5};
function index(name) {const fd=fs.openSync(name,'r');try{return scanFrames(fd);}finally{fs.closeSync(fd);}}
function frame(type,i) {const e=scan.entries.get(frameKey(type,i));return [e.at,e.n+FRAME];}
function erase(bytes,ranges) {
  const pieces=[];let p=0;for (const [at,n] of [...ranges].sort((a,b)=>a[0]-b[0])) {pieces.push(bytes.subarray(p,at));p=at+n;}pieces.push(bytes.subarray(p));return Buffer.concat(pieces);
}
function verify(name,expected=pristine) {
  assert.deepEqual(fs.readFileSync(join(name,'restored.bin')),raw);
  assert.deepEqual(fs.readFileSync(join(name,'recipe.grf')),inner);
  assert.deepEqual(fs.readFileSync(join(name,'protected.grfp')),expected);
}
before(()=>{
  dir=fs.mkdtempSync(join(tmpdir(),'grfp-tests-'));
  raw=Buffer.concat([noiseBytes(GROUP),Buffer.alloc(GROUP,65),noiseBytes(GROUP).map(b=>97+b%24),Buffer.from('a short final group')]);
  fs.writeFileSync(path('in'),raw);packFile(path('in'),path('ordinary'),73,opts);inner=fs.readFileSync(path('ordinary'));
  packProtected(path('in'),path('wrapped'),73,opts);pristine=fs.readFileSync(path('wrapped'));scan=index(path('wrapped'));
});
after(()=>{if (dir) fs.rmSync(dir,{recursive:true,force:true});});

test('resynchronizes after a byte deletion and destroyed length field, with no source and only the tail catalog',()=>{
  const [at]=frame(DATA,0),bad=Buffer.from(pristine);bad.writeUInt32LE(0xffffffff,at+13);
  fs.writeFileSync(path('bad-frame'),erase(bad,[[0,at],[at+FRAME+18,1]]));
  const out=path('framed-out'),s=recoverProtected(path('bad-frame'),out);
  assert.equal(s.intactCatalogCopies,1);assert.equal(s.recipeGroupsFromParity,1);assert.equal(s.reusedOriginalPages,0);verify(out);
});

test('overlapping damage uses one reverse compilation and one parity shard; no incomplete output on failure',()=>{
  fs.writeFileSync(path('two-lost'),erase(pristine,[frame(DATA,0),frame(DATA,2)]));
  const fail=path('over-budget');assert.throws(()=>recoverProtected(path('two-lost'),fail),/2 recipe groups.*1 usable/);assert.ok(!fs.existsSync(fail));
  const old=Buffer.from(raw);old[GROUP+1]^=64;old[2*GROUP+1]^=128;fs.writeFileSync(path('mixed-old'),old);
  const out=path('hybrid-out'),s=recoverProtected(path('two-lost'),out,{damaged:path('mixed-old')});
  assert.deepEqual([s.recipeGroupsFromOriginal,s.recipeGroupsFromParity,s.rebuiltOriginalPages],[1,1,2]);verify(out);
  assert.throws(()=>recoverProtected(path('two-lost'),out),/already exists/);verify(out);
});

test('zero parity cross-repairs complementary groups and refuses a bad original group in the only surviving copy',()=>{
  const file=path('no-parity');const s=packProtected(path('in'),file,73,{...opts,parityPercent:0});assert.equal(s.parityFrames,0);
  const protectedBytes=fs.readFileSync(file),g=index(file).entries.get(frameKey(DATA,0));
  fs.writeFileSync(path('zero-broken'),erase(protectedBytes,[[g.at,g.n+FRAME]]));
  fs.writeFileSync(path('only-first'),raw.subarray(0,GROUP));const out=path('cross-out');
  const r=recoverProtected(path('zero-broken'),out,{damaged:path('only-first')});
  assert.deepEqual([r.recipeGroupsFromOriginal,r.recipeGroupsFromParity,r.reusedOriginalPages,r.replayedOriginalBytes],[1,0,16,raw.length-GROUP]);verify(out,protectedBytes);
  const wrong=Buffer.from(raw.subarray(0,GROUP));wrong[500]^=1;fs.writeFileSync(path('wrong'),wrong);
  assert.throws(()=>recoverProtected(path('zero-broken'),path('no-publish'),{damaged:path('wrong')}),/still missing/);assert.ok(!fs.existsSync(path('no-publish')));
});

test('a locally self-consistent but wrong parity equation cannot publish incorrect bytes',()=>{
  const [at,n]=frame(PARITY,0),body=Buffer.from(pristine.subarray(at+FRAME,at+n));body[0]^=1;
  const bad=Buffer.from(pristine),id=bad.subarray(at+17,at+49);frameHeader(PARITY,0,id,body).copy(bad,at);body.copy(bad,at+FRAME);
  fs.writeFileSync(path('stale'),erase(bad,[frame(DATA,0)]));
  const out=path('unverified');assert.throws(()=>recoverProtected(path('stale'),out),/group 0 checksum mismatch/);assert.ok(!fs.existsSync(out));
});

test('one surviving catalog suffices; absent or conflicting catalogs fail closed, including on empty input',()=>{
  const metaLength=frame(DATA,0)[0];fs.writeFileSync(path('no-catalog'),pristine.subarray(metaLength,-metaLength));
  assert.throws(()=>recoverProtected(path('no-catalog'),path('none'),{damaged:path('in')}),/No intact.*catalog/);
  fs.writeFileSync(path('empty'),Buffer.alloc(0));packProtected(path('empty'),path('empty-grfp'),undefined,{parityPercent:5});
  const empty=fs.readFileSync(path('empty-grfp'));fs.writeFileSync(path('one-copy'),empty.subarray(0,empty.length/2));
  const r=recoverProtected(path('one-copy'),path('empty-out'));assert.equal(r.intactCatalogCopies,1);assert.equal(r.groups,0);
  assert.deepEqual(fs.readFileSync(path('empty-out/protected.grfp')),empty);
  fs.writeFileSync(path('ambiguous'),Buffer.concat([pristine,empty]));
  assert.throws(()=>recoverProtected(path('ambiguous'),path('amb-out')),/multiple.*catalogs/);assert.ok(!fs.existsSync(path('amb-out')));
});

test('protection retrofits an ordinary GRF1 exactly and rejects incorrect encoder settings',()=>{
  protectExisting(path('ordinary'),path('converted'),73,opts);assert.deepEqual(fs.readFileSync(path('converted')),pristine);
  const html=new URL('./viewer-html.grf',import.meta.url);assert.throws(()=>protectExisting(html,path('wrong-profile'),undefined,opts),/profile does not reproduce/);
  assert.ok(!fs.existsSync(path('wrong-profile')));
  for (const parityPercent of [-1,101,0.5]) assert.throws(()=>packProtected(path('in'),path('invalid'),undefined,{parityPercent}),/Parity must/);
});
