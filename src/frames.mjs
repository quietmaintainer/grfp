// GRP1 outer frames. No recovery decision depends on the byte offsets that
// frames had before the damage. The catalog is replicated at both ends.
import * as fs from 'node:fs';
import { createHash } from 'node:crypto';
import { packingProfile } from './archive.mjs';
import { GROUP } from './groups.mjs';
import { PAGE } from './codec.mjs';
import { STRIPE,parityCount } from './parity.mjs';
import { check16,decode16,even16,LIMIT16 } from './rs16.mjs';
import { parseLongHeader } from './long.mjs';
import { maxWire } from './long-record.mjs';
import { MAX_PRIOR } from './prior.mjs';

const SYNC=Buffer.from('GRP1\r\n\x1a\n','latin1');
export const FRAME=81, META=0, DATA=1, PARITY=2, MAX_GROUPS=65536;
export const GLOBAL_DATA=3, GLOBAL_PARITY=4, GLOBAL='global16';
const CAT_BLOCK=65536;
const MAX_META=16*1024*1024, MAX_BODY=GROUP+19*(GROUP/PAGE);
export const LONG_ENCODER='grl-checkpoint-v1';
const MAX_LONG_BODY=4+maxWire(4194304,{p:4096,t:256,restart:true});
export const sha=()=>createHash('sha256');
export const digest=b=>sha().update(b).digest('hex');
const isHash=h=>typeof h==='string' && /^[0-9a-f]{64}$/.test(h);
export const frameKey=(type,index)=>`${type}:${index}`;
export const coord=(d,i)=>d*65536+i; // high word is geometry, even without a catalog
export function readAt(fd,pos,n) {
  const b=Buffer.allocUnsafe(n); let used=0;
  while (used<n) { const got=fs.readSync(fd,b,used,n-used,pos+used); if (!got) break; used+=got; }
  return b.subarray(0,used);
}
export function checkPercent(percent) {
  if (!Number.isInteger(percent) || percent<0 || percent>100) throw Error('Parity must be a whole percentage from 0 to 100');
}

export function frameHeader(type,index,id,body) {
  const h=Buffer.alloc(FRAME); SYNC.copy(h); h[8]=type; h.writeUInt32LE(index,9); h.writeUInt32LE(body.length,13); id.copy(h,17);
  sha().update(h.subarray(8,49)).update(body).digest().copy(h,49); return h;
}
export function validateCatalog(m) {
  if (m?.format!=='GRP1' || !['grf1-group-v1',LONG_ENCODER].includes(m.encoder) || (m.stripe!==STRIPE && m.stripe!==GLOBAL) || !isHash(m.originalSha256) || !isHash(m.grfFooter) ||
      !Number.isSafeInteger(m.bytes) || m.bytes<0 || !Array.isArray(m.groups)) throw Error('Invalid GRP1 catalog');
  checkPercent(m.percent);
  const p=m.profile;let c;
  if(m.encoder===LONG_ENCODER)c=longGeometry(m).c;
  else {if (!p || !['width','text','templates','textWindow'].every(k=>Object.hasOwn(p,k))) throw Error('Incomplete GRP1 encoder profile');packingProfile(p.width ?? undefined,p);}
  const step=c?.checkpoint??GROUP;if(m.bytes>step*MAX_GROUPS || m.groups.length!==Math.ceil(m.bytes/step))throw Error('Invalid catalog group count');
  for (const [i,g] of m.groups.entries()) {
    const n=Math.min(step,m.bytes-i*step),limit=c?4+maxWire(n,c):n+19*Math.ceil(n/PAGE);
    if (!Array.isArray(g) || g.length!==3 || !Number.isInteger(g[0]) || g[0]<1 || g[0]>limit || !isHash(g[1]) || !isHash(g[2])) throw Error('Invalid catalog group');
  }
}
export const protectableLong=c=>c.restart || (c.p===256 && c.t===256); // the old 256/256 control already has independent frames
export function longGeometry(m){const s=m.profile?.header;
  if(m.stripe!==GLOBAL || typeof s!=='string' || s.length>4*Math.ceil((50+MAX_PRIOR)/3))throw Error('Invalid protected long profile');
  const h=Buffer.from(s,'base64');if(h.toString('base64')!==s)throw Error('Invalid protected model/header encoding');
  const g=parseLongHeader(h);if(g.size!==m.bytes || !protectableLong(g.c))throw Error('Expected matching restartable archive header');return g;
}

export function globalLayout(m,meta) {
  if(!meta.length || meta.length>MAX_META)throw Error('Invalid global catalog length');
  const len=Buffer.alloc(4);len.writeUInt32LE(meta.length);const cat=Buffer.concat([len,meta]),parts=[];
  for(let i=0;i<cat.length;i+=CAT_BLOCK)parts.push(cat.subarray(i,i+CAT_BLOCK));
  const d=parts.length+m.groups.length,r=parityCount(m.groups.length,m.percent);check16(d,r);
  const width=even16(m.groups.reduce((n,g)=>Math.max(n,g[0]),parts[0].length));
  return {parts,d,r,width};
}

// No full catalog copy: use the independently checked coordinates from the
// frames. RS acts column-wise, so only the first 64 KiB of each survivor is
// needed for catalog recovery; no group lengths/encoder settings needed yet.
function bootstrap(fd,owner,d,shards,parities) {
  const read=e=>{const b=e && loadFrame(fd,e,e.n);if(!b)throw Error('Global frame changed during recovery');return b;};
  const missing=Array.from({length:d},(_,i)=>i).filter(i=>!shards.has(i)),rows=[...parities.keys()];
  const recovered=new Map();
  function solve(us) {
    if(!us.length)return;
    if(missing.length>rows.length)throw Error('No recoverable global catalog: insufficient parity');
    const width=parities.get(rows[0]).n;if(width%2 || rows.some(p=>parities.get(p).n!==width))throw Error('Invalid global parity width');
    const n=Math.min(CAT_BLOCK,width);
    decode16({d,missing,rows,wanted:us,width:n,length:()=>n,load:i=>read(shards.get(i)),parity:p=>read(parities.get(p)),save:(i,b)=>recovered.set(i,b)});
  }
  if(!shards.has(0))solve([0]);
  const first=recovered.get(0) ?? read(shards.get(0));if(first.length<4)throw Error('Short global catalog');
  const len=first.readUInt32LE(),count=Math.ceil((4+len)/CAT_BLOCK);
  if(!len || len>MAX_META || count>d)throw Error('Invalid global catalog length');
  solve(missing.filter(i=>i>0 && i<count));
  const parts=[];for(let i=0;i<count;i++) {
    const b=i===0?first:recovered.get(i) ?? read(shards.get(i)),n=Math.min(CAT_BLOCK,4+len-i*CAT_BLOCK);
    if(b.length<n || (!recovered.has(i) && b.length!==n))throw Error('Invalid global catalog shard length');
    parts.push(b.subarray(0,n));
  }
  const bytes=Buffer.concat(parts).subarray(4);if(digest(bytes)!==owner)throw Error('Recovered catalog identity mismatch');
  return {bytes,fromParity:recovered.size};
}

function nextMarker(fd,from,end) {
  for (let p=from;p+SYNC.length<=end;) {
    const block=readAt(fd,p,Math.min(128*1024,end-p)), offset=block.indexOf(SYNC);
    if (offset>=0) return p+offset;
    if (block.length<=SYNC.length) break;
    p+=block.length-SYNC.length+1;
  }
  return end;
}

export function scanFrames(fd) {
  const end=fs.fstatSync(fd).size, sets=new Map(),geometries=new Map(); let catalog, catalogBytes, id, metaCopies=0, unique=0, rejected=0;
  for (let p=0;p+FRAME<=end;) {
    const h=readAt(fd,p,FRAME);
    if (h.length!==FRAME) throw Error('Protected input changed while scanning');
    if (h.subarray(0,8).equals(SYNC)) {
      const type=h[8], index=h.readUInt32LE(9), n=h.readUInt32LE(13), owner=h.subarray(17,49).toString('hex');
      const d=index>>>16,slot=index&65535,global=type===GLOBAL_DATA || type===GLOBAL_PARITY;
      const valid=global ? d>0 && (type===GLOBAL_DATA?slot<d:d+slot<LIMIT16) : type<=PARITY && index<MAX_GROUPS && (type!==META || !index);
      if (valid && n>0 && n<=(type===META ? MAX_META : global ? MAX_LONG_BODY : MAX_BODY) && p+FRAME+n<=end) {
        const body=readAt(fd,p+FRAME,n);
        if (body.length===n && sha().update(h.subarray(8,49)).update(body).digest().equals(h.subarray(49))) {
          const hash=digest(body);
          if (type===META) {
            if (owner!==hash) throw Error('Catalog identity mismatch');
            if (id && owner!==id) throw Error('Ambiguous: multiple protected archive catalogs');
            if (!id) { catalog=JSON.parse(body.toString('utf8')); validateCatalog(catalog); catalogBytes=body; id=owner; }
            metaCopies++;
          } else {
            if(global){if(geometries.has(owner) && geometries.get(owner)!==d)throw Error('Conflicting global geometries');geometries.set(owner,d);}
            if (!sets.has(owner)) sets.set(owner,new Map());
            const map=sets.get(owner), key=frameKey(type,index), old=map.get(key);
            if (old && old.hash!==hash) throw Error('Conflicting copies of a protected frame');
            if (!old) {
              if (++unique>2*MAX_GROUPS) throw Error('Too many protected frames');
              map.set(key,{at:p,n,hash,type,index});
            }
          }
          p+=FRAME+n; continue;
        }
      }
      rejected++;
    }
    // A bad length may span the next valid frame. Only skip a whole frame
    // after its header *and* payload have passed their checksum.
    p=nextMarker(fd,p+1,end);
  }
  if(!catalog){
    if(geometries.size!==1)throw Error(geometries.size?'Ambiguous global archive IDs':'No intact GRP1 catalog copy');
    [id]=geometries.keys();
  }
  const coded=sets.get(id) ?? new Map();let entries=coded,catalogFromParity=0;
  if(!catalog || catalog.stripe===GLOBAL) {
    const shards=new Map(),pars=new Map();for(const e of coded.values()) {
      if(e.type===GLOBAL_DATA)shards.set(e.index&65535,e);if(e.type===GLOBAL_PARITY)pars.set(e.index&65535,e);
    }
    if(!catalog){const b=bootstrap(fd,id,geometries.get(id),shards,pars);catalogFromParity=b.fromParity;
      catalogBytes=b.bytes;catalog=JSON.parse(catalogBytes.toString('utf8'));validateCatalog(catalog);if(catalog.stripe!==GLOBAL)throw Error('Incorrect global catalog profile');}
    const {parts,d,r}=globalLayout(catalog,catalogBytes);
    if(geometries.has(id) && geometries.get(id)!==d)throw Error('Catalog and coded geometry disagree');
    if(parts.every((b,i)=>shards.get(i)?.hash===digest(b)))metaCopies++;
    entries=new Map();for(let i=0;i<catalog.groups.length;i++){const e=shards.get(parts.length+i);if(e)entries.set(frameKey(DATA,i),e);}
    for(let i=0;i<r;i++){const e=pars.get(i);if(e)entries.set(frameKey(PARITY,i),e);}
  }
  return {catalog,catalogBytes,entries,metaCopies,rejected,catalogFromParity};
}

export function loadFrame(fd,entry,n,hash) {
  if (!entry || entry.n!==n || (hash && entry.hash!==hash)) return null;
  const body=readAt(fd,entry.at+FRAME,n);
  return body.length===n && digest(body)===entry.hash ? body : null;
}
