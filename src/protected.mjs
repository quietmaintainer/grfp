// GRP1 protection. A data shard is an exact GRF1 group or a restartable GRL
// checkpoint (including its length prefix); FEC never changes its entropy data.
import * as fs from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { newOutput, packFile, packingProfile, walkArchive } from './archive.mjs';
import { GROUP, groupChoices, chooseGroup, parseGroup, restoreGroup } from './groups.mjs';
import { STRIPE, parityCount, parityShards, recoverShards } from './parity.mjs';
import { check16,encode16,decode16 } from './rs16.mjs';
import { sha,digest,readAt,checkPercent,frameHeader,frameKey,scanFrames,loadFrame,validateCatalog,globalLayout,coord,LONG_ENCODER,longGeometry,protectableLong,
  FRAME,META,DATA,PARITY,MAX_GROUPS,GLOBAL,GLOBAL_DATA,GLOBAL_PARITY } from './frames.mjs';
import { packLong,readLongHeader,readLongFrame,restoreLong } from './long.mjs';
import { packLongRecord,restoreLongRecord,pageHashes,u32 } from './long-record.mjs';
import { PAGE } from './codec.mjs';

function using(path,flags,fn) {
  const fd=fs.openSync(path,flags);
  try { return fn(fd); } finally { fs.closeSync(fd); }
}
function scratch(target,fn) {
  if (fs.existsSync(target)) throw Error(`Output already exists: ${target}`);
  const tmp=fs.mkdtempSync(join(dirname(resolve(target)),'.grfp-'));
  try { return fn(tmp); } finally { fs.rmSync(tmp,{recursive:true,force:true}); }
}
function grfHeader(bytes) { const h=Buffer.alloc(12); h.write('GRF1'); h.writeBigUInt64LE(BigInt(bytes),4); return h; }
const compile=(b,p)=>chooseGroup(groupChoices(b,p.width ?? undefined,p.text,p.templates,p.textWindow),p.templates).bytes;
function innerSpec(m){
  if(m.encoder!==LONG_ENCODER)return {head:grfHeader(m.bytes),tail:Buffer.alloc(0),step:GROUP,name:'recipe.grf',donorId:digest,compile:b=>compile(b,m.profile),
    decode:(w,n,old,assemble)=>restoreGroup(parseGroup(w,n),old,assemble)};
  const {h,c}=longGeometry(m);return {head:h,tail:Buffer.from(m.originalSha256,'hex'),step:c.checkpoint,name:'recipe.grl',donorId:b=>digest(pageHashes(b)),
    compile:b=>{const wire=packLongRecord(b,c);return Buffer.concat([u32(wire.length),wire]);},
    decode:(w,n,old,assemble)=>{if(assemble)throw Error('Lattice backend applies to GRF1');if(w.length<4 || w.readUInt32LE()!==w.length-4)throw Error('Invalid protected GRL frame');return restoreLongRecord(w.subarray(4),n,c,old);}};
}
function offsets(m,pos){return m.groups.map(([n])=>{const at=pos;pos+=n;return at;});}
function writeAt(fd,b,pos){let i=0;while(i<b.length){const n=fs.writeSync(fd,b,i,b.length-i,pos+i);if(!n)throw Error('Short staging write');i+=n;}}
function checkFec(fec){if(fec!=='local8' && fec!==GLOBAL)throw Error('FEC profile must be local8 or global16');}
function checkSize(bytes,percent,fec) {
  if(bytes>GROUP*MAX_GROUPS)throw Error('Source exceeds GRP1 group limit');
  const k=Math.ceil(bytes/GROUP);
  // At least one coded catalog shard. globalLayout checks the exact count
  // once the group lengths/hashes and the final catalog bytes are known.
  if(fec===GLOBAL)check16(k+1,parityCount(k,percent));
}

function writeProtected(innerPath,target,m,meta) {
  const id=sha().update(meta).digest(),spec=innerSpec(m),header=spec.head;
  return newOutput(target,write=>using(innerPath,'r',fd=>{
    const outer=sha(),inner=sha().update(header); let pos=header.length,protectedBytes=0,parityBytes=0,parityFrames=0;
    function frame(type,index,body) {
      const h=frameHeader(type,index,id,body); write(h);write(body);outer.update(h).update(body);protectedBytes+=FRAME+body.length;
    }
    if (!readAt(fd,0,header.length).equals(header)) throw Error('Inner recipe header mismatch');
    if(m.stripe===GLOBAL) {
      const {parts,d,r,width}=globalLayout(m,meta),starts=offsets(m,pos);
      function load(i) {if(i<parts.length)return parts[i];const g=i-parts.length,[n,,expected]=m.groups[g],b=readAt(fd,starts[g],n);
        if(b.length!==n || digest(b)!==expected)throw Error('Inner recipe group mismatch');return b;}
      for(let i=0;i<d;i++){const b=load(i);frame(GLOBAL_DATA,coord(d,i),b);if(i>=parts.length){inner.update(b);pos+=b.length;}}
      encode16(d,r,width,load,(p,b)=>{frame(GLOBAL_PARITY,coord(d,p),b);parityBytes+=b.length;parityFrames++;});
    } else {
      frame(META,0,meta);
      for (let first=0;first<m.groups.length;first+=STRIPE) {
        const data=m.groups.slice(first,first+STRIPE).map(([n,,expected],i)=>{
          const b=readAt(fd,pos,n); pos+=n;
          if (b.length!==n || digest(b)!==expected) throw Error('Inner GRF1 group mismatch');
          inner.update(b);frame(DATA,first+i,b);return b;
        });
        let p=0; for (const b of parityShards(data,m.percent)) { frame(PARITY,first+p++,b);parityBytes+=b.length;parityFrames++; }
      }
    }
    const groupBytes=pos-header.length;if(!readAt(fd,pos,spec.tail.length).equals(spec.tail))throw Error('Inner source hash mismatch');pos+=spec.tail.length;const footer=inner.update(spec.tail).digest();
    if (footer.toString('hex')!==m.grfFooter || !readAt(fd,pos,32).equals(footer) || fs.fstatSync(fd).size!==pos+32) throw Error('Inner recipe checksum or length mismatch');
    frame(META,0,meta);
    return {originalBytes:m.bytes,originalSha256:m.originalSha256,grfBytes:pos+32,grfFooter:m.grfFooter,protectedBytes,
      protectedSha256:outer.digest('hex'),groups:m.groups.length,fec:m.stripe===GLOBAL?GLOBAL:'local8',stripes:m.stripe===GLOBAL?1:Math.ceil(m.groups.length/STRIPE),parityPercent:m.percent,
      innerFormat:header.toString('latin1',0,4),innerBytes:pos+32,parityFrames,parityPayloadBytes:parityBytes,framingAndCatalogBytes:protectedBytes-groupBytes-parityBytes};
  }));
}

export function packProtected(source,target,width,options={}) {
  const percent=options.parityPercent,profile=packingProfile(width,options),fec=options.fec ?? 'local8';checkPercent(percent);checkFec(fec);
  checkSize(fs.statSync(source).size,percent,fec);
  return scratch(target,tmp=>{
    const path=join(tmp,'recipe.grf'), groups=[];
    const s=packFile(source,path,width,{...options,onGroup:(raw,wire)=>groups.push([wire.length,digest(raw),digest(wire)])});
    return seal(path,target,percent,profile,groups,s.bytes,s.sha256,fec);
  });
}

function seal(path,target,percent,profile,groups,bytes,originalSha256,fec,encoder='grf1-group-v1') {
  const grfFooter=using(path,'r',fd=>readAt(fd,fs.fstatSync(fd).size-32,32).toString('hex'));
  const m={format:'GRP1',encoder,stripe:fec===GLOBAL?GLOBAL:STRIPE,percent,bytes,originalSha256,grfFooter,profile,groups};
  validateCatalog(m);return writeProtected(path,target,m,Buffer.from(JSON.stringify(m)));
}

export async function packLongProtected(source,target,{parityPercent=5,...opts}={}) {
  checkPercent(parityPercent);if(fs.existsSync(target))throw Error('Output already exists');
  const k=Math.ceil(fs.statSync(source).size/((opts.predictor??4096)*1024));check16(1+k,parityCount(k,parityPercent));
  const tmp=fs.mkdtempSync(join(dirname(resolve(target)),'.grlp-'));
  try {const path=join(tmp,'inner'),groups=[];const s=await packLong(source,path,{...opts,restart:true,onCheckpoint:g=>groups.push(g)});
    const profile=using(path,'r',fd=>({header:readLongHeader(fd).h.toString('base64')}));
    return seal(path,target,parityPercent,profile,groups,s.originalBytes,s.originalSha256,GLOBAL,LONG_ENCODER);
  }finally{fs.rmSync(tmp,{recursive:true,force:true});}
}

// A GRL checkpoint already commits to its original through the ordered page
// hashes. Use their SHA-256 as the donor ID; this retrofit needs no source,
// model sidecar or costly second text encoding. seal rereads all group hashes.
export function protectLongExisting(path,target,parityPercent=5){
  checkPercent(parityPercent);if(fs.existsSync(target))throw Error('Output already exists');
  return using(path,'r',fd=>{const {h,size,c}=readLongHeader(fd);if(!protectableLong(c))throw Error('Protection requires independent 256 KiB units or restartable GRL');
    const k=Math.ceil(size/c.checkpoint);check16(1+k,parityCount(k,parityPercent));const groups=[],wire=sha().update(h);let pos=h.length;
    for(let off=0;off<size;off+=c.checkpoint){const n=Math.min(c.checkpoint,size-off),{prefix,bytes}=readLongFrame(fd,pos,n,c),tags=16*Math.ceil(n/PAGE);
      if(bytes.length<tags+14*Math.ceil(n/262144))throw Error('Short restart record');groups.push([4+bytes.length,digest(bytes.subarray(0,tags)),sha().update(prefix).update(bytes).digest('hex')]);
      wire.update(prefix).update(bytes);pos+=4+bytes.length;}
    const raw=readAt(fd,pos,32);if(fs.fstatSync(fd).size!==pos+64 || !wire.update(raw).digest().equals(readAt(fd,pos+32,32)))throw Error('Inner GRL checksum or length mismatch');
    return seal(path,target,parityPercent,{header:h.toString('base64')},groups,size,raw.toString('hex'),GLOBAL,LONG_ENCODER);
  });
}

// Older GRF1 files did not store all encoder settings. Check the supplied
// profile against every exact wire record before promising reverse repair.
export function protectExisting(path,target,width,options={}) {
  const percent=options.parityPercent ?? 5,profile=packingProfile(width,options),fec=options.fec ?? 'local8';checkPercent(percent);checkFec(fec);
  if (fs.existsSync(target)) throw Error(`Output already exists: ${target}`);
  const groups=[],rawHash=sha();let pos=12;
  const s=using(path,'r',fd=>walkArchive(path,(group,s)=>{
    checkSize(s.bytes,percent,fec);
    const b=restoreGroup(group).bytes,wire=readAt(fd,pos,group.wireBytes);pos+=group.wireBytes;
    if (!compile(b,profile).equals(wire)) throw Error(`Encoder profile does not reproduce GRF1 group ${groups.length}`);
    groups.push([wire.length,digest(b),digest(wire)]);rawHash.update(b);
  }));
  return seal(path,target,percent,profile,groups,s.bytes,rawHash.digest('hex'),fec);
}

// Reframe already verified group wires without the original or another text
// encoding pass. If a recipe group is missing, recover the old archive first.
export function reprotect(path,target,{fec=GLOBAL,parityPercent}={}) {
  checkFec(fec);return scratch(target,tmp=>using(path,'r',fd=>{
    const {catalog:m,entries}=scanFrames(fd),percent=parityPercent ?? m.percent;checkPercent(percent);
    const spec=innerSpec(m);if(m.encoder===LONG_ENCODER && fec!==GLOBAL)throw Error('Restartable archives require global16');
    const inner=join(tmp,spec.name);using(inner,'wx',out=>{
      const head=spec.head,h=sha().update(head);fs.writeFileSync(out,head);
      m.groups.forEach(([n,,expected],i)=>{const b=loadFrame(fd,entries.get(frameKey(DATA,i)),n,expected);
        if(!b)throw Error(`Missing group ${i}: recover the input archive before converting`);h.update(b);fs.writeFileSync(out,b);});
      fs.writeFileSync(out,spec.tail);const footer=h.update(spec.tail).digest();if(footer.toString('hex')!==m.grfFooter)throw Error('Inner footer mismatch');fs.writeFileSync(out,footer);
    });
    return seal(inner,target,percent,m.profile,m.groups,m.bytes,m.originalSha256,fec,m.encoder);
  }));
}

// Stage the systematic data in its final on-disk GRF1 positions. Only the
// missing outputs of one RS batch and a single input group need be resident.
function rebuildGlobal(fd,oldFd,inner,out,scan,assemble) {
  const {catalog:m,catalogBytes,entries}=scan,spec=innerSpec(m),{parts,d,r,width}=globalLayout(m,catalogBytes),starts=offsets(m,spec.head.length),missing=[],rows=[];
  const s={intactRecipeGroups:0,recipeGroupsFromOriginal:0,recipeGroupsFromParity:0,missingParityFrames:0,
    reusedOriginalPages:0,rebuiltOriginalPages:0,replayedOriginalBytes:0,decodedTapeBytes:0};
  const rawSize=i=>Math.min(spec.step,m.bytes-i*spec.step),old=i=>oldFd===undefined?undefined:readAt(oldFd,i*spec.step,rawSize(i));
  for(const [i,[n,,h]] of m.groups.entries()){
    const b=loadFrame(fd,entries.get(frameKey(DATA,i)),n,h);
    if(b){writeAt(inner,b,starts[i]);s.intactRecipeGroups++;}else missing.push(i);
  }
  for(let j=0;j<r;j++){if(entries.get(frameKey(PARITY,j))?.n===width)rows.push(j);else s.missingParityFrames++;}
  const needed=[];let left=missing.length;
  for(const g of missing){if(oldFd!==undefined && left>rows.length){const b=old(g);
    if(b.length===rawSize(g) && spec.donorId(b)===m.groups[g][1]){const w=spec.compile(b);
      if(w.length===m.groups[g][0] && digest(w)===m.groups[g][2]){writeAt(inner,w,starts[g]);left--;s.recipeGroupsFromOriginal++;continue;}}
  }needed.push(parts.length+g);}
  if(needed.length>rows.length)throw Error(`Global stripe: ${needed.length} recipe groups still missing, only ${rows.length} usable parity shards`);
  const load=i=>i<parts.length?parts[i]:readAt(inner,starts[i-parts.length],m.groups[i-parts.length][0]);
  decode16({d,missing:needed,rows,width,length:i=>m.groups[i-parts.length][0],load,
    parity:j=>{const b=loadFrame(fd,entries.get(frameKey(PARITY,j)),width);if(!b)throw Error('Global parity changed while reading');return b;},
    save:(i,b)=>{const g=i-parts.length;if(digest(b)!==m.groups[g][2])throw Error(`Rebuilt recipe group ${g} checksum mismatch`);
      writeAt(inner,b,starts[g]);s.recipeGroupsFromParity++;}});
  const head=spec.head,wireHash=sha().update(head),rawHash=sha();writeAt(inner,head,0);let pos=head.length;
  for(const [i,[n,rawDigest,wireDigest]] of m.groups.entries()){
    const wire=readAt(inner,pos,n);pos+=n;if(digest(wire)!==wireDigest)throw Error(`Recipe group ${i} checksum mismatch`);
    wireHash.update(wire);if(out===null)continue; // separate parallel restore after the wire is verified
    const got=spec.decode(wire,rawSize(i),old(i),assemble);
    if(spec.donorId(got.bytes)!==rawDigest)throw Error(`Original group ${i} checksum mismatch`);
    rawHash.update(got.bytes);fs.writeFileSync(out,got.bytes);
    s.reusedOriginalPages+=got.reusedPages;s.rebuiltOriginalPages+=got.rebuiltPages;s.replayedOriginalBytes+=got.replayedBytes;s.decodedTapeBytes+=got.decodedTapeBytes;
  }
  writeAt(inner,spec.tail,pos);pos+=spec.tail.length;const footer=wireHash.update(spec.tail).digest();if(footer.toString('hex')!==m.grfFooter || (out!==null && rawHash.digest('hex')!==m.originalSha256))throw Error('Final original or inner recipe digest mismatch');
  writeAt(inner,footer,pos);return s;
}

function rebuild(fd,oldFd,inner,out,scan,assemble) {
  const {catalog:m,entries}=scan, p=m.profile, rawHash=sha(), wireHash=sha(), head=grfHeader(m.bytes);
  fs.writeFileSync(inner,head);wireHash.update(head);
  const stats={intactRecipeGroups:0,recipeGroupsFromOriginal:0,recipeGroupsFromParity:0,missingParityFrames:0,
    reusedOriginalPages:0,rebuiltOriginalPages:0,replayedOriginalBytes:0,decodedTapeBytes:0};
  const old=g=>oldFd===undefined ? undefined : readAt(oldFd,g*GROUP,Math.min(GROUP,m.bytes-g*GROUP));
  for (let first=0;first<m.groups.length;first+=STRIPE) {
    const stripe=m.groups.slice(first,first+STRIPE), lengths=stripe.map(g=>g[0]), k=stripe.length;
    const data=stripe.map(([n,,hash],i)=>loadFrame(fd,entries.get(frameKey(DATA,first+i)),n,hash));
    let missing=data.filter(b=>!b).length;stats.intactRecipeGroups+=k-missing;
    const parity=new Map(), count=parityCount(k,m.percent), longest=Math.max(...lengths);
    for (let j=0;j<count;j++) {
      const e=entries.get(frameKey(PARITY,first+j));
      if (!e || e.n!==longest) {stats.missingParityFrames++;continue;}
      if (missing) {const b=loadFrame(fd,e,longest); if (b) parity.set(j,b); else stats.missingParityFrames++;}
    }
    // A verified source group is an additional equation. Only pay to re-pack
    // when there aren't already enough usable parity shards for this stripe.
    for (let i=0;oldFd!==undefined && missing>parity.size && i<k;i++) if (!data[i]) {
      const g=first+i,b=old(g), n=Math.min(GROUP,m.bytes-g*GROUP);
      if (b.length!==n || digest(b)!==stripe[i][1]) continue;
      const wire=compile(b,p);
      if (wire.length!==lengths[i] || digest(wire)!==stripe[i][2]) continue; // different encoder: never substitute an equivalent archive
      data[i]=wire;missing--;stats.recipeGroupsFromOriginal++;
    }
    if (missing>parity.size) throw Error(`Stripe ${first/STRIPE}: ${missing} recipe groups still missing, only ${parity.size} usable parity shards`);
    stats.recipeGroupsFromParity+=recoverShards(data,lengths,parity);
    for (const [i,wire] of data.entries()) {
      const g=first+i,n=Math.min(GROUP,m.bytes-g*GROUP);
      if (digest(wire)!==stripe[i][2]) throw Error(`Rebuilt recipe group ${g} checksum mismatch`);
      const r=restoreGroup(parseGroup(wire,n),old(g),assemble);
      if (digest(r.bytes)!==stripe[i][1]) throw Error(`Original group ${g} checksum mismatch`);
      fs.writeFileSync(inner,wire);wireHash.update(wire);fs.writeFileSync(out,r.bytes);rawHash.update(r.bytes);
      stats.reusedOriginalPages+=r.reusedPages;stats.rebuiltOriginalPages+=r.rebuiltPages;
      stats.replayedOriginalBytes+=r.replayedBytes;stats.decodedTapeBytes+=r.decodedTapeBytes;
    }
  }
  const footer=wireHash.digest();
  if (footer.toString('hex')!==m.grfFooter || rawHash.digest('hex')!==m.originalSha256) throw Error('Final original or GRF1 digest mismatch');
  fs.writeFileSync(inner,footer);return stats;
}

// Verify all three files in staging before creating the output directory.
function publish(tmp,target,names) {
  fs.mkdirSync(target);const done=[];
  try {
    for (const name of names) {
      const src=join(tmp,name),dest=join(target,name);
      try { fs.linkSync(src,dest); } catch (e) {
        if (!['EPERM','ENOTSUP','ENOSYS','EOPNOTSUPP'].includes(e.code)) throw e;
        fs.copyFileSync(src,dest,fs.constants.COPYFILE_EXCL);
      }
      done.push(dest);
    }
  } catch (e) { for (const dest of done) fs.unlinkSync(dest);fs.rmdirSync(target);throw e; }
}
export function recoverProtected(path,target,{damaged,assemble}={}) {
  return scratch(target,tmp=>using(path,'r',fd=>{
    const scan=scanFrames(fd),name=innerSpec(scan.catalog).name, inner=join(tmp,name), out=join(tmp,'restored.bin');
    const rebuildFn=scan.catalog.stripe===GLOBAL?rebuildGlobal:rebuild;
    const work=old=>using(inner,'wx+',i=>using(out,'wx',o=>rebuildFn(fd,old,i,o,scan,assemble)));
    const stats=damaged===undefined ? work(undefined) : using(damaged,'r',work);
    const archive=writeProtected(inner,join(tmp,'protected.grfp'),scan.catalog,scan.catalogBytes);
    publish(tmp,target,['restored.bin',name,'protected.grfp']);
    return {...archive,intactCatalogCopies:scan.metaCopies,catalogPiecesFromParity:scan.catalogFromParity,rejectedFrames:scan.rejected,...stats,...(assemble?.stats && {lattice:{...assemble.stats}})};
  }));
}

export async function recoverLongProtected(path,target,{damaged,jobs=1,backend='js'}={}) {
  if(fs.existsSync(target))throw Error('Output already exists');const tmp=fs.mkdtempSync(join(dirname(resolve(target)),'.grlp-'));
  try {const inner=join(tmp,'recipe.grl'),out=join(tmp,'restored.bin');let scan;
    const s=using(path,'r',fd=>{scan=scanFrames(fd);if(scan.catalog.encoder!==LONG_ENCODER)throw Error('Expected protected restartable recipe');
      const work=old=>using(inner,'wx+',i=>rebuildGlobal(fd,old,i,null,scan));return damaged===undefined?work(undefined):using(damaged,'r',work);});
    const raw=await restoreLong(inner,out,{damaged,jobs,backend}),m=scan.catalog,spec=innerSpec(m);if(raw.originalSha256!==m.originalSha256)throw Error('Catalog source mismatch');
    using(out,'r',fd=>m.groups.forEach((g,i)=>{if(spec.donorId(readAt(fd,i*spec.step,Math.min(spec.step,m.bytes-i*spec.step)))!==g[1])throw Error('Catalog checkpoint mismatch');}));
    const packed=writeProtected(inner,join(tmp,'protected.grfp'),m,scan.catalogBytes);publish(tmp,target,['restored.bin','recipe.grl','protected.grfp']);
    return {...packed,intactCatalogCopies:scan.metaCopies,catalogPiecesFromParity:scan.catalogFromParity,intactRecipeGroups:s.intactRecipeGroups,
      missingParityFrames:s.missingParityFrames,recipeGroupsFromParity:s.recipeGroupsFromParity,recipeGroupsFromOriginal:s.recipeGroupsFromOriginal,raw};
  } finally{fs.rmSync(tmp,{recursive:true,force:true});}
}
