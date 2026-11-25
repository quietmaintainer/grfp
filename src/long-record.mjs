// GRL1: the template dictionary and the local probability model have separate
// reset intervals. Both restart at a bounded, independently verifiable checkpoint.
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { PAGE } from './codec.mjs';
import { packText, restoreText } from './text.mjs';
import { hash,u32,pageHashes,asText,transform,expandSelected } from './long-tape.mjs';
import { packRestartRecord,restoreRestartRecord } from './restart-record.mjs';
export { hash,u32,pageHashes };

export const windowsKiB=[256,1024,4096];
export function config(p=1024,t=256,restart=false,seeded=false,continuous=false) {
  if (!windowsKiB.includes(p) || !windowsKiB.includes(t)) throw Error('Expected window sizes of 256, 1024 or 4096 KiB');
  if(((seeded||continuous) && !restart) || (seeded && continuous))throw Error('Invalid restart model profile');
  if(restart && (t!==256 || (p!==4096 && !((seeded||continuous) && p===256))))throw Error('Restart format requires 256 KiB templates and a supported predictor interval');
  return {p,t,checkpoint:Math.max(p,t)*1024,restart,seeded,continuous};
}
export function maxWire(n,{p,t,restart}) {return 16*Math.ceil(n/PAGE)+9*Math.ceil(n/(1024*t))+5*Math.ceil(n/(1024*(restart?t:p)))+n;}
export function packLongRecord(raw,c) {
  if(!raw.length || raw.length>c.checkpoint) throw Error('Invalid long checkpoint');
  if(c.restart)return packRestartRecord(raw,c);
  const pieces=[pageHashes(raw)], tapes=[];
  for(let at=0;at<raw.length;at+=c.t*1024) {
    const v=transform(raw.subarray(at,at+c.t*1024));pieces.push(Buffer.of(v.kind),u32(v.bound),u32(v.bytes.length));tapes.push(v.bytes);
  }
  const tape=tapes.length===1?tapes[0]:Buffer.concat(tapes);
  for(let at=0;at<tape.length;at+=c.p*1024) {
    const b=tape.subarray(at,at+c.p*1024),zip=deflateRawSync(b,{level:6});let mode=0,body=b;
    if(zip.length<body.length) {mode=1;body=zip;}
    if(asText(b)) {const text=packText(b,true,String(c.p));if(text.length<body.length) {mode=2;body=text;}}
    pieces.push(Buffer.of(mode),u32(body.length),body);
  }
  return Buffer.concat(pieces);
}

export function restoreLongRecord(wire,n,c,old) {
  if(!n || n>c.checkpoint || wire.length>maxWire(n,c)) throw Error('Invalid long checkpoint');
  if(c.restart)return restoreRestartRecord(wire,n,c,old);
  let pos=0;const take=k=>{if(k>wire.length-pos) throw Error('Truncated long record');const b=wire.subarray(pos,pos+k);pos+=k;return b;};
  const pages=Math.ceil(n/PAGE),hashes=take(pages*16),trusted=[];
  for(let i=0;i<pages;i++) {
    const start=i*PAGE,k=Math.min(PAGE,n-start),survivor=old?.subarray(start,start+k);
    trusted.push(survivor?.length===k && hash(survivor).subarray(0,16).equals(hashes.subarray(i*16,i*16+16)));
  }
  const reusedPages=trusted.filter(Boolean).length,rebuiltPages=pages-reusedPages,meta=[];let tapeBytes=0;
  for(let at=0;at<n;at+=c.t*1024) {
    const length=Math.min(c.t*1024,n-at),kind=take(1)[0],bound=take(4).readUInt32LE(),size=take(4).readUInt32LE();
    if(kind>2 || !size || size>length || !bound || bound>2*length || (kind!==2 && bound!==length) || (!kind && size!==length)) throw Error('Invalid long template lengths');
    meta.push({kind,bound,size,length});tapeBytes+=size;
  }
  const parts=[];
  for(let at=0;at<tapeBytes;at+=c.p*1024) {
    const k=Math.min(c.p*1024,tapeBytes-at),mode=take(1)[0],size=take(4).readUInt32LE();
    if(mode>2 || !size || size>k || (!mode && size!==k) || (mode===2 && size<4)) throw Error('Invalid long predictor record');
    const b=take(size);if(!rebuiltPages) continue;
    if(mode===2) parts.push(restoreText(b,k,true,String(c.p)));
    else if(mode===1) {const r=inflateRawSync(b,{info:true,maxOutputLength:k});if(r.buffer.length!==k || r.engine.bytesWritten!==size) throw Error('Invalid deflate record');parts.push(r.buffer);}
    else parts.push(b);
  }
  if(pos!==wire.length) throw Error('Trailing long record bytes');
  if(!rebuiltPages) return {bytes:old,reusedPages,rebuiltPages,replayedBytes:0,decodedTapeBytes:0};
  const tape=Buffer.concat(parts,tapeBytes),out=Buffer.allocUnsafe(n);let at=0,w=0;
  for(const {kind,bound,size,length} of meta) {
    const b=expandSelected(tape.subarray(at,at+size),{kind,bound,length});at+=size;
    b.copy(out,w);w+=b.length;
  }
  for(let i=0;i<pages;i++) {
    const start=i*PAGE,end=Math.min(start+PAGE,n);
    if(trusted[i]) old.copy(out,start,start,end);
    else if(!hash(out.subarray(start,end)).subarray(0,16).equals(hashes.subarray(i*16,i*16+16))) throw Error('Long checkpoint content mismatch');
  }
  return {bytes:out,reusedPages,rebuiltPages,replayedBytes:n,decodedTapeBytes:tapeBytes};
}
