// A seed is a normal, independently restorable GRL1 or GRL2. Verify its wire identity
// before trusting any offsets, then decode source checkpoints on demand.
import * as fs from 'node:fs';
import { readLongHeader,readLongFrame,sha,at } from './long.mjs';
import { restoreLongRecord } from './long-record.mjs';

export class BaseView {
  constructor(size,step,load) {this.size=size;this.step=step;this.load=load;this.cache=new Map();this.loads=0;this.loadedBytes=0;}
  block(i) {
    let b=this.cache.get(i);if(b) this.cache.delete(i);
    else {b=this.load(i);this.loads++;this.loadedBytes+=b.length;if(this.cache.size>=4)this.cache.delete(this.cache.keys().next().value);}
    this.cache.set(i,b);return b;
  }
  slice(off,n) {
    if(!Number.isSafeInteger(off) || off<0 || !Number.isSafeInteger(n) || n<0 || off>this.size-n) throw Error('Reference outside shared seed');
    if(!n)return Buffer.alloc(0);
    const i=Math.floor(off/this.step),local=off%this.step,b=this.block(i);
    if(local+n<=b.length) return b.subarray(local,local+n);
    const parts=[b.subarray(local)];let left=n-parts[0].length;
    for(let j=i+1;left>0;j++){const s=this.block(j).subarray(0,left);parts.push(s);left-=s.length;}
    return Buffer.concat(parts,n);
  }
}

export function openSeed(path) {
  const fd=fs.openSync(path,'r');try {
    const {h,size,c}=readLongHeader(fd),wire=sha().update(h),offsets=[];let pos=h.length;
    for(let off=0;off<size;off+=c.checkpoint) {
      const n=Math.min(c.checkpoint,size-off),frame=readLongFrame(fd,pos,n,c);
      offsets.push(pos);wire.update(frame.prefix).update(frame.bytes);pos+=4+frame.bytes.length;
    }
    const original=at(fd,pos,32),id=wire.update(original).digest();
    if(pos+64!==fs.fstatSync(fd).size || !id.equals(at(fd,pos+32,32)))throw Error('Shared seed checksum mismatch');
    const view=new BaseView(size,c.checkpoint,i=>{const n=Math.min(c.checkpoint,size-i*c.checkpoint);
      return restoreLongRecord(readLongFrame(fd,offsets[i],n,c).bytes,n,c).bytes;});
    return {id,original,view,close:()=>fs.closeSync(fd)};
  }catch(e){fs.closeSync(fd);throw e;}
}
