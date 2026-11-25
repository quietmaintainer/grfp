// GPM1: a small, data-only prior for the existing order-4 PPM model. Every
// row is (parent, next byte, quantized pseudocount). No seed text is replayed.
import { transform } from './long-tape.mjs';
export const PRIOR_NODES=16384, MAX_PRIOR=6+4*PRIOR_NODES, TRAIN_LIMIT=4*1024**2;
const shared=(T,n)=>new T(new SharedArrayBuffer(n*T.BYTES_PER_ELEMENT));
export function parsePrior(input) {
  const b=Buffer.from(input.buffer,input.byteOffset,input.byteLength);
  if(b.length<6 || b.length>MAX_PRIOR || b.toString('latin1',0,4)!=='GPM1')throw Error('Invalid GPM1 model');
  const count=b.readUInt16LE(4);if(b.length!==6+4*count)throw Error('Invalid prior row count');
  const n=count+2,child=shared(Uint32Array,n),sibling=shared(Uint32Array,n),freq=shared(Uint16Array,n),symbol=shared(Uint8Array,n),roots=shared(Uint32Array,256);
  const depth=new Uint8Array(n),seen=new Set();
  for(let j=2,pos=6;j<n;j++,pos+=4){const p=b.readUInt16LE(pos)+1,v=b[pos+2],f=b[pos+3],key=p*256+v;
    if(p>=j || depth[p]>=5 || !f || f>32 || seen.has(key))throw Error('Invalid prior context or mass');
    seen.add(key);depth[j]=depth[p]+1;sibling[j]=child[p];child[p]=j;symbol[j]=v;freq[j]=f;if(p===1)roots[v]=j;
  }
  const wire=shared(Uint8Array,b.length);wire.set(b);return {count,wire,child,sibling,freq,symbol,roots};
}
export function trainPrior(raw,budget=PRIOR_NODES) {
  if(!Number.isInteger(budget)||budget<0||budget>PRIOR_NODES||!raw.length||raw.length>TRAIN_LIMIT)throw Error('Invalid prior training bounds');
  const counts=Array.from({length:5},()=>new Map());let distinct=0;
  for(let off=0;budget && off<raw.length;off+=262144){const tape=transform(raw.subarray(off,off+262144)).bytes;let key=0;
    for(let i=0;i<tape.length;i++){key=(key%2**32)*256+tape[i];let modulus=256;
      for(let d=0;d<5 && d<=i;d++,modulus*=256){const s=key%modulus,m=counts[d],v=m.get(s);if(v===undefined && ++distinct>1000000)throw Error('Training sample exceeds one million distinct n-grams');m.set(s,(v??0)+1);}}
  }
  // A prefix occurs at least as often as any extension. Shorter first on
  // ties makes the global frequency cut prefix-closed, even for NUL bytes.
  const rows=counts.flatMap((m,d)=>[...m].map(([key,hits])=>({d,key,hits}))).sort((a,b)=>b.hits-a.hits||a.d-b.d||a.key-b.key).slice(0,budget);
  rows.sort((a,b)=>a.d-b.d||a.key-b.key);const ids=counts.map(()=>new Map()),maximum=new Map();
  rows.forEach((r,i)=>{const p=r.d?ids[r.d-1].get(Math.floor(r.key/256)):0;if(p===undefined)throw Error('Missing prior prefix');
    r.parent=p;ids[r.d].set(r.key,i+1);maximum.set(p,Math.max(maximum.get(p)??0,r.hits));});
  const b=Buffer.alloc(6+4*rows.length);b.write('GPM1');b.writeUInt16LE(rows.length,4);
  rows.forEach(({key,parent,hits},i)=>{const off=6+4*i;b.writeUInt16LE(parent,off);b[off+2]=key%256;b[off+3]=1+Math.floor(31*hits/maximum.get(parent));});
  return b;
}
