import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { STRIPE,parityCount } from '../src/parity.mjs';
import { DATA,PARITY,sha,readAt } from '../src/frames.mjs';

export async function hashFile(name){const h=sha();for await(const b of fs.createReadStream(name))h.update(b);return h.digest('hex');}
export function cutCopy(input,out,cuts) {
  const size=fs.statSync(input).size,src=fs.openSync(input,'r');
  try {const dst=fs.openSync(out,'wx');let at=0;
    try {for(const [start,n] of [...cuts].sort((a,b)=>a[0]-b[0]).concat([[size,0]])) {
      assert.ok(at<=start && start+n<=size);
      while(at<start){const len=Math.min(1024*1024,start-at),b=readAt(src,at,len);assert.equal(b.length,len);fs.writeFileSync(dst,b);at+=len;}
      at=start+n;
    }} finally{fs.closeSync(dst);}
  }finally{fs.closeSync(src);}return size-fs.statSync(out).size;
}

// Keep the two historical PRNG draws in order. A local parity ID is the
// first group index of its stripe plus the within-stripe parity ordinal.
export function legacyLossPlan(groups,percent) {
  const seed=0x6b342,stripes=[],data=[],parity=[],atBudget=[];let rng=seed;
  function sample(list,n) {const a=list.slice();for(let i=0;i<n;i++) {rng=(Math.imul(rng,1664525)+1013904223)>>>0;
    const j=i+Math.floor(rng/2**32*(a.length-i));[a[i],a[j]]=[a[j],a[i]];}return a.slice(0,n);}
  for(let first=0;first<groups;first+=STRIPE){const k=Math.min(STRIPE,groups-first),p=parityCount(k,percent),ds=Array.from({length:k},(_,i)=>({type:DATA,id:first+i}));
    data.push(...ds);parity.push(...Array.from({length:p},(_,i)=>({type:PARITY,id:first+i})));stripes.push({data:k,parity:p});atBudget.push(...sample(ds,p));}
  const all=[...data,...parity],random=sample(all,Math.floor(all.length*percent/100)),counts=stripes.map(()=>0);
  random.forEach(s=>counts[Math.floor(s.id/STRIPE)]++);return {seed,stripes,data,parity,atBudget,random,counts};
}
