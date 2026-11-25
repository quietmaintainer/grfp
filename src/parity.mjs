// Systematic Cauchy Reed–Solomon erasure code, GF(2^8), primitive polynomial
// 0x11d. [I; C] is MDS: any square minor of C is invertible because all
// data coordinates 0..99 and parity coordinates 100..199 are distinct.
export const STRIPE = 100;
export const parityCount = (k,percent) => Math.ceil(k*percent/100);
const log = new Uint8Array(256), exp = new Uint8Array(510);
for (let i=0,x=1;i<255;i++) { exp[i]=x; log[x]=i; x<<=1; if (x&256) x^=0x11d; }
exp.set(exp.subarray(0,255),255);
const mul = Array.from({length:256},(_,a)=>Uint8Array.from({length:256},(_,b)=>a && b ? exp[log[a]+log[b]] : 0));
const inv = x => exp[255-log[x]];
const coefficient = (p,d) => inv((STRIPE+p)^d);
function add(out,src,factor) {
  const row=mul[factor];
  for (let i=0;i<src.length;i++) out[i]^=row[src[i]];
}

// Short data groups are implicitly zero-extended only for parity arithmetic;
// they are stored at their true lengths. yield limits live parity memory.
export function* parityShards(data,percent) {
  const length=Math.max(...data.map(b=>b.length));
  for (let p=0;p<parityCount(data.length,percent);p++) {
    const out=Buffer.alloc(length);
    data.forEach((b,d)=>add(out,b,coefficient(p,d)));
    yield out;
  }
}

// Known erasures only. Solve just the missing columns, rather than inverting
// a k-by-k matrix on every repair. The caller verifies each recovered digest.
export function recoverShards(data,lengths,parity) {
  const missing=data.flatMap((b,i)=>b ? [] : [i]), n=missing.length;
  if (!n) return 0;
  if (n>parity.size) throw Error(`Insufficient parity: ${n} missing data groups, ${parity.size} usable parity shards`);
  const rows=[...parity].slice(0,n).map(([p,body])=>{
    const rhs=Buffer.from(body);
    data.forEach((b,d)=>{ if (b) add(rhs,b,coefficient(p,d)); });
    return {a:Uint8Array.from(missing,d=>coefficient(p,d)),rhs};
  });
  for (let i=0;i<n;i++) {
    let pivot=i; while (pivot<n && !rows[pivot].a[i]) pivot++;
    if (pivot===n) throw Error('Singular parity equations');
    [rows[i],rows[pivot]]=[rows[pivot],rows[i]];
    const {a,rhs}=rows[i], scale=mul[inv(a[i])];
    for (let j=i;j<n;j++) a[j]=scale[a[j]];
    for (let j=0;j<rhs.length;j++) rhs[j]=scale[rhs[j]];
    for (let j=0;j<n;j++) if (j!==i && rows[j].a[i]) {
      const factor=rows[j].a[i];
      for (let k=i;k<n;k++) rows[j].a[k]^=mul[factor][a[k]];
      add(rows[j].rhs,rhs,factor);
    }
  }
  missing.forEach((d,i)=>{data[d]=rows[i].rhs.subarray(0,lengths[d]);});
  return n;
}
