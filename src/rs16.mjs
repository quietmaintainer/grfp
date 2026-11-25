// Systematic Cauchy Reed–Solomon over GF(2^16). Each pair of successive
// bytes is a little-endian field symbol; a missing final high byte is zero.
export const LIMIT16=65535;
const WORK=8*1024*1024, log=new Uint16Array(65536), exp=new Uint16Array(2*LIMIT16);
const littleEndian = new Uint8Array(Uint16Array.of(1).buffer)[0] === 1;
for(let i=0,x=1;i<LIMIT16;i++) {
  exp[i]=x;log[x]=i;x<<=1;if(x&65536)x^=0x1100b;
  if(x===1 && i!==LIMIT16-1)throw Error('Invalid GF16 generator');
}
exp.set(exp.subarray(0,LIMIT16),LIMIT16);
const inv=x=>exp[LIMIT16-log[x]],mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0;
export const even16=n=>n+(n%2);
export function check16(d,r) {
  if(!Number.isInteger(d)||d<1||!Number.isInteger(r)||r<0||d+r>LIMIT16)throw Error('Global GF16 code exceeds 65,535 systematic + parity coordinates');
}

// Split a coefficient's 65,536-entry multiplication table into two 256-entry
// tables. Multiplication distributes over the XOR of the low and high byte.
const tables=new Map();
function add(out,b,f) {
  let t=tables.get(f);if(!t) {
    if(tables.size>=1024)tables.delete(tables.keys().next().value);
    t=new Uint16Array(512);for(let i=1;i<256;i++){t[i]=mul(f,i);t[256+i]=mul(f,i<<8);}tables.set(f,t);
  }
  const n=Math.min(out.length,b.length),end=n-(n%2);
  if (littleEndian) {
    // Accumulators are zero-offset, even-sized Buffers. Source shards can be
    // unaligned or odd-sized, so their bytes still feed separate table lookups.
    const words = new Uint16Array(out.buffer, out.byteOffset, out.length / 2);
    for (let i = 0, word = 0; i < end; i += 2, word++) {
      words[word] ^= t[b[i]] ^ t[256 + b[i + 1]];
    }
    if (n !== end) words[end / 2] ^= t[b[end]];
    return;
  }
  for(let i=0;i<end;i+=2){const v=t[b[i]]^t[256+b[i+1]];out[i]^=v;out[i+1]^=v>>>8;}
  if(n!==end){const v=t[b[end]];out[end]^=v;out[end+1]^=v>>>8;}
}

// File-backed callbacks: no d-by-shard-size or r-by-r allocation. Accumulate
// at most one output batch at once, rereading the survivors for later batches.
function batches(outputs,width,fn) {
  if(!Number.isSafeInteger(width)||width<=0||width%2)throw Error('Invalid GF16 symbol width');
  const batch=Math.max(1,Math.floor(WORK/width));
  for(let i=0;i<outputs.length;i+=batch)fn(outputs.slice(i,i+batch));
}
export function encode16(d,r,width,load,save) {
  check16(d,r);
  batches(Array.from({length:r},(_,i)=>i),width,ps=>{
    const out=ps.map(()=>Buffer.alloc(width));
    for(let i=0;i<d;i++) {const b=load(i);if(b.length>width)throw Error('Oversized systematic shard');
      for(let j=0;j<ps.length;j++)add(out[j],b,inv((d+ps[j])^i));}
    ps.forEach((p,j)=>save(p,out[j]));
  });
}

// A(z)=product(z+u) over missing systematic points; B(z)=product(z+y)
// over the same number of surviving parity points (y=d+p). Interpolating
// A(z)*sum(missing_value[u]/(z+u)) at y gives each target u directly.
// Row weight B(u)/A'(u); survivor weight A(v)/B(v) for data or A(y)/B'(y)
// for parity. Multiply these weights by 1/(u+v). '+' in the field is XOR.
export function decode16({d,missing,rows,wanted=missing,width,length,load,parity,save}) {
  check16(d,0);if(!wanted.length)return;
  if(missing.length>rows.length)throw Error(`Insufficient global parity: ${missing.length} missing, ${rows.length} usable`);
  const lost=new Set(missing),ps=rows.slice(0,missing.length),ys=ps.map(p=>d+p);
  if(lost.size!==missing.length || missing.some(v=>!Number.isInteger(v)||v<0||v>=d) || wanted.some(v=>!lost.has(v)) ||
     ps.some(p=>!Number.isInteger(p)||p<0||p+d>=LIMIT16) || new Set(ps).size!==ps.length)throw Error('Invalid GF16 coordinates');
  function product(x,set) {let a=1;for(const v of set)if(x!==v)a=mul(a,x^v);return a;}
  const row=new Uint16Array(d),col=new Uint16Array(d),parCol=new Uint16Array(ps.length);
  for(const u of wanted)row[u]=mul(product(u,ys),inv(product(u,missing)));
  for(let i=0;i<d;i++)if(!lost.has(i))col[i]=mul(product(i,missing),inv(product(i,ys)));
  ys.forEach((y,j)=>{parCol[j]=mul(product(y,missing),inv(product(y,ys)));});
  batches(wanted,width,us=>{
    const out=us.map(u=>{const n=length(u);if(!Number.isInteger(n)||n<1||n>width)throw Error('Invalid recovery length');return Buffer.alloc(even16(n));});
    function combine(v,weight,b){for(let j=0;j<us.length;j++)add(out[j],b,mul(mul(row[us[j]],weight),inv(us[j]^v)));}
    for(let i=0;i<d;i++)if(!lost.has(i))combine(i,col[i],load(i));
    ps.forEach((p,j)=>combine(ys[j],parCol[j],parity(p)));
    us.forEach((u,j)=>save(u,out[j].subarray(0,length(u))));
  });
}
