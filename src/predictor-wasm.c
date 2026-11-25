/* Bit-compatible GRL2 PPM-D, span calibration and rANS. No libc, imports,
   host callbacks, stored weights, or executable data from the archive. */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef __SIZE_TYPE__ usize;
#define API(n) __attribute__((export_name(#n)))
#define REQUIRE(x) do { if (!(x)) __builtin_trap(); } while (0)
#define SCALE 32768u
#define LOWER (1u<<23)
#define FRAME (1u<<18)
#define LIMIT (1u<<22)
#define SHIFT 13
#define BLOCK (1u<<SHIFT)
enum Action { WARM, WRITE, READ };

extern u8 __heap_base;
static u32 bump;
void *memset(void *p,int v,usize n){volatile u8 *d=p;for(usize i=0;i<n;i++)d[i]=(u8)v;return p;}
static void *reserve(u32 n){
  u32 at=(bump+7u)&~7u;REQUIRE(at<0x20000000u && n<=0x20000000u-at);bump=at+n;
  u32 have=(u32)__builtin_wasm_memory_size(0),need=(bump+65535u)>>16;
  if(need>have)REQUIRE(__builtin_wasm_memory_grow(0,need-have)!=(usize)-1);
  return (void*)(usize)at;
}
// One flat, non-moving pool at the end of linear memory for trie nodes and
// anchor-chain entries. Grow committed memory in slabs without copying tables.
typedef union {struct {u32 child,sibling,freq;u8 symbol;};struct {u32 key,continuation,next;} anchor;} Node;
static Node *pool;
static u32 capacityNodes,nodes,total,pos,seedNodes,history[5],roots[256],excluded[256],masses[256];
static u8 syms[256],*bytes,*io;
static Node *node(u32 i){return pool+i;}
static Node *fresh(u32 i){REQUIRE(i<=seedNodes+2+6*total);if(i>=capacityNodes){reserve(BLOCK*sizeof(Node));capacityNodes+=BLOCK;}
  Node *p=node(i);*p=(Node){0};return p;}

static u32 *heads,slots,wordHash,wordLen,runLen;
static int from,bin;static u16 hits[20],trials[20];
static u32 location(u32 k){u32 z=k;z^=z>>16;z*=0x7feb352du;z^=z>>15;return z&(slots-1);}
static u32 replace(u32 k,u32 value){
  const u32 h=location(k);u32 j=heads[h];while(j && node(j)->anchor.key!=k)j=node(j)->anchor.next;
  if(!j){j=++nodes;Node *z=fresh(j);z->anchor.key=k;z->anchor.next=heads[h];heads[h]=j;}
  u32 prev=node(j)->anchor.continuation;node(j)->anchor.continuation=value;return prev;
}
static void bucket(u32 mass,u32 sum){u32 tier=!runLen?0:runLen<3?1:runLen<8?2:3;
  bin=(int)(tier*5+(!mass?0:mass*16<sum?1:mass*4<sum?2:mass*4<sum*3?3:4));}
static u32 bonus(u32 mass,u32 sum){bucket(mass,sum);int h=hits[bin]+1,m=trials[bin]-hits[bin]+2;
  int a=(h*(int)sum-(h+m)*(int)mass)/m;if(a<=0)return 0;u32 v=(u32)a;
  if(v>32*sum)v=32*sum;if(v>SCALE-sum)v=SCALE-sum;return v;}
static void observe(u32 i,u8 b){
  if(from>=0){int hit=bytes[from]==b;
    if(bin>=0){if(trials[bin]>=256){trials[bin]>>=1;hits[bin]>>=1;}trials[bin]++;hits[bin]+=(u16)hit;bin=-1;}
    if(hit){from++;runLen++;}else{from=-1;runLen=0;}}
  if((b>=65&&b<=90)||(b>=97&&b<=122)||(b>=48&&b<=57)||b==95){wordHash=wordHash*16777619u^(b>=65&&b<=90?b+32:b);wordLen++;}
  else{if(wordLen>=2){u32 prev=replace(wordHash*257u^b,i+1);if(from<0||!runLen){from=prev?(int)prev:-1;runLen=0;}}
    wordHash=wordLen=0;}
}

static u32 *events,eventCap,eventN,x,inPos,inLen,ioCap,outLen;static int writing;
// GXE1: the host expands the same integer network once to immutable codes.
#define EXPERT_CELLS (5*5*8*4*4*8*8*2)
static u16 *corrections;
static const u16 gains[65]={64,67,70,73,76,79,83,87,91,95,99,103,108,112,117,123,128,134,140,146,152,159,166,173,181,189,197,206,215,225,235,245,256,267,279,292,304,318,332,347,362,378,395,412,431,450,470,490,512,535,558,583,609,636,664,693,724,756,790,825,861,899,939,981,1024};
static u32 cls(u32 b){if(b>=97&&b<=122)return 0;if(b>=65&&b<=90)return 1;if(b>=48&&b<=57)return 2;if(b==32||b==9)return 3;if(b==10||b==13)return 4;
  switch(b){case '<':case '>':case '[':case ']':case '{':case '}':case '|':case '&':case ';':case '/':case '=':case '"':case '\'':return 5;}return b<128?6:7;}
static void correct(u32 i,u32 k,int back,int offered,int boosted,u32 n,u32 *sum,u32 *esc){
  u32 top=0;for(u32 j=1;j<n;j++)if(masses[j]>masses[top])top=j;
  u32 m=masses[top],nb=n==1?0:n==2?1:n<=4?2:n<=16?3:4,support=31u-(u32)__builtin_clz(*sum / *esc),dom=4*m / *sum;
  if(support>7)support=7;if(dom>3)dom=3;u32 sp=offered<0?0:!boosted?1:offered==syms[top]?2:3;
  u32 shape=(((k*5+nb)*8+support)*4+dom)*4+sp,key=((shape*8+cls(i?bytes[i-1]:0))*8+cls(syms[top]))*2+back;
  u32 q=corrections[key];if(q==32+128*32)return;u32 ge=gains[q&127],gt=gains[q>>7],raw=(*sum-m)*256+m*gt+*esc*ge;
  u32 bits=32u-(u32)__builtin_clz(raw-1),shift=bits>15?bits-15:0;if((raw>>shift)>SCALE-n-1)shift++;
  u32 s=0;for(u32 j=0;j<n;j++){u32 v=masses[j]*(j==top?gt:256)>>shift;masses[j]=v?v:1;s+=masses[j];}
  u32 e=*esc*ge>>shift;*esc=e?e:1;*sum=s;
}
static u32 peek(u32 sum){return (((x%SCALE)+1)*sum-1)/SCALE;}
static void take(enum Action a,u32 lo,u32 mass,u32 sum){
  if(mass==sum)return;u32 start=lo*SCALE/sum,width=(lo+mass)*SCALE/sum-start;REQUIRE(width);
  if(a==WRITE){REQUIRE(eventN<eventCap);events[eventN++]=(start<<16)+width;}
  else{x=width*(x/SCALE)+x%SCALE-start;while(x<LOWER){REQUIRE(inPos<inLen);x=x*256+io[inPos++];}}
}
static void advance(enum Action a,u32 nbytes){
  REQUIRE(nbytes && nbytes<=FRAME && nbytes<=total-pos);u32 end=pos+nbytes;
  for(u32 i=pos;i<end;i++){
    int depth=i<4?(int)i:4,candidate=from>=0?bytes[from]:-1,done=0;u32 tag=i+1,value=a==READ?0:bytes[i],skipped=0;
    for(int k=a!=WARM||candidate>=0?depth:-1;k>=0;k--){
      u32 n=0,sum=0;int slot=-1;
      for(u32 j=node(history[k])->child;j;j=node(j)->sibling){Node *entry=node(j);u8 v=entry->symbol;if(excluded[v]==tag)continue;
        if(v==candidate)slot=(int)n;syms[n]=v;masses[n]=2*entry->freq-1;sum+=masses[n++];}
      if(!n)continue;u32 esc=n;
      while(sum+esc>SCALE){sum=0;for(u32 j=0;j<n;j++){masses[j]=(masses[j]+1)>>1;sum+=masses[j];}}
      int offered=candidate,boosted=0;
      if(candidate>=0){u32 m=slot<0?0:masses[slot];if(a==WARM){bucket(m,sum+esc);break;}
        u32 extra=bonus(m,sum+esc);if(extra){boosted=1;if(slot<0){REQUIRE(n<256);syms[n]=(u8)candidate;masses[n++]=extra;}else masses[slot]+=extra;sum+=extra;}candidate=-1;}
      if(corrections && a!=WARM)correct(i,(u32)k,skipped!=0,offered,boosted,n,&sum,&esc);
      u32 all=sum+esc,target=a==READ?peek(all):0,lo=0;
      for(u32 j=0;j<n;j++){if(a==READ?target<lo+masses[j]:value==syms[j]){value=syms[j];take(a,lo,masses[j],all);done=1;break;}lo+=masses[j];}
      if(done)break;take(a,sum,esc,all);skipped+=n;for(u32 j=0;j<n;j++)excluded[syms[j]]=tag;
    }
    if(!done && a!=WARM){REQUIRE(skipped<256);u32 left=256-skipped,target=a==READ?peek(left):0,rank=0;
      for(u32 v=0;v<256;v++)if(excluded[v]!=tag){if(a==READ?rank==target:v==value){value=v;break;}rank++;}take(a,rank,1,left);}
    if(a==READ)bytes[i]=(u8)value;observe(i,(u8)value);int learn=1;
    for(int k=depth;k>=0;k--){Node *parent=node(history[k]);u32 j=k?parent->child:roots[value];while(j&&node(j)->symbol!=value)j=node(j)->sibling;
      if(!j){j=++nodes;Node *z=fresh(j);z->symbol=(u8)value;z->sibling=parent->child;parent->child=j;if(!k)roots[value]=j;}
      Node *z=node(j);if(!z->freq)z->freq=1;else if(learn){z->freq++;learn=0;}if(k<4)history[k+1]=j;}
  }pos=end;
}
static u8 *start(u32 capacity,int enc,int expert){
  REQUIRE(capacity && capacity<=LIMIT);bump=(u32)(usize)&__heap_base;total=capacity;pos=0;writing=enc;
  corrections=expert?reserve(EXPERT_CELLS*sizeof(u16)):0;
  bytes=reserve(total);u32 frame=total<FRAME?total:FRAME;eventCap=6*frame;
  if(enc)events=reserve(4*eventCap);ioCap=4+2*eventCap;io=reserve(ioCap);
  slots=256;while(slots<total/32 && slots<131072)slots*=2;heads=reserve(4*slots);memset(heads,0,4*slots);
  pool=reserve(0);capacityNodes=seedNodes=0;nodes=1;fresh(1);memset(history,0,sizeof(history));history[0]=1;memset(roots,0,sizeof(roots));memset(excluded,0,sizeof(excluded));
  wordHash=wordLen=runLen=0;from=bin=-1;memset(hits,0,sizeof(hits));memset(trials,0,sizeof(trials));return bytes;
}
API(begin) u8 *begin(u32 capacity,int enc){return start(capacity,enc,0);}
API(begin_expert) u8 *begin_expert(u32 capacity,int enc){return start(capacity,enc,1);}
API(expert_address) u16 *expert_address(void){return corrections;}
// JS validates the canonical serialized rows before they reach this kernel.
static u8 priorRows[4*16384];
API(prior_address) u8 *prior_address(void){return priorRows;}
API(install_prior) void install_prior(u32 count){REQUIRE(!pos && nodes==1 && count<=16384);seedNodes=count;
  for(u32 i=0;i<count;i++){u8 *r=priorRows+4*i;u32 p=1+r[0]+256u*r[1],j=++nodes;REQUIRE(p<j && r[3] && r[3]<=32);
    Node *z=fresh(j);z->symbol=r[2];z->freq=r[3];z->sibling=node(p)->child;node(p)->child=j;if(p==1)roots[r[2]]=j;}}
API(warm) void warm(u32 n){advance(WARM,n);}
API(encode) u8 *encode(u32 n){REQUIRE(writing);eventN=0;advance(WRITE,n);x=LOWER;u32 p=ioCap;
  while(eventN){u32 op=events[--eventN],w=op&65535;while(x>=w*65536u){REQUIRE(p>4);io[--p]=(u8)x;x>>=8;}x=(x/w)*SCALE+x%w+(op>>16);}
  REQUIRE(p>=4);p-=4;for(u32 j=0;j<4;j++)io[p+j]=(u8)(x>>(8*j));outLen=ioCap-p;return io+p;}
API(body_size) u32 body_size(void){return outLen;}
API(io_address) u8 *io_address(void){return io;}
API(io_capacity) u32 io_capacity(void){return ioCap;}
API(decode) void decode(u32 n,u32 len){REQUIRE(!writing && len>=4 && len<=ioCap);inLen=len;inPos=4;
  x=io[0]|((u32)io[1]<<8)|((u32)io[2]<<16)|((u32)io[3]<<24);REQUIRE(x>=LOWER && x<LOWER*256u);
  advance(READ,n);REQUIRE(x==LOWER && inPos==inLen);}
