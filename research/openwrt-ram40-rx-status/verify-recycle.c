/* SPDX-License-Identifier: GPL-2.0-only */
/* Actual shared core; firmware, DMA and OS effects are synthetic. */
#define C80_NET_LIBRARY
#include "verify-netdev.c"

struct cycle_model {
    struct net_model base;
    unsigned mode,posts,notified,barriers,ordered,jumped,frozen;
    c80_u64 frozen_us;
    unsigned busy[C80_NET_RECYCLE_N];
    unsigned expected_bytes;
    c80_u8 expected_payload[C80_NET_MTU];
    struct c80_net_cell snapshot[C80_NET_RECYCLE_N];
};
static unsigned cycle_cases;
static struct model *cm(struct cycle_model *x) { return nm(&x->base); }
static void cycle_owned(struct cycle_model *x)
{
    association_pinned(&x->base.parent);
    for(unsigned i=0;i<C80_NET_RECYCLE_N;++i)
        if(x->busy[i]) assert(!memcmp(&x->snapshot[i],&cm(x)->pool.net.tx[i],sizeof(x->snapshot[i])));
}
static c80_u32 cycle_read(void *o,c80_u32 a)
{ struct cycle_model *x=o;cycle_owned(x);return association_read(o,a); }
static void cycle_write(void *o,c80_u32 a,c80_u32 val)
{
    struct cycle_model *x=o;struct model *m=cm(x);struct c80_net_result *n=&m->result.net;
    cycle_owned(x);
    if(a==C80_AUTH_RING+8 && m->phase==37 && n->inflight) {
        unsigned count=x->posts,index=count%C80_NET_RECYCLE_N,slot=(count+2)%C80_NET_RECYCLE_RING_N;
        assert(val<C80_NET_RECYCLE_RING_N && C80_NET_RECYCLE_RING_N==128u);
        struct c80_desc *d=&m->pool.auth_tx[slot];struct c80_net_cell *c=&m->pool.net.tx[index];
        assert(n->submitted==count+1 && n->inflight==index+1 && n->active_slot==slot && val==(slot+1)%C80_NET_RECYCLE_RING_N);
        assert(n->active_token==16+count%C80_NET_TOKEN_COUNT && n->cell_generation[index]==count+1 && n->descriptor_generation[slot]==count+1);
        assert(!x->busy[index] && n->token[index]==C80_NET_SUBMITTED && x->barriers==count+1);
        assert(d->ctrl==0x40400000 && !d->info && d->addr==c80_dma_address(&m->io,c->header) && d->addr1==c80_dma_address(&m->io,c->frame));
        assert(c80_get16(c->header+32)==(0x8000|n->active_token));
        assert(c80_get16(c->frame+22)==(((count+2)&4095)<<4));
        unsigned wi=x->base.kind?7:1,raw; c80_u8 frame[C80_NET_FRAME_MAX],h[64]={0};
        if(x->mode==22) {
            raw=32+x->expected_bytes;memcpy(frame,wire[7],32);memcpy(frame+32,x->expected_payload,x->expected_bytes);
        } else { raw=wire_size[wi];memcpy(frame,wire[wi],raw); }
        c80_put16(frame+22,((count+2)&4095)<<4);assert(!memcmp(frame,c->frame,raw));
        memcpy(h,data_txd,32);c80_put16(h,32+raw);c80_put16(h+32,0x8000|n->active_token);
        c80_put32(h+40,d->addr1);c80_put16(h+44,0x8000|raw);assert(!memcmp(h,c->header,64));
        memcpy(&x->snapshot[index],c,sizeof(*c));x->busy[index]=1;++x->posts;
        if(x->mode!=6) *regptr(m,a)=val;
        if(x->mode!=2 && x->mode!=4) { d->ctrl|=C80_DONE;*regptr(m,C80_AUTH_RING+12)=val; }
        if(x->mode==7) d->addr^=16;
        if(x->mode==8) *regptr(m,C80_AUTH_RING+12)=(val+1)%C80_NET_RECYCLE_RING_N;
        return;
    }
    association_write(o,a,val);
}
static void cycle_barrier(void *o,int publish)
{
    struct cycle_model *x=o;struct model *m=cm(x);cycle_owned(x);association_barrier(o,publish);
    unsigned i=m->result.net.submitted%C80_NET_RECYCLE_N,s=(m->result.net.submitted+2)%C80_NET_RECYCLE_RING_N;
    struct c80_desc *d=&m->pool.auth_tx[s];
    if(publish && m->phase==37 && m->result.net.linked && !m->result.net.inflight &&
       d->ctrl==0x40400000 && d->addr==c80_dma_address(&m->io,m->pool.net.tx[i].header)) ++x->barriers;
}
static void cycle_link(void *o,int on)
{ struct cycle_model *x=o;cycle_owned(x);if(on)++x->base.links;else ++x->base.closes; }
static void cycle_complete(void *o,c80_u32 bytes)
{
    struct cycle_model *x=o;struct model *m=cm(x);struct c80_net_result *n=&m->result.net;
    unsigned i=(n->completed-1)%C80_NET_RECYCLE_N;cycle_owned(x);
    assert(x->busy[i] && n->token[i]==7 && !n->inflight && n->headers==n->completed && n->returned==n->completed);
    x->busy[i]=0;
    if(x->mode==22) { assert(bytes==14+x->expected_bytes);++x->base.complete; }
    else nc(&x->base,bytes);
}
static c80_u32 cycle_dequeue(void *o,c80_u8 *p,c80_u32 capacity)
{
    struct cycle_model *x=o;c80_u32 bytes=nd(&x->base,p,capacity);
    if(!bytes || x->mode!=22) return bytes;
    const unsigned sizes[]={20,21,28,60,64,128,300,512,1024,1399,1400};
    unsigned len=sizes[x->posts%(sizeof(sizes)/sizeof(sizes[0]))];assert(14+len<=capacity);
    for(unsigned i=0;i<len;++i)x->expected_payload[i]=(x->posts*13+i*7)&255;
    x->expected_payload[0]=0x45;c80_setbe16(x->expected_payload+2,len);c80_setbe16(x->expected_payload+6,0x4000);
    memcpy(p,peer,6);if(x->posts%4==0)memset(p,255,6);memcpy(p+6,synthetic_nvm+4,6);c80_setbe16(p+12,0x800);
    memcpy(p+14,x->expected_payload,len);x->expected_bytes=len;return 14+len;
}
static int cycle_stop(void *o)
{
    struct cycle_model *x=o;struct model *m=cm(x);struct c80_net_result *n=&m->result.net;
    if(x->mode==16) return m->phase==38;
    if(x->mode==14 || x->mode==15) return n->inflight!=0;
    if(x->mode==19) return 0; /* Frozen-clock detector, never target-stop. */
    return n->linked && n->completed>=x->base.wanted;
}
static c80_u64 cycle_time(void *o)
{
    struct cycle_model *x=o;struct model *m=cm(x);
    if(x->mode==19 && m->phase==37 && m->result.net.completed) {
        if(!x->frozen) { x->frozen=1;x->frozen_us=m->us; }
        return x->frozen_us;
    }
    return m->us;
}
static void cycle_notice(struct cycle_model *x,unsigned token)
{
    struct model *m=cm(x);unsigned i=x->base.parent.base.auth.em.producer;
    assert(!(m->pool.rx[1][i].ctrl&C80_DONE));unsigned count=x->mode==10 || x->mode==12?2:1;
    unsigned bytes=notification(m->pool.data[1][i],1,count,token);
    if(x->mode==10)c80_put16(m->pool.data[1][i]+12,token);
    if(x->mode==12)c80_put16(m->pool.data[1][i]+12,4096);
    m->pool.rx[1][i].ctrl=C80_DONE|C80_LS0|(bytes<<16);
    x->base.parent.base.auth.em.producer=(i+1)%64;m->rx_next[1]=(i+1)%64;
}
static void cycle_delay(void *o,c80_u32 us)
{
    struct cycle_model *x=o;struct model *m=cm(x);struct c80_net_result *n=&m->result.net;
    cycle_owned(x);association_delay(o,us);
    if(m->phase!=37 || !n->linked) return;
    if(n->inflight && x->mode==4 && m->us-n->submitted_us>=4000) {
        if((n->token[n->inflight-1]&C80_NET_RETURNED) && !(n->token[n->inflight-1]&C80_NET_HEADER_DONE)) x->ordered=1;
        m->pool.auth_tx[n->active_slot].ctrl|=C80_DONE;*regptr(m,C80_AUTH_RING+12)=(n->active_slot+1)%C80_NET_RECYCLE_RING_N;
    }
    if(n->inflight && x->mode==5 && (n->token[n->inflight-1]&C80_NET_HEADER_DONE))x->ordered=1;
    if(x->notified<x->posts && x->mode!=1 && x->mode!=15 && (x->mode!=5 || m->us-n->submitted_us>=4000)) {
        unsigned token=n->active_token;if(x->mode==9)token=token==4095?16:token+1;
        if(x->mode==11 && x->posts==17)token=16;
        cycle_notice(x,token);++x->notified;
    }
    if(x->mode==13 && n->completed>=512) *regptr(m,C80_GLO)&=~4u;
    if((x->mode==17 || x->mode==18 || x->mode==21) && n->completed && !x->jumped) {
        if(x->mode==18)m->us-=10000;
        else m->us+=x->mode==21?0x100000100ull:200000000ull;
        x->jumped=1;
    }
    if(x->mode!=19 && !n->closed && x->base.requests<x->base.wanted && x->base.requests<=n->completed)
        input(&x->base,x->base.requests!=0);
    if(x->mode==19 && !x->base.requests && !n->closed)input(&x->base,0);
}
static struct cycle_model *cycle_new(unsigned count,unsigned mode)
{
    struct net_model *b=nnew(count,0);struct cycle_model *x=calloc(1,sizeof(*x));assert(x);memcpy(&x->base,b,sizeof(*b));free(b);
    struct model *m=cm(x);x->mode=mode;m->io.context=x;m->io.pool=&m->pool;m->io.net_recycle_test=1;
    m->io.read=cycle_read;m->io.write=cycle_write;m->io.dma_order=cycle_barrier;m->io.delay_us=cycle_delay;m->io.time_us=cycle_time;
    m->io.net_link=cycle_link;m->io.net_complete=cycle_complete;m->io.net_dequeue=cycle_dequeue;m->io.net_stop_requested=cycle_stop;return x;
}
static void cycle_full(unsigned count,unsigned mode,unsigned expected)
{
    struct cycle_model *x=cycle_new(count,mode);struct model *m=cm(x);struct c80_result *r=&m->result;
    unsigned rc=c80_run(&m->io,firmware,r);struct c80_net_result *n=&r->net;
    if(rc!=expected)fprintf(stderr,"RECYCLE count%u mode%u got%u expected%u posts%u done%u phase%u\n",count,mode,rc,expected,n->submitted,n->completed,m->phase);
    assert(rc==expected);
    if(rc && n->inflight) {
        assert(r->failure_snapshot && r->failure_ring==5 && r->failure_phase==37);
        assert(r->failure_slot==n->active_slot);
        assert(r->failure_desc[1]==m->pool.auth_tx[n->active_slot].ctrl);
    }
    cycle_owned(x);assert(!r->critical && !r->cleanup && r->dma_idle && r->mcu_stopped && n->closed && x->base.closes==1);
    if(!mode || mode==4 || mode==5 || mode==17 || mode==21 || mode==22) {
        assert(n->stop_requested && n->submitted==count && n->headers==count && n->returned==count && n->completed==count && x->base.complete==count && !n->inflight);
        assert(!n->exhausted && !n->token_fault && !n->stale_tokens && r->sta_valid[1] && r->beacon_valid[2] && r->beacon_valid[3]);
        assert(n->payload_reuses==(count>C80_NET_RECYCLE_N?count-C80_NET_RECYCLE_N:0));
        assert(n->ring_wraps==(count+2)/C80_NET_RECYCLE_RING_N && n->token_wraps==(count?(count-1)/C80_NET_TOKEN_COUNT:0));
        assert(r->auth_ring_after[3]==(count+2)%C80_NET_RECYCLE_RING_N);
        if(count)assert(n->rx_delivered==count);
    }
    if(mode==4 || mode==5)assert(x->ordered);
    if(mode==11)assert(n->submitted==17 && n->completed==16 && n->payload_reuses==1 && n->token_fault);
    if(mode==14)assert(n->stop_requested && n->completed==1 && !n->inflight && r->sta_valid[1]);
    if(mode==15)assert(n->stop_requested && n->inflight && !n->completed);
    if(mode==16)assert(n->stop_requested && !n->submitted && !r->beacon_attempted[0] && r->devinfo_valid[1]);
    if(mode==17)assert(n->active_us>180000000ull);
    if(mode==21)assert(n->active_us>0xffffffffull && r->watch[1].elapsed_us==0xffffffffu);
    for(unsigned i=0;i<C80_NET_RECYCLE_N;++i)if(n->cell_generation[i])assert(!memcmp(&x->snapshot[i],&m->pool.net.tx[i],sizeof(x->snapshot[i])));
    printf("PASS RECYCLE-full count%u mode%u rc%u posts%u done%u payload_reuse%u ring_wrap%u token_wrap%u\n",count,mode,rc,n->submitted,n->completed,n->payload_reuses,n->ring_wraps,n->token_wraps);
    ++cycle_cases;free(x);
}
static void cycle_ledger(unsigned fault)
{
    struct cycle_model *x=cycle_new(0,0);struct model *m=cm(x);struct c80_net_result *n=&m->result.net;
    m->phase=m->result.phase=37;m->result.auth_ring_programmed=m->result.auth_dma_done=m->result.auth_token_returned=1;
    m->result.assoc_submitted=m->result.assoc_dma_done=m->result.assoc_token_returned=m->result.sta_valid[0]=1;
    n->prepared=n->enabled=n->linked=n->recycling=1;n->submitted=n->completed=512;
    n->cell_generation[0]=497;n->token[0]=7;n->descriptor_generation[2]=513-C80_NET_RECYCLE_RING_N;
    *regptr(m,C80_AUTH_RING)=c80_dma_address(&m->io,m->pool.auth_tx);*regptr(m,C80_AUTH_RING+4)=C80_NET_RECYCLE_RING_N;
    *regptr(m,C80_AUTH_RING+8)=*regptr(m,C80_AUTH_RING+12)=2;
    struct c80_desc *d=&m->pool.auth_tx[2];d->ctrl=C80_DONE|C80_LS0|(64u<<16);d->addr=c80_dma_address(&m->io,m->pool.net.tx[0].header);d->addr1=c80_dma_address(&m->io,m->pool.net.tx[0].frame);
    x->base.queued=1;x->base.response_bytes=42;
    switch(fault) {
    case 0:n->cell_generation[0]=498;break;case 1:n->cell_generation[0]=513;break;
    case 2:n->token[0]=C80_NET_SUBMITTED|C80_NET_HEADER_DONE;break;case 3:n->token[0]=C80_NET_SUBMITTED|C80_NET_RETURNED;break;
    case 4:n->descriptor_generation[2]=2;break;case 5:n->descriptor_generation[2]=513;break;
    case 6:d->ctrl&=~C80_DONE;break;case 7:d->addr^=16;break;case 8:d->addr1^=16;break;case 9:d->info=1;break;
    case 10:n->token_fault=1;break;case 11:n->submitted=n->completed=0xffffffffu;break;
    case 12:n->completed=511;break;case 13:n->recycling=0;break;
    default:assert(0);
    }
    struct c80_net_cell prior=m->pool.net.tx[0];unsigned old=n->submitted;
    unsigned rc=c80_net_step(&m->io,&m->result);
    assert(rc==(fault==10?C80_NET_TOKEN:fault==11?C80_NET_COUNTER:fault==13?C80_NET_PREREQ:C80_NET_REUSE));
    assert(n->submitted==old && !memcmp(&prior,&m->pool.net.tx[0],sizeof(prior)) && !x->posts);
    printf("PASS RECYCLE-ledger%u refuses before payload reuse rc%u\n",fault,rc);++cycle_cases;free(x);
}
#ifndef C80_SCHED_LIBRARY
int main(int argc,char **argv)
{
    c80_netdev_test_entry(argc,argv);
    const char *names[]={"test_mcu.bin","test_wifi.bin","WIFI_RAM_CODE_iemi.bin","WIFI_RAM_CODE_demi.bin","mt7626_patch_e1_hdr.bin","WIFI_RAM_CODE_7626.bin"};
    for(unsigned i=0;i<6;++i){char path[4096];snprintf(path,sizeof(path),"%s/%s",argv[1],names[i]);FILE *f=fopen(path,"rb");assert(f);firmware[i].data=malloc(firmware[i].bytes);assert(fread((void *)firmware[i].data,1,firmware[i].bytes,f)==firmware[i].bytes);fclose(f);}
    unsigned counts[]={0,1,16,17,125,126,127,128,129,256,510,511,512,513,1025,4080,4081,8160,9000,32770,131074};
    for(unsigned i=0;i<sizeof(counts)/sizeof(counts[0]);++i)cycle_full(counts[i],0,0);
    for(unsigned mode=1;mode<=19;++mode)if(mode!=3) {
        unsigned rc=mode==1 || mode==2 || mode==15?73:mode==6?72:mode==7 || mode==8?71:mode==9 || mode==10 || mode==11?75:mode==12?58:mode==13?44:mode==18 || mode==19?5:0;
        cycle_full(mode==11?18:mode==13?513:2,mode,rc);
    }
    cycle_full(2,21,0);
    cycle_full(8193,22,0);
    for(unsigned i=0;i<14;++i)cycle_ledger(i);
    for(unsigned i=0;i<6;++i)free((void *)firmware[i].data);
    printf("PASS: %u new actual-core recyclable-TX cases; plus601 netdev+589 data cases; ASan/UBSan; synthetic firmware/DMA/OS effects.\n",cycle_cases);return 0;
}
#endif
