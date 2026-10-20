/* SPDX-License-Identifier: GPL-2.0-only */
/* Actual transport core. The host/network/MCU/device callbacks below are
 * synthetic. QEMU separately exercises the real Linux packet callbacks. */
#define C80_DATA_LIBRARY
#include "verify-data.c"
struct net_model {
    struct association_model parent;
    unsigned fault,wanted,requests,queued,kind,pubs,notices,complete,prepare,links,closes,barriers;
    unsigned ordered,stop_at_control;
    c80_u8 response[C80_NET_ETH_MAX],received[C80_NET_ETH_MAX];unsigned response_bytes,received_bytes;
    struct c80_net_cell pinned[C80_NET_TX_N];
};
static unsigned net_cases;
static struct model *nm(struct net_model *x) { return &x->parent.base.auth.em.m; }
static void pinned(struct net_model *x)
{
    association_pinned(&x->parent);
    for(unsigned i=0;i<x->pubs;++i) assert(!memcmp(&x->pinned[i],&nm(x)->pool.net.tx[i],sizeof(x->pinned[i])));
}
static int np(void *o,const c80_u8 *mac)
{ struct net_model *x=o;assert(!memcmp(mac,synthetic_nvm+4,6) && !nm(x)->writes);++x->prepare;return x->fault==20?-1:0; }
static void nl(void *o,int on)
{ struct net_model *x=o;if(on) { assert(nm(x)->result.assoc_token_returned);++x->links; } else { ++x->closes;pinned(x); } }
static int nr(void *o,const c80_u8 *p,c80_u32 bytes)
{
    struct net_model *x=o;assert(bytes<=sizeof(x->received));memcpy(x->received,p,bytes);x->received_bytes=bytes;
    if(x->fault==21) return -1;
    unsigned k=c80_be16(p+12)==0x806?0:1,wi=k?7:1;
    assert(bytes==wire_size[k?6:0] && !memcmp(p,wire[k?6:0],bytes));
    assert(!x->queued);memcpy(x->response,peer,6);memcpy(x->response+6,synthetic_nvm+4,6);
    memcpy(x->response+12,wire[wi]+30,wire_size[wi]-30);x->response_bytes=wire_size[wi]-18;x->queued=1;x->kind=k;
    return 0;
}
static c80_u32 nd(void *o,c80_u8 *p,c80_u32 cap)
{ struct net_model *x=o;if(!x->queued) return 0;assert(x->response_bytes<=cap);memcpy(p,x->response,x->response_bytes);x->queued=0;return x->response_bytes; }
static void nc(void *o,c80_u32 bytes)
{ struct net_model *x=o;assert(bytes==42 || bytes==74);++x->complete; }
static int ns(void *o)
{ struct net_model *x=o;return (x->fault==22 && nm(x)->result.net.completed>=1) || ((x->fault==23 || x->fault==25) && nm(x)->result.net.inflight) || (x->fault==24 && nm(x)->phase==38); }
static c80_u32 nread(void *o,c80_u32 a)
{ return association_read(o,a); }
static void nwrite(void *o,c80_u32 a,c80_u32 val)
{
    struct net_model *x=o;struct model *m=nm(x);struct c80_net_result *n=&m->result.net;
    if(a==C80_AUTH_RING+8 && m->phase==37 && val>=3) {
        unsigned i=val-3;struct c80_net_cell *cell=&m->pool.net.tx[i];struct c80_desc *d=&m->pool.auth_tx[i+2];
        assert(i==x->pubs && i<C80_NET_TX_N && n->submitted==i+1 && n->token[i]==C80_NET_SUBMITTED && x->barriers==x->pubs+1);
        assert(d->ctrl==0x40400000 && !d->info && d->addr==c80_dma_address(&m->io,cell->header) && d->addr1==c80_dma_address(&m->io,cell->frame));
        unsigned wi=x->kind?7:1; c80_u8 expected[160];memcpy(expected,wire[wi],wire_size[wi]);c80_put16(expected+22,(i+2)<<4);
        assert(!memcmp(expected,cell->frame,wire_size[wi]));
        c80_u8 h[64]={0};memcpy(h,data_txd,32);c80_put16(h,32+wire_size[wi]);c80_put16(h+32,0x8000|(C80_NET_TOKEN_BASE+i));c80_put32(h+40,d->addr1);c80_put16(h+44,0x8000|wire_size[wi]);
        assert(!memcmp(h,cell->header,64));pinned(x);memcpy(&x->pinned[i],cell,sizeof(*cell));++x->pubs;
        if(x->fault!=3) *regptr(m,a)=val;
        if(x->fault!=2 && x->fault!=4 && x->fault!=6) d->ctrl|=C80_DONE;
        if(x->fault!=2 && x->fault!=4 && x->fault!=7) *regptr(m,C80_AUTH_RING+12)=val;
        if(x->fault==5) d->addr^=16;
        return;
    }
    association_write(o,a,val);
}
static void nb(void *o,int publish)
{
    struct net_model *x=o;struct model *m=nm(x);association_barrier(o,publish);
    unsigned i=m->result.net.submitted;
    if(publish && m->phase==37 && i<C80_NET_TX_N && m->pool.auth_tx[i+2].addr==c80_dma_address(&m->io,m->pool.net.tx[i].header) && m->pool.auth_tx[i+2].ctrl==0x40400000 && !m->result.net.token[i]) ++x->barriers;
}
static void note(struct net_model *x,unsigned token)
{
    struct model *m=nm(x);unsigned i=x->parent.base.auth.em.producer;
    assert(!(m->pool.rx[1][i].ctrl&C80_DONE));unsigned bytes=notification(m->pool.data[1][i],1,1,token);
    m->pool.rx[1][i].ctrl=C80_DONE|C80_LS0|(bytes<<16);x->parent.base.auth.em.producer=(i+1)%64;m->rx_next[1]=x->parent.base.auth.em.producer;
}
static void input(struct net_model *x,unsigned kind)
{
    struct model *m=nm(x);unsigned i=m->result.rx_next[0];assert(!(m->pool.rx[0][i].ctrl&C80_DONE));
    unsigned bytes=data_packet(m->pool.data[0][i],kind,1,8,0,0,2);
    c80_put16(m->pool.data[0][i]+24,(x->requests+4)<<4);
    m->pool.rx[0][i].ctrl=C80_DONE|C80_LS0|(bytes<<16);++x->requests;
}
static void n_delay(void *o,c80_u32 us)
{
    struct net_model *x=o;struct model *m=nm(x);association_delay(o,us);
    if(m->phase!=37 || !m->result.net.linked) return;
    struct c80_net_result *n=&m->result.net;
    if(n->inflight && x->fault==4 && m->us-n->submitted_us>=3000) {
        unsigned i=n->inflight-1;
        if((n->token[i]&C80_NET_RETURNED) && !(n->token[i]&C80_NET_HEADER_DONE)) x->ordered=1;
        m->pool.auth_tx[i+2].ctrl|=C80_DONE;*regptr(m,C80_AUTH_RING+12)=i+3;
    }
    if(n->inflight && x->fault==8 && (n->token[n->inflight-1]&C80_NET_HEADER_DONE)) x->ordered=1;
    if(x->notices<x->pubs && x->fault!=1 && x->fault!=2 && x->fault!=6 && x->fault!=7 && x->fault!=25 &&
       (x->fault!=8 || m->us-n->submitted_us>=4000)) {
        note(x,C80_NET_TOKEN_BASE+x->notices);++x->notices;
    }
    if(!n->closed && x->requests<x->wanted && x->requests<=n->completed) input(x,x->requests!=0);
}
static struct net_model *nnew(unsigned count,unsigned fault)
{
    struct association_model *p=association_new(0);struct net_model *x=calloc(1,sizeof(*x));assert(x);memcpy(&x->parent,p,sizeof(*p));free(p);
    struct model *m=nm(x);x->wanted=count;x->fault=fault;m->io.context=x;m->io.pool=&m->pool;
    m->io.netdev_test=1;m->io.data_echo_test=0;m->io.long_beacon_test=1;m->io.net_prepare=np;m->io.net_link=nl;m->io.net_receive=nr;m->io.net_dequeue=nd;m->io.net_complete=nc;m->io.net_stop_requested=ns;
    m->io.read=nread;m->io.write=nwrite;m->io.delay_us=n_delay;m->io.dma_order=nb;return x;
}
static void full(unsigned count,unsigned fault,unsigned expected)
{
    struct net_model *x=nnew(count,fault);struct model *m=nm(x);unsigned rc=c80_run(&m->io,firmware,&m->result);struct c80_net_result *n=&m->result.net;
    if(rc!=expected) fprintf(stderr,"NET FULL count%u fault%u got%u expected%u pub%u done%u phase%u\n",count,fault,rc,expected,n->submitted,n->completed,m->phase);
    assert(rc==expected);pinned(x);
    assert(!m->result.critical && !m->result.cleanup);
    if(fault!=20) assert(m->result.dma_idle && m->result.mcu_stopped && n->closed && x->closes==1);
    if(!fault || fault==4 || fault==8) {
        assert(n->submitted==count && n->headers==count && n->returned==count && n->completed==count && x->complete==count && !n->inflight);
        assert(m->result.diag_submissions==0 && m->result.sta_valid[1] && m->result.watch[1].complete && m->result.auth_ring_after[3]==2+count);
        assert(n->exhausted==(count==C80_NET_TX_N));if(count) assert(n->rx_delivered==count);
    }
    if(fault==4 || fault==8) assert(x->ordered);
    if(fault==21) assert(n->rx_dropped==1 && !n->submitted);
    if(fault==22 || fault==23) assert(n->stop_requested && m->result.beacon_valid[2] && m->result.beacon_valid[3] && m->result.radio_valid[4] && m->result.sta_valid[1]);
    if(fault==24) assert(n->stop_requested && !n->submitted && !m->result.beacon_attempted[0] && m->result.radio_valid[4] && m->result.bss_valid[1] && m->result.devinfo_valid[1]);
    if(fault==23) assert(n->submitted==1 && n->completed==1 && !n->inflight);
    printf("PASS NET-full count%u fault%u rc%u posts%u done%u retained-by-contract\n",count,fault,rc,n->submitted,n->completed);++net_cases;free(x);
}
static void unit(unsigned kind,unsigned t,unsigned group,unsigned pad,unsigned qos)
{
    struct net_model *x=nnew(0,0);struct model *m=nm(x);struct c80_result *r=&m->result;unsigned off=16+16*!!(group&8)+16*!!(group&1)+8*!!(group&2)+24*!!(group&4)+2*pad;c80_u8 v[512];
    memcpy(m->pool.nvm_payload+8,synthetic_nvm+4,6);memcpy(m->pool.auth_frame+4,peer,6);
    r->phase=37;r->assoc_submitted=r->assoc_dma_done=r->assoc_token_returned=r->sta_valid[0]=r->net.linked=1;
    unsigned bytes=data_packet(v,kind,t,group,pad,qos,2);c80_net_receive(&m->io,r,v,bytes,off);
    assert(r->net.rx_delivered==1 && x->received_bytes==wire_size[kind?6:0] && !memcmp(x->received,wire[kind?6:0],x->received_bytes));assert(!m->writes && !r->net.submitted);
    printf("PASS NET-unit kind%u translated%u groups%x pad%u QoS%u\n",kind,t,group,pad,qos);++net_cases;free(x);
}
static void rx_fault(unsigned fault)
{
    struct net_model *x=nnew(0,0);struct model *m=nm(x);struct c80_result *r=&m->result;c80_u8 v[512];
    memcpy(m->pool.nvm_payload+8,synthetic_nvm+4,6);memcpy(m->pool.auth_frame+4,peer,6);
    r->phase=37;r->assoc_submitted=r->assoc_dma_done=r->assoc_token_returned=r->sta_valid[0]=r->net.linked=1;
    unsigned bytes=data_packet(v,1,1,8,0,0,2),off=32;c80_u8 *p=v+32,*ip=p+14;
    switch(fault) {
    case 0:v[10]|=2;break;case 1:v[10]|=16;break;case 2:v[10]|=128;break;case 3:v[11]|=1;break;case 4:v[11]|=2;break;case 5:v[9]|=0x10;break;
    case 6:v[8]=2;break;case 7:v[18]^=2;break;case 8:p[6]^=2;break;case 9:p[0]^=2;break;case 10:v[3]&=~0x10;break;
    case 11:c80_put16(v+16,0x4108);break;case 12:c80_put16(v+16,0x8108);break;case 13:c80_put16(v+16,0x0308);break;case 14:v[24]|=1;break;case 15:v[7]=1;break;
    case 16:ip[0]=0x41;break;case 17:ip[0]=0x65;break;case 18:ip[2]=0xff;break;case 19:ip[6]=0x20;break;case 20:p[12]=0x86;p[13]=0xdd;break;
    case 21:r->phase=38;break;case 22:r->net.linked=0;break;case 23:r->net.closed=1;break;case 24:r->sta_valid[0]=0;break;case 25:r->sta_status[0]=1;break;
    case 26:r->sta_attempted[1]=1;break;case 27:r->assoc_dma_done=0;break;case 28:r->assoc_token_returned=0;break;case 29:m->io.netdev_test=0;break;
    case 30:bytes=15;break;case 31:off=bytes+1;break;case 32:off=31;break;case 33:bytes=C80_RX_SIZE+1;break;
    default:assert(0);
    }
    c80_net_receive(&m->io,r,v,bytes,off);assert(!r->net.rx_delivered && !x->queued && !m->writes);
    printf("PASS NET-RX-reject%u\n",fault);++net_cases;free(x);
}
static void net_free_cases(void)
{
    struct c80_result *r=calloc(1,sizeof(*r));c80_u8 v[32];assert(r);r->net.enabled=1;
    c80_net_free(r,16);assert(r->net.early_tokens==1 && !r->net.token[0]);++net_cases;puts("PASS NET-token-before-publish cannot pre-complete");
    r->net.token[0]=C80_NET_SUBMITTED;c80_net_free(r,16);assert(r->net.token[0]==5 && r->net.returned==1);++net_cases;puts("PASS NET-token-before-header preserves independent ownership");
    c80_net_free(r,16);assert(r->net.returned==1 && r->net.duplicate_tokens==1);++net_cases;puts("PASS NET-duplicate-token no extra completion");
    memset(r,0,sizeof(*r));r->net.enabled=1;r->net.token[0]=1;notification(v,1,2,16);c80_put16(v+12,4096);
    assert(c80_rx1_non_event(r,v,16,6)==C80_RX1_NOTIFY_BAD && r->net.token[0]==1 && !r->net.returned);++net_cases;puts("PASS NET-token-list whole validation before mutation");free(r);
}
static int capture_only(void *o,const c80_u8 *p,c80_u32 bytes)
{ struct net_model *x=o;assert(bytes<=sizeof(x->received));memcpy(x->received,p,bytes);x->received_bytes=bytes;return 0; }
static void frame_sizes(void)
{
    const unsigned sizes[]={20,21,28,60,64,300,328,512,1024,1399,1400};
    for(unsigned k=0;k<sizeof(sizes)/sizeof(sizes[0]);++k) for(unsigned broadcast=0;broadcast<2;++broadcast) {
        struct net_model *x=nnew(0,0);struct model *m=nm(x);c80_u8 *e=m->pool.net.ethernet;
        memcpy(m->pool.nvm_payload+8,synthetic_nvm+4,6);memcpy(m->pool.auth_frame+4,peer,6);
        memcpy(e,peer,6);if(broadcast)memset(e,255,6);memcpy(e+6,synthetic_nvm+4,6);c80_setbe16(e+12,0x800);
        unsigned len=sizes[k];for(unsigned i=0;i<len;++i)e[14+i]=(i*17+31)&255;e[14]=0x45;c80_setbe16(e+16,len);c80_setbe16(e+20,0x4000);
        unsigned index=C80_NET_TX_N-1;assert(c80_net_frame(&m->io,index,14+len)==14+len);struct c80_net_cell *cell=&m->pool.net.tx[index];
        assert(c80_get16(cell->header)==64+len && c80_get16(cell->header+32)==0x810f && c80_get16(cell->header+44)==(0x8000|(32+len)));
        assert(!memcmp(cell->frame+4,peer,6) && !memcmp(cell->frame+10,synthetic_nvm+4,6) && !memcmp(cell->frame+32,e+14,len));assert(!m->writes);
        printf("PASS NET-TX-codec IPv4-bytes%u broadcast%u final_unique_token271\n",len,broadcast);++net_cases;free(x);
    }
    for(unsigned fault=0;fault<9;++fault) {
        struct net_model *x=nnew(0,0);struct model *m=nm(x);c80_u8 *e=m->pool.net.ethernet;
        memcpy(m->pool.nvm_payload+8,synthetic_nvm+4,6);memcpy(m->pool.auth_frame+4,peer,6);memcpy(e,peer,6);memcpy(e+6,synthetic_nvm+4,6);c80_setbe16(e+12,0x800);e[14]=0x45;c80_setbe16(e+16,20);unsigned len=34,index=0;
        switch(fault) {case 0:len=13;break;case 1:len=C80_NET_ETH_MAX+1;break;case 2:e[0]^=2;break;case 3:e[6]^=2;break;case 4:e[14]=0x44;break;case 5:c80_setbe16(e+16,1401);break;case 6:c80_setbe16(e+20,0x2000);break;case 7:e[12]=0x86;e[13]=0xdd;break;case 8:index=C80_NET_TX_N;break;default:assert(0);}
        assert(!c80_net_frame(&m->io,index,len));struct c80_net_cell zero={0};assert(!memcmp(&zero,&m->pool.net.tx[0],sizeof(zero)) && !m->writes);
        printf("PASS NET-TX-reject%u no_DMA_mutation\n",fault);++net_cases;free(x);
    }
}
static void net_guard(unsigned bytes,unsigned translated)
{
    long page=sysconf(_SC_PAGESIZE);void *map=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(map!=MAP_FAILED);assert(!mprotect((char *)map+page,page,PROT_NONE));
    c80_u8 full[512],*input=(c80_u8 *)map+page-bytes;data_packet(full,1,translated,translated?8:0,0,0,2);memcpy(input,full,bytes);
    struct net_model *x=nnew(0,0);struct model *m=nm(x);struct c80_result *r=&m->result;memcpy(m->pool.nvm_payload+8,synthetic_nvm+4,6);memcpy(m->pool.auth_frame+4,peer,6);
    r->phase=37;r->assoc_submitted=r->assoc_dma_done=r->assoc_token_returned=r->sta_valid[0]=r->net.linked=1;m->io.net_receive=capture_only;
    c80_net_receive(&m->io,r,input,bytes,translated?32:16);assert(!m->writes);free(x);assert(!munmap(map,2*page));
    printf("PASS NET-guard bytes%u translated%u\n",bytes,translated);++net_cases;
}
int main(int argc,char **argv)
{
    /* Run all589 existing data cases too, then reload released firmware. */
    c80_data_test_entry(argc,argv);
    const char *names[]={"test_mcu.bin","test_wifi.bin","WIFI_RAM_CODE_iemi.bin","WIFI_RAM_CODE_demi.bin","mt7626_patch_e1_hdr.bin","WIFI_RAM_CODE_7626.bin"};
    for(unsigned i=0;i<6;++i) { char path[4096];snprintf(path,sizeof(path),"%s/%s",argv[1],names[i]);FILE *f=fopen(path,"rb");assert(f);firmware[i].data=malloc(firmware[i].bytes);assert(fread((void *)firmware[i].data,1,firmware[i].bytes,f)==firmware[i].bytes);fclose(f); }
    full(0,0,0);full(2,0,0);full(64,0,0);full(256,0,0);
    full(2,1,73);full(2,2,73);full(2,3,72);full(2,4,0);full(2,5,71);full(2,6,73);full(2,7,73);full(2,8,0);
    full(1,20,70);full(1,21,0);full(1,22,0);full(2,23,0);full(1,24,0);full(2,25,73);
    for(unsigned k=0;k<2;++k) for(unsigned g=0;g<16;++g) for(unsigned pad=0;pad<2;++pad) for(unsigned q=0;q<2;++q) for(unsigned t=0;t<2;++t) if(!t || (g&8)) unit(k,t,g,pad,q);
    for(unsigned f=0;f<34;++f) rx_fault(f);
    net_free_cases();frame_sizes();
    for(unsigned t=0;t<2;++t) for(unsigned bytes=0;bytes<=160;++bytes) net_guard(bytes,t);
    for(unsigned i=0;i<6;++i) free((void *)firmware[i].data);
    printf("PASS: %u new actual-core Linux packet-adapter cases; plus589 legacy data cases; ASan/UBSan; synthetic host/device effects.\n",net_cases);return 0;
}
