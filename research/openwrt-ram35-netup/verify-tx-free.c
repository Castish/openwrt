/* SPDX-License-Identifier: GPL-2.0-only */
#define C80_AUTH_LIBRARY
#include "verify-auth-tx.c"
static unsigned free_cases;
static void passed(const char *kind,unsigned a,unsigned b)
{ printf("PASS TXFREE-%s %u/%u\n",kind,a,b);++free_cases; }
static unsigned notification(c80_u8 *p,unsigned version,unsigned count,unsigned token)
{
    unsigned stride=version?4:2,n=8+count*stride,dma=(n+3)&~3u;memset(p,0,dma);
    c80_put32(p,(6u<<29)|(count<<16)|n);c80_put32(p+4,version<<16);
    for(unsigned i=0;i<count;++i) c80_put16(p+8+stride*i,token);
    return dma;
}
static void notify_unit(unsigned variant,unsigned start)
{
    struct event_model *x=event_new(0);struct model *m=&x->m;struct c80_result *r=&m->result;
    m->io.rx1_packet_test=1;r->phase=m->phase=37;r->auth_submitted=1;
    x->next_cpu=x->producer=start;r->rx_next[1]=start;*regptr(m,0x18004418)=(start+63)%64;
    struct c80_desc *d=&m->pool.rx[1][start];c80_u8 *p=m->pool.data[1][start];
    unsigned size=notification(p,1,1,0),expected=C80_RX_TIMEOUT,valid=1,ours=1;
    switch(variant) {
    case 0:break;case 1:size=notification(p,0,1,0);break;
    case 2:size=notification(p,7,127,0);break;
    case 3:size=notification(p,0,127,4095);ours=0;break;
    case 4:size=notification(p,1,0,0);ours=0;break;
    case 5:r->auth_submitted=0;ours=0;break;
    case 6:r->auth_token_returned=1;break;
    case 7:size=notification(p,1,1,1);ours=0;break;
    case 8:size=notification(p,1,2,0);c80_put16(p+12,4096);expected=58;valid=0;ours=0;break;
    case 9:c80_put32(p,(6u<<29)|(1u<<16)|11);expected=58;valid=0;ours=0;break;
    case 10:size=8;expected=58;valid=0;ours=0;break;
    case 11:size=16;expected=58;valid=0;ours=0;break;
    case 12:size=4;expected=58;valid=0;ours=0;break;
    case 13:c80_put32(p,(6u<<29)|(1u<<23)|12);valid=0;ours=0;break;
    case 14:x->mode=1;expected=49;break;
    case 15:x->mode=2;break;
    case 16:d->addr^=16;expected=14;valid=0;ours=0;break;
    case 17:d->addr1=16;expected=14;valid=0;ours=0;break;
    case 18:size=3;expected=14;valid=0;ours=0;break;
    case 19:size=1537;expected=14;valid=0;ours=0;break;
    case 20:size=notification(p,0,2,0);break;
    default:assert(0);
    }
    d->ctrl=C80_DONE|C80_LS0|(size<<16);c80_u32 status=0x55;
    assert(c80_receive(&m->io,r,0,0,&status)==expected && status==0x55);
    assert(r->txfree_valid==valid && r->auth_token_returned==(ours||variant==6));
    assert(!r->rx1_unmatched && !r->last_event_len && !m->result.auth_dma_done);
    if(expected==C80_RX_TIMEOUT) assert(x->returned==1 && r->rx_next[1]==(start+1)%64);
    else assert(x->returned==0 && r->rx_next[1]==start);
    if(variant==5) assert(r->txfree_before_submit==1 && !r->txfree_ours);
    if(variant==6) assert(r->txfree_duplicate==1);
    if(variant==8) assert(!r->txfree_tokens && !r->txfree_ours);
    if(variant==13) assert(r->txfree_other==1 && !r->txfree_valid);
    if(variant==20) assert(r->txfree_ours==2 && r->txfree_duplicate==1);
    passed("unit",variant,start);free(x);
}
static void types_unit(unsigned type)
{
    struct event_model *x=event_new(0);struct model *m=&x->m;m->io.rx1_packet_test=1;m->phase=m->result.phase=37;
    c80_put32(m->pool.data[1][0],(type<<29)|4);m->pool.rx[1][0].ctrl=C80_DONE|C80_LS0|(4u<<16);c80_u32 status=99;
    unsigned expected=type==7?14:type==6?58:13;
    assert(c80_receive(&m->io,&m->result,7,4,&status)==expected && status==99);
    assert(m->result.rx1_type[type]==1);
    assert(x->returned==(expected==13));passed("type",type,expected);free(x);
}
static void list_guard(unsigned size,unsigned version,unsigned count)
{
    long page=sysconf(_SC_PAGESIZE);c80_u8 *area=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(area!=MAP_FAILED);
    assert(!mprotect(area+page,page,PROT_NONE));c80_u8 *p=area+page-size;memset(p,0,size);
    c80_put32(p,(6u<<29)|(count<<16)|(8+count*(version?4:2)));
    if(size>=8) c80_put32(p+4,version<<16);
    struct c80_result result={0};unsigned rc=c80_rx1_non_event(&result,p,size,6);
    unsigned bytes=8+count*(version?4:2);assert(rc==(size==((bytes+3)&~3u)?13:58));
    assert(!result.auth_token_returned);passed("guard",size,version);assert(!munmap(area,2*page));
}
static void mixed_wrap(void)
{
    struct event_model *x=event_new(0);struct model *m=&x->m;m->io.rx1_packet_test=1;m->phase=m->result.phase=37;
    x->next_cpu=63;m->result.rx_next[1]=63;m->result.auth_submitted=1;
    notification(m->pool.data[1][63],1,1,0);m->pool.rx[1][63].ctrl=C80_DONE|C80_LS0|(12u<<16);
    c80_u8 *p=m->pool.data[1][0];memset(p,0,28);c80_put32(p,(7u<<29)|28);c80_put16(p+16,12);c80_put16(p+18,0xe000);p[20]=4;p[21]=7;p[24]=2;
    m->pool.rx[1][0].ctrl=C80_DONE|C80_LS0|(28u<<16);c80_u32 status=99;
    assert(c80_receive(&m->io,&m->result,7,4,&status)==0 && status==2);
    assert(x->returned==2 && m->result.rx_next[1]==1 && m->result.auth_token_returned && m->result.last_event_seq==7);
    assert(m->result.rx1_type[6]==1 && m->result.rx1_type[7]==1 && !m->result.rx1_unmatched);
    passed("mixed-wrap",63,0);free(x);
}
struct complete_model { struct auth_model auth;unsigned emitted,scenario; };
static void complete_barrier(void *opaque,int publish)
{
    struct complete_model *x=opaque;struct model *m=&x->auth.em.m;
    /* Old synthetic MCU producers omitted the outer event header. Supply
     * device-produced type7 here, before CPU acquisition; real parser stays exact. */
    if(!publish) for(unsigned i=0;i<64;++i) {
        unsigned size=(m->pool.rx[1][i].ctrl>>16)&0x3fff;c80_u8 *p=m->pool.data[1][i];
        if((m->pool.rx[1][i].ctrl&C80_DONE) && size>=24 && !c80_get32(p) && c80_get16(p+18)==0xe000)
            c80_put32(p,(7u<<29)|size);
    }
    auth_barrier(opaque,publish);
}
static void complete_delay(void *opaque,c80_u32 us)
{
    struct complete_model *x=opaque;struct model *m=&x->auth.em.m;auth_delay(opaque,us);
    if(m->phase!=37 || !x->auth.pubs || x->emitted) return;
    unsigned i=x->auth.em.producer;struct c80_desc *d=&m->pool.rx[1][i];assert(!(d->ctrl&C80_DONE));
    unsigned size=notification(m->pool.data[1][i],x->scenario==1?0:1,1,x->scenario==3?1:0);
    if(x->scenario==2) size=notification(m->pool.data[1][i],1,2,0);
    if(x->scenario==4) size=4;
    d->ctrl=C80_DONE|C80_LS0|(size<<16);x->auth.em.producer=(i+1)%64;m->rx_next[1]=x->auth.em.producer;++x->emitted;
}
static void complete_full(unsigned scenario)
{
    struct auth_model *old=auth_new(19);struct complete_model *x=calloc(1,sizeof(*x));assert(x);memcpy(&x->auth,old,sizeof(*old));free(old);
    struct model *m=&x->auth.em.m;struct c80_result *r=&m->result;x->scenario=scenario;
    m->io.context=x;m->io.pool=&m->pool;m->io.rx1_packet_test=1;m->io.dma_order=complete_barrier;m->io.delay_us=complete_delay;
    unsigned expected=scenario==4?58:0;assert(c80_run(&m->io,firmware,r)==expected);auth_pinned(&x->auth);
    assert(x->emitted==1 && x->auth.pubs==1 && r->auth_dma_done && r->auth_same_peer_assoc==1);
    assert(r->primary==expected && !r->critical && !r->cleanup && r->mcu_stopped && r->dma_idle && !r->auth_ring_restore_bad);
    if(!expected) {
        assert(r->watch[0].complete && r->watch[1].complete && r->beacon_complete && r->bss_complete && r->devinfo_complete);
        assert(r->txfree_valid==1 && r->auth_token_returned==(scenario!=3));
        assert(r->tx_submitted==58 && r->tx_completed==58);
    } else assert(r->txfree_bad==1 && !r->watch[1].complete && !r->auth_token_returned);
    passed("full",scenario,expected);free(x);
}
#ifdef C80_COMPLETE_LIBRARY
int c80_complete_test_entry(int argc,char **argv)
#else
int main(int argc,char **argv)
#endif
{
    assert(argc==5);FILE *f=fopen(argv[4],"rb");assert(f && fread(auth_oracle,1,32,f)==32 && fgetc(f)==EOF);fclose(f);
    f=fopen(argv[3],"rb");assert(f && fread(synthetic_nvm,1,1024,f)==1024 && fgetc(f)==EOF);fclose(f);
    f=fopen(argv[2],"rb");assert(f);
    for(unsigned i=0;i<59;++i) { c80_u8 b[4];assert(fread(b,1,4,f)==4);stock_sizes[i]=c80_get32(b);assert(stock_sizes[i]<=1152 && fread(stock_packets[i],1,stock_sizes[i],f)==stock_sizes[i]); }assert(fgetc(f)==EOF);fclose(f);
    const char *names[]={"test_mcu.bin","test_wifi.bin","WIFI_RAM_CODE_iemi.bin","WIFI_RAM_CODE_demi.bin","mt7626_patch_e1_hdr.bin","WIFI_RAM_CODE_7626.bin"};
    for(unsigned i=0;i<6;++i) { char path[4096];snprintf(path,sizeof(path),"%s/%s",argv[1],names[i]);f=fopen(path,"rb");assert(f);firmware[i].bytes=c80_blob_sizes[i];firmware[i].data=malloc(firmware[i].bytes);assert(fread((void *)firmware[i].data,1,firmware[i].bytes,f)==firmware[i].bytes && fgetc(f)==EOF);fclose(f); }
    for(unsigned v=0;v<21;++v) for(unsigned s=0;s<2;++s) notify_unit(v,s?63:0);
    for(unsigned t=0;t<8;++t) types_unit(t);
    for(unsigned s=4;s<=16;++s) for(unsigned v=0;v<2;++v) list_guard(s,v,1);
    for(unsigned v=0;v<2;++v) list_guard(8,v,127);
    mixed_wrap();for(unsigned i=0;i<5;++i) complete_full(i);
    for(unsigned i=0;i<6;++i) free((void *)firmware[i].data);
    printf("PASS: %u actual-core RX1 classification/TX-free cases; ASan/UBSan, synthetic device effects.\n",free_cases);return 0;
}
