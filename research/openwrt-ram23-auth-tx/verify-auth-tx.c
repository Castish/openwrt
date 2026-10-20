/* SPDX-License-Identifier: GPL-2.0-only */
#define C80_CLIENT_LIBRARY
#include "verify-client-rx.c"
struct auth_model {
    struct event_model em;
    unsigned fault,pubs,wmb,pending,duplicate_frames,assoc_frames,delayed,jumped;
    c80_u8 kept_header[64],kept_frame[32];
};
static c80_u8 auth_oracle[32];
static unsigned auth_cases;
static void auth_pinned(struct auth_model *x)
{
    if(!x->pubs) return;
    assert(!memcmp(x->kept_header,x->em.m.pool.auth_header,64));
    assert(!memcmp(x->kept_frame,x->em.m.pool.auth_frame,32));
}
static c80_u32 auth_read(void *opaque,c80_u32 address)
{
    struct auth_model *x=opaque;auth_pinned(x);
    if(x->em.m.phase==37 && x->em.m.result.auth_captured && !x->pubs) {
        if(x->fault==25 && address==C80_AUTH_RING) return 0x41440000;
        if(x->fault==26 && address==C80_AUTH_RING+4) return 31;
    }
    return event_read(opaque,address);
}
static void auth_write(void *opaque,c80_u32 address,c80_u32 value)
{
    struct auth_model *x=opaque;struct model *m=&x->em.m;auth_pinned(x);
    if(address>=C80_AUTH_RING && address<=C80_AUTH_RING+8) {
        if(m->phase==6 || m->phase==90) {
            if(m->phase==90) assert(m->result.mcu_stopped && (!m->result.dma_started || m->result.dma_idle));
            ++m->writes;
            if(x->fault==16 && m->phase==6 && address==C80_AUTH_RING) return;
            if(x->fault==17 && m->phase==6 && address==C80_AUTH_RING+4) return;
            if(x->fault==9 && m->phase==90 && address==C80_AUTH_RING+4) return;
            *regptr(m,address)=value;return;
        }
        assert(address==C80_AUTH_RING+8 && value==1 && m->phase==37 && x->pending==1 && !x->pubs);
        assert(m->result.auth_submitted==1 && m->result.beacon_valid[1] && m->result.bss_valid[0]);
        assert((*regptr(m,C80_GLO)&(5|C80_DOWNLOAD_MODE))==5 && !*regptr(m,C80_MASK));
        struct c80_desc *d=&m->pool.auth_tx[0];
        assert(d->ctrl==0x40400000 && d->addr==c80_dma_address(&m->io,m->pool.auth_header));
        assert(d->addr1==c80_dma_address(&m->io,m->pool.auth_frame) && !d->info);
        assert(!memcmp(auth_oracle,m->pool.auth_header,32));
        c80_u8 txp[32]={0};c80_put16(txp,0x8000);c80_put32(txp+8,d->addr1);c80_put16(txp+12,0x801e);
        assert(!memcmp(txp,m->pool.auth_header+32,32));
        c80_u8 f[32]={0};c80_put16(f,0xb0);c80_put16(f+2,304);memcpy(f+4,peer,6);
        memcpy(f+10,synthetic_nvm+4,6);memcpy(f+16,synthetic_nvm+4,6);c80_put16(f+26,2);
        assert(!memcmp(f,m->pool.auth_frame,32));
        memcpy(x->kept_header,m->pool.auth_header,64);memcpy(x->kept_frame,m->pool.auth_frame,32);
        ++x->pubs;x->pending=0;
        if(x->fault!=4) *regptr(m,address)=1;
        if(x->fault!=2 && x->fault!=3 && x->fault!=24) d->ctrl|=C80_DONE;
        if(x->fault!=1 && x->fault!=3 && x->fault!=24) *regptr(m,C80_AUTH_RING+12)=1;
        if(x->fault==5) *regptr(m,C80_AUTH_RING+12)=2;
        if(x->fault==6) d->addr^=16;
        if(x->fault==7) d->ctrl^=C80_LS0;
        if(x->fault==8) d->info=1;
        return;
    }
    event_write(opaque,address,value);
}
static void auth_barrier(void *opaque,int publish)
{
    struct auth_model *x=opaque;struct model *m=&x->em.m;auth_pinned(x);
    if(publish && x->fault==24 && m->result.auth_captured && !m->result.auth_submitted &&
       (m->pool.auth_tx[0].ctrl&C80_DONE) && !x->jumped) { m->us+=500000;x->jumped=1; }
    if(publish && m->result.auth_captured && !m->result.auth_submitted && m->pool.auth_tx[0].ctrl==0x40400000) {
        assert(!x->wmb && !x->pending);x->pending=1;++x->wmb;
    }
    event_barrier(opaque,publish);
}
static void auth_frame_inject(struct auth_model *x,unsigned subtype)
{
    struct model *m=&x->em.m;unsigned i=m->result.rx_next[0];c80_u8 *p=m->pool.data[0][i];
    assert(!(m->pool.rx[0][i].ctrl&C80_DONE));memset(p,0,128);
    unsigned n=subtype==11?30:28;c80_put32(p,(2u<<29)|(16+n));frame(p+16,m->pool.nvm_payload+8,subtype);
    if(x->fault==23) p[16+10]^=2;
    m->pool.rx[0][i].ctrl=C80_DONE|C80_LS0|((16+n)<<16);
}
static void auth_stage(void *opaque,c80_u32 phase)
{
    struct auth_model *x=opaque;
    stage(opaque,phase);
    if(phase==38 || phase==37) {
        event_pump(&x->em,63);
        if(phase==38 || (x->fault!=20 && x->fault!=21 && x->fault!=22 && x->fault!=24)) window_frame(&x->em);
        if(phase==37 && x->fault==20) { /* no auth in beacon window */ }
    }
}
static void auth_delay(void *opaque,c80_u32 us)
{
    struct auth_model *x=opaque;struct model *m=&x->em.m;auth_pinned(x);event_delay(opaque,us);
    if(m->phase!=37) return;
    if((x->fault==21 || x->fault==22) && !x->delayed && m->us-m->watch_start>(x->fault==21?29000000u:28000000u)) {
        auth_frame_inject(x,11);x->delayed=1;
    }
    if(x->fault==24 && !x->delayed && m->us-m->watch_start>=29000000u) { auth_frame_inject(x,11);x->delayed=1; }
    if(x->fault==18 && x->pubs && x->duplicate_frames<3) { auth_frame_inject(x,11);++x->duplicate_frames; }
    if((x->fault==19 || x->fault==23) && x->pubs && !x->assoc_frames) { auth_frame_inject(x,0);++x->assoc_frames; }
}
static struct auth_model *auth_new(unsigned fault)
{
    struct event_model *old=event_new(1);struct auth_model *x=calloc(1,sizeof(*x));assert(x);
    memcpy(&x->em,old,sizeof(*old));free(old);struct model *m=&x->em.m;
    x->fault=fault;m->io.context=x;m->io.read=auth_read;m->io.write=auth_write;m->io.dma_order=auth_barrier;
    m->io.stage=auth_stage;m->io.delay_us=auth_delay;m->io.pool=&m->pool;m->io.auth_reply_test=1;
    if(fault==10) m->fault=BSS_RESET_STUCK;
    if(fault==11) m->fault=BSS_DMA_BUSY;
    if(fault==12) *regptr(m,C80_AUTH_RING+12)=1;
    if(fault==13) *regptr(m,C80_AUTH_RING)=0x41001000;
    if(fault==14) *regptr(m,C80_AUTH_RING+4)=32;
    if(fault==15) *regptr(m,C80_AUTH_RING+8)=1;
    return x;
}
static void auth_full(unsigned fault,unsigned expected)
{
    struct auth_model *x=auth_new(fault);struct model *m=&x->em.m;
    unsigned rc=c80_run(&m->io,firmware,&m->result);assert(rc==expected);auth_pinned(x);
    if(fault>=12 && fault<=17) assert(!x->pubs && !m->result.auth_captured);
    else {
        if(fault==25 || fault==26) assert(!x->pubs && m->result.auth_captured && !x->wmb);
        else if(fault==20 || fault==21) assert(!x->pubs && !m->result.auth_captured);
        else assert(x->pubs==1 && x->wmb==1 && m->result.auth_captured==1 && !x->pending);
        if(fault==20 || fault==21 || !expected) assert(m->result.watch[0].complete && m->result.watch[1].complete);
        if(!expected && fault!=20 && fault!=21) assert(m->result.auth_dma_done && m->result.auth_cpu_readback==1 && m->result.auth_dma_index==1);
    }
    if(expected==80 || expected==81) assert(m->result.critical==expected && !m->result.dma_idle);
    else {
        assert(!m->result.critical && m->result.mcu_stopped);
        if(m->result.dma_started) assert(m->result.dma_idle);
        if(expected==16) assert(m->result.cleanup && m->result.auth_ring_restore_bad==2);
        else assert(!m->result.cleanup && !m->result.auth_ring_restore_bad);
    }
    if(fault==18) assert(m->result.auth_duplicate==3);
    if(fault==19) assert(m->result.auth_same_peer_assoc==1);
    if(fault==23) assert(m->result.auth_same_peer_assoc==0);
    if(fault==21) assert(m->result.auth_late==1);
    if(fault==24) assert(x->jumped && !m->result.watch[1].complete && m->result.auth_wait_us<1000000);
    printf("PASS AUTH-full fault%u rc%u captured%u published%u header_done%u\n",fault,rc,m->result.auth_captured,x->pubs,m->result.auth_dma_done);
    ++auth_cases;free(x);
}
static void auth_guard(unsigned which)
{
    struct auth_model *x=auth_new(0);struct model *m=&x->em.m;
    switch(which) {
    case 0:m->io.management_rx_test=0;break;case 1:m->io.rx1_rearm_test=0;break;
    case 2:m->io.bss_period_test=0;break;case 3:m->io.beacon_state_test=0;break;
    case 4:m->io.rx0_rearm_test=0;break;case 5:m->io.watch_test=0;break;
    case 6:m->io.beacon_test=0;break;case 7:m->io.radio_test=0;break;
    case 8:m->io.devinfo_test=0;break;default:m->io.bss_test=0;break;
    }
    assert(c80_run(&m->io,firmware,&m->result)==52 && m->result.primary==52 && !m->writes && !x->pubs);
    printf("PASS AUTH-guard %u noMMIO\n",which);++auth_cases;free(x);
}
static void auth_capture_unit(unsigned variant)
{
    struct auth_model *x=auth_new(0);struct model *m=&x->em.m;c80_u8 req[80];
    m->result.phase=37;m->result.auth_ring_programmed=1;m->result.nvm_equal=m->result.devinfo_mac_valid=1;
    m->result.bss_valid[0]=m->result.radio_valid[3]=m->result.beacon_valid[1]=1;
    memcpy(m->pool.nvm_payload+8,synthetic_nvm+4,6);frame(req,m->pool.nvm_payload+8,11);
    if(variant==1) m->result.phase=38;
    if(variant==2) m->io.auth_reply_test=0;
    if(variant==3) m->result.auth_ring_programmed=0;
    if(variant==4) m->result.bss_valid[0]=0;
    if(variant==5) m->result.bss_status[0]=1;
    if(variant==6) m->result.radio_valid[3]=0;
    if(variant==7) m->result.radio_status[3]=1;
    if(variant==8) m->result.beacon_valid[1]=0;
    if(variant==9) m->result.beacon_status[1]=1;
    if(variant==10) m->result.nvm_equal=0;
    if(variant==11) m->result.devinfo_mac_valid=0;
    if(variant==12) req[26]=2;
    if(variant==13) req[28]=1;
    if(variant==14) req[24]=1;
    if(variant==15) req[4]^=2;
    if(variant==16) req[16]^=2;
    if(variant==17) req[1]|=0x40;
    if(variant==18) req[22]=1;
    if(variant==19) req[1]|=4;
    if(variant==20) req[10]|=1;
    if(variant==21) memcpy(req+10,req+16,6);
    c80_management_receive(&m->io,&m->result,req,variant==22?29:30);
    assert(m->result.auth_captured==(variant==0));assert(!m->writes && !x->pubs);
    printf("PASS AUTH-capture variant%u captured%u\n",variant,m->result.auth_captured);++auth_cases;free(x);
}
int main(int argc,char **argv)
{
    assert(argc==5);FILE *f=fopen(argv[4],"rb");assert(f && fread(auth_oracle,1,32,f)==32 && fgetc(f)==EOF);fclose(f);
    f=fopen(argv[3],"rb");assert(f && fread(synthetic_nvm,1,1024,f)==1024 && fgetc(f)==EOF);fclose(f);
    f=fopen(argv[2],"rb");assert(f);
    for(unsigned i=0;i<59;++i) { c80_u8 b[4];assert(fread(b,1,4,f)==4);stock_sizes[i]=c80_get32(b);assert(stock_sizes[i]<=1152 && fread(stock_packets[i],1,stock_sizes[i],f)==stock_sizes[i]); }assert(fgetc(f)==EOF);fclose(f);
    const char *names[]={"test_mcu.bin","test_wifi.bin","WIFI_RAM_CODE_iemi.bin","WIFI_RAM_CODE_demi.bin","mt7626_patch_e1_hdr.bin","WIFI_RAM_CODE_7626.bin"};
    for(unsigned i=0;i<6;++i) { char path[4096];snprintf(path,sizeof(path),"%s/%s",argv[1],names[i]);f=fopen(path,"rb");assert(f);firmware[i].bytes=c80_blob_sizes[i];firmware[i].data=malloc(firmware[i].bytes);assert(fread((void *)firmware[i].data,1,firmware[i].bytes,f)==firmware[i].bytes && fgetc(f)==EOF);fclose(f); }
    unsigned expected[]={0,56,56,56,55,57,57,57,57,16,80,81,53,53,11,53,54,54,0,0,0,0,0,0,56,57,57};
    for(unsigned i=0;i<sizeof(expected)/sizeof(expected[0]);++i) auth_full(i,expected[i]);
    for(unsigned i=0;i<10;++i) auth_guard(i);
    for(unsigned i=0;i<23;++i) auth_capture_unit(i);
    assert(sizeof(struct c80_dma_pool)==268800);
    for(unsigned i=0;i<6;++i) free((void *)firmware[i].data);
    printf("PASS: %u actual-core single auth TX cases, synthetic DMA/firmware/client effects; ASan/UBSan.\n",auth_cases);return 0;
}
