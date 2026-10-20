/* SPDX-License-Identifier: GPL-2.0-only */
/* Actual core, independent synthetic producer. Not RF/client AP emulation. */
#define main c80_inherited_main
#include "verify-core.c"
#undef main
#include <sys/mman.h>
#include <unistd.h>
struct event_model {
    struct model m;
    unsigned mode,attempts,returned,pending,barriers,next_cpu,producer,limit,produced;
    unsigned refill,full,state_reads,queries,window_frames;
};
static unsigned cases;
static const c80_u8 peer[6]={2,0x71,0x22,0x33,0x44,0x55};
static void event_pump(struct event_model *x,unsigned count)
{
    struct model *m=&x->m;
    while(count-- && x->produced<x->limit) {
        unsigned i=x->producer;struct c80_desc *d=&m->pool.rx[1][i];c80_u8 *p=m->pool.data[1][i];
        if(d->ctrl&C80_DONE) break;
        assert(d->addr==c80_dma_address(&m->io,p) && !d->addr1);
        assert(d->ctrl==(1536u<<16) || d->ctrl==(C80_LS0|(1536u<<16)));
        memset(p,0,36);c80_put16(p+16,20);c80_put16(p+18,0xe000);
        p[20]=0xed;p[21]=0;p[24]=0xfe;p[28]=0xa5;
        d->ctrl=C80_DONE|C80_LS0|(36u<<16);++x->produced;
        x->producer=(i+1)%64;m->rx_next[1]=x->producer;
        *regptr(m,0x1800441c)=x->producer;
    }
}
static c80_u32 event_read(void *opaque,c80_u32 address)
{
    struct event_model *x=opaque;struct model *m=&x->m;
    if(address==C80_SYNC && m->phase>=20 && m->phase<90) return 6;
    if(x->full) for(unsigned i=0;i<12;++i) if(address==c80_state_regs[i]) {
        unsigned sample=x->state_reads/12;
        assert(sample<5 && i==x->state_reads%12);
        assert((m->phase==(unsigned[]){30,33,34,37,36}[sample]));
        ++x->state_reads;return 0x10000000u|(sample<<8)|i;
    }
    return read_reg(opaque,address);
}
static void event_barrier(void *opaque,int publish)
{
    struct event_model *x=opaque;struct model *m=&x->m;
    if(publish && m->result.rx1_rearmed>x->attempts) {
        struct c80_desc *d=&m->pool.rx[1][x->next_cpu];
        assert(!x->pending && d->ctrl==(C80_LS0|(1536u<<16)));
        assert(d->addr==c80_dma_address(&m->io,m->pool.data[1][x->next_cpu]) && !d->addr1 && !d->info);
        x->pending=1;++x->barriers;
    }
}
static void event_write(void *opaque,c80_u32 address,c80_u32 value)
{
    struct event_model *x=opaque;struct model *m=&x->m;
    if(address==0x18004418 && m->phase!=6 && m->phase!=90) {
        assert(value<64 && value==x->next_cpu && x->pending==1);
        struct c80_desc *d=&m->pool.rx[1][value];
        assert(d->ctrl==(C80_LS0|(1536u<<16)) && !d->addr1 && !d->info);
        assert(d->addr==c80_dma_address(&m->io,m->pool.data[1][value]));
        ++x->attempts;x->pending=0;
        if(x->mode==1) return; /* Ignore CPU-index write: readback must stop. */
        *regptr(m,address)=value;++x->returned;x->next_cpu=(value+1)%64;
        if(x->mode==2) memset(m->pool.data[1][value],0xcc,1536); /* DMA reuse after publication. */
        if(x->refill && (!x->full || m->phase==38 || m->phase==37)) event_pump(x,1);
        return;
    }
    if(x->full && address==0x18004408 && (m->phase==38 || m->phase==37)) {
        assert(value<64 && m->pool.rx[0][value].ctrl==(C80_LS0|(1536u<<16)));
        *regptr(m,address)=value;return;
    }
    if(x->full && address==0x180043f8 && (m->phase==39 || m->phase==40)) {
        unsigned slot=value-1,k=m->phase-39,i=x->producer;
        struct c80_desc *d=&m->pool.tx[slot];c80_u8 *p=m->pool.command[slot];
        assert(value==m->tx_seen+1 && slot<27 && d->ctrl==(C80_LS0|(168u<<16)));
        check_packet(m,p,168);++m->tx_seen;++m->writes;++x->queries;
        d->ctrl|=C80_DONE;*regptr(m,address)=value;*regptr(m,0x180043fc)=value;
        struct c80_desc *rx=&m->pool.rx[1][i];c80_u8 *v=m->pool.data[1][i];
        assert(!(rx->ctrl&C80_DONE));memset(v,0,40);
        c80_put16(v+16,24);c80_put16(v+18,0xe000);v[20]=0xed;v[21]=p[39];v[24]=0x3c;c80_put16(v+28,2);
        c80_put32(v+32,1000000+30000000*k);rx->ctrl=C80_DONE|C80_LS0|(40u<<16);
        x->producer=(i+1)%64;m->rx_next[1]=x->producer;return;
    }
    if(x->full) m->rx_next[1]%=64;
    write_reg(opaque,address,value);
    if(x->full) { m->rx_next[1]%=64;x->producer=m->rx_next[1]; }
}
static void frame(c80_u8 *p,const c80_u8 *own,unsigned sub)
{
    memset(p,0,80);c80_put16(p,sub<<4);
    memcpy(p+4,own,6);memcpy(p+10,peer,6);memcpy(p+16,own,6);
    if(sub==4) { p[24]=0;p[25]=9;memcpy(p+26,"C80-RAM16",9); }
    if(sub==11) c80_put16(p+26,1);
}
static void window_frame(struct event_model *x)
{
    struct model *m=&x->m;unsigned i=m->result.rx_next[0];
    struct c80_desc *d=&m->pool.rx[0][i];c80_u8 *p=m->pool.data[0][i];
    assert(!(d->ctrl&C80_DONE));memset(p,0,100);
    c80_put32(p,(2u<<29)|46u);frame(p+16,m->pool.nvm_payload+8,11);
    d->ctrl=C80_DONE|C80_LS0|(46u<<16);++x->window_frames;
}
static void event_stage(void *opaque,c80_u32 phase)
{
    struct event_model *x=opaque;stage(opaque,phase);
    if(phase==38 || phase==37) { event_pump(x,x->refill?63:1);window_frame(x); }
}
static void event_delay(void *opaque,c80_u32 us)
{
    struct event_model *x=opaque;delay(opaque,us);
    if(x->full && (x->m.phase==38 || x->m.phase==37)) event_pump(x,2);
}
static struct event_model *event_new(int full)
{
    struct event_model *x=calloc(1,sizeof(*x));assert(x);struct model *m=&x->m;
    x->full=full;m->us=100;m->fault=BSS_GOOD;
    for(unsigned i=0;i<10;++i) *regptr(m,c80_aon_regs[i])=(c80_u32[]){0,0xe0800022,0,0xffffff20,0x11040,1,0x269f0000,0x0700b644,0x0700b644,0x9000}[i];
    *regptr(m,c80_controls[0])=0x40100000;*regptr(m,c80_controls[1])=0xf0000000;
    *regptr(m,0x180b1010)=0x10040101;*regptr(m,0x18002000)=*regptr(m,0x18002004)=0x8a00;
    *regptr(m,C80_OWN)=0x30001;*regptr(m,C80_GLO)=0x10001870;*regptr(m,C80_SYNC)=2;
    m->io=(struct c80_io){.context=x,.read=event_read,.write=event_write,.time_us=model_time,.delay_us=event_delay,
        .dma_order=event_barrier,.copy_emi=copy_emi,.crc_emi=crc_emi,.stage=full?event_stage:stage,
        .pool=&m->pool,.dma_base=0x41000000,.irq_arm=model_irq_arm,.irq_disarm=model_irq_disarm,
        .nvm_read=model_nvm_read,.devinfo_test=1,.bss_test=1,.radio_test=1,.beacon_test=1,.watch_test=1,
        .rx0_rearm_test=1,.beacon_state_test=1,.bss_period_test=1,.rx1_rearm_test=1,.management_rx_test=1};
    if(!full) for(unsigned q=0;q<2;++q) for(unsigned i=0;i<64;++i) {
        m->pool.rx[q][i].addr=c80_dma_address(&m->io,m->pool.data[q][i]);m->pool.rx[q][i].ctrl=1536u<<16;
    }
    return x;
}
static void done(const char *kind,unsigned a,unsigned b,unsigned c)
{ printf("PASS CLIENT-%s %u/%u/%u\n",kind,a,b,c);++cases; }
static void event_unit(unsigned fault,unsigned start)
{
    struct event_model *x=event_new(0);struct model *m=&x->m;
    c80_u32 status=0x1234;unsigned bytes=28,expected=0;
    x->next_cpu=x->producer=start;m->result.rx_next[1]=start;*regptr(m,0x18004418)=(start+63)%64;
    struct c80_desc *d=&m->pool.rx[1][start];c80_u8 *p=m->pool.data[1][start];
    memset(p,0,64);c80_put16(p+16,12);c80_put16(p+18,0xe000);p[20]=4;p[21]=7;p[24]=2;
    if(fault==1) d->addr^=16;
    if(fault==2) d->addr1=0x1230;
    if(fault==3) bytes=15;
    if(fault==4) bytes=1537;
    if(fault==6) c80_put16(p+16,8);
    if(fault==7) c80_put16(p+16,13);
    if(fault==8) p[19]=0xd0;
    if(fault==9) p[20]=1;
    if(fault==10) p[21]=6;
    if(fault==11) x->mode=1;
    if(fault==12) x->mode=2;
    if(fault==13) { bytes=36;c80_put16(p+16,20);p[20]=0xed;p[24]=0x3c;c80_put16(p+28,5);p[32]=1;c80_put32(p+36,0x789abcde);bytes=40;c80_put16(p+16,24); }
    d->ctrl=C80_DONE|C80_LS0|(bytes<<16);
    if(fault==5) d->ctrl&=~C80_LS0;
    if(fault==14) d->ctrl&=~C80_DONE;
    expected=fault>=1 && fault<=7?C80_RX_BAD:fault>=8 && fault<=10?C80_RX_TIMEOUT:fault==11?C80_RX1_RETURN_FAILED:fault==14?C80_RX_TIMEOUT:0;
    unsigned rc=c80_receive(&m->io,&m->result,7,fault==13?0xed:4,&status);assert(rc==expected);
    if(expected==C80_RX_BAD || fault==14) assert(!x->attempts && !m->result.rx1_rearmed);
    else if(fault==11) assert(x->attempts==1 && !x->returned && m->result.rx1_readback!=start);
    else {
        assert(x->returned==1 && x->barriers==1 && m->result.rx_next[1]==(start+1)%64);
        assert(m->result.rx1_packets==1 && m->result.rx1_rearmed==1 && m->result.rx1_publishes==1);
        if(!expected) assert(status==(fault==13?0u:2u));
        if(fault==12) { assert(m->result.last_event_id==4 && m->result.last_event_status==2);assert(p[24]==0xcc); }
        if(fault==13) assert(m->result.counter_query_valid && m->result.counter_value==0x789abcde);
        if(expected==C80_RX_TIMEOUT) assert(m->result.rx1_unmatched==1 && m->result.rx1_meta_valid==15 && m->result.rx1_meta_dma_bytes==28);
    }
    done("event",fault,start,rc);free(x);
}
static void event_short(unsigned bytes)
{
    struct event_model *x=event_new(0);struct model *m=&x->m;c80_u32 status=0;
    c80_u8 *p=m->pool.data[1][0];memset(p,0,1536);p[20]=0xed;
    m->pool.rx[1][0].ctrl=C80_DONE|C80_LS0|(bytes<<16);
    unsigned rc=c80_receive(&m->io,&m->result,7,4,&status);
    assert(rc==C80_RX_TIMEOUT && x->returned==1 && m->result.rx1_unmatched==1 && m->result.rx1_short==1);
    unsigned valid=(bytes>=18?1u:0u)|(bytes>=20?2u:0u)|(bytes>=21?4u:0u)|(bytes>=22?8u:0u);
    assert(m->result.rx1_meta_valid==valid && m->result.rx1_meta_dma_bytes==bytes);
    done("short",bytes,valid,rc);free(x);
}
static void event_stream(unsigned start,unsigned count,int refill)
{
    struct event_model *x=event_new(0);struct model *m=&x->m;c80_u32 status=0,rc;
    x->producer=x->next_cpu=start;m->result.rx_next[1]=start;x->limit=count;x->refill=refill;
    event_pump(x,refill?63:count);
    do { rc=c80_receive(&m->io,&m->result,7,4,&status);assert(rc==C80_RX_TIMEOUT); } while(x->returned<count);
    assert(x->returned==count && x->barriers==count && m->result.rx_next[1]==(start+count)%64);
    assert(m->result.rx1_unmatched==count && m->result.rx1_meta_valid==31 && m->result.rx1_meta_ext==0xfe);
    assert(m->result.rx1_budget_yields==(refill?count/64:count==64));
    done("stream",start,count,refill);free(x);
}
static void full_case(unsigned mode,unsigned count,unsigned fault,unsigned expected)
{
    struct event_model *x=event_new(1);struct model *m=&x->m;
    x->mode=mode;x->limit=count;x->refill=1;m->fault=fault;
    unsigned rc=c80_run(&m->io,firmware,&m->result);assert(rc==expected);
    if(!expected || expected==80 || expected==81) {
        assert(x->state_reads==60 && x->queries==2 && m->result.tx_completed==58 && m->result.tx_submitted==58);
        assert(x->returned==count+27 && m->result.rx1_packets==count+27 && x->returned==m->result.rx1_rearmed);
        assert(m->result.rx1_unmatched==count && m->result.rx_next[1]==(count+27)%64 && !x->pending);
        assert(m->result.management[0].auth_open_request==1 && m->result.management[1].auth_open_request==1);
        assert(m->result.watch[0].complete && m->result.watch[1].complete && m->result.irq_events==1);
    }
    if(expected==80 || expected==81) assert(m->result.critical && !m->result.dma_idle);
    else assert(m->result.mcu_stopped && m->result.dma_idle && !m->result.cleanup && !m->result.mask_after);
    done("full",mode,count,rc);free(x);
}
static void guard_case(unsigned which)
{
    struct event_model *x=event_new(1);struct model *m=&x->m;unsigned expected=51;
    if(which==0) { m->io.beacon_state_test=m->io.bss_period_test=m->io.management_rx_test=0;m->io.rx0_rearm_test=0;expected=50; }
    if(which==1) m->io.rx1_rearm_test=0;
    if(which==2) m->io.bss_period_test=0;
    assert(c80_run(&m->io,firmware,&m->result)==expected && m->result.primary==expected);
    assert(!m->writes && !m->tx_seen && !x->attempts);done("guard",which,expected,0);free(x);
}
static void management_case(unsigned variant,unsigned window)
{
    struct event_model *x=event_new(0);struct model *m=&x->m;unsigned len=35,sub=4;
    c80_u8 p[80];memcpy(m->pool.nvm_payload+8,synthetic_nvm+4,6);
    const c80_u8 *own=m->pool.nvm_payload+8;m->result.phase=window?37:38;m->result.devinfo_mac_valid=m->result.nvm_equal=1;
    if(variant>=40) sub=(variant-40)%16;
    if(variant>=25 && variant<=32) sub=11;
    if(variant==33 || variant==34) sub=0;
    if(variant==35 || variant==36) sub=2;
    if(variant==37 || variant==38) sub=12;
    frame(p,own,sub);
    if(sub==11) len=30;
    if(sub==0) len=28;
    if(sub==2) len=34;
    if(sub==12 || sub==10) len=26;
    if(variant==1) { memset(p+4,255,6);memset(p+16,255,6); }
    if(variant==2) { p[25]=0;len=26; }
    if(variant==3) p[26]='X';
    if(variant==4) { p[25]=32;len=58; }
    if(variant==5) p[25]=33;
    if(variant==6) len=34;
    if(variant==7) len=25;
    if(variant==8) p[24]=1;
    if(variant==9) p[4]^=0x20;
    if(variant==10) p[16]^=0x20;
    if(variant==11) memset(p+10,0,6);
    if(variant==12) p[10]|=1;
    if(variant==13) memcpy(p+10,own,6);
    if(variant==14) p[1]|=0x40;
    if(variant==15) p[1]|=0x80;
    if(variant==16) p[1]|=4;
    if(variant==17) p[22]=1;
    if(variant==18) p[0]|=1;
    if(variant==19) p[1]|=1;
    if(variant==20) p[1]|=2;
    if(variant==21) m->io.management_rx_test=0;
    if(variant==22) m->result.devinfo_mac_valid=0;
    if(variant==23) m->result.nvm_equal=0;
    if(variant==24) m->result.phase=30;
    if(variant==26) p[24]=3;
    if(variant==27) p[26]=2;
    if(variant==28) p[28]=1;
    if(variant==29) len=29;
    if(variant==30) p[4]^=0x20;
    if(variant==31) p[16]^=0x20;
    if(variant==32) p[1]|=0x40;
    if(variant==33) len=27;
    if(variant==35) len=33;
    if(variant==37) len=25;
    c80_management_receive(&m->io,&m->result,p,len);
    struct c80_management_counts *c=&m->result.management[window];
    assert(!memcmp(&m->result.management[!window],&(struct c80_management_counts){0},sizeof(*c)));
    if(variant>=21 && variant<=24) assert(!memcmp(c,&(struct c80_management_counts){0},sizeof(*c)));
    else if(variant>=18 && variant<=20) assert(c->bad_fc==1 && !c->headers);
    else {
        assert(c->headers==1 && c->subtype[sub]==1);
        if(variant>=11 && variant<=13) assert(c->peer_bad==1 && !c->probe_eligible);
        if(variant==14 || variant==15 || variant==32) assert(c->protected_ordered==1);
        if(variant==16 || variant==17) assert(c->fragments==1);
        if(variant<=8) {
            assert(c->probe_eligible==1);
            if(variant<=1) assert(c->probe_test_ssid==1);
            if(variant==2) assert(c->probe_wildcard==1);
            if(variant==3 || variant==4) assert(c->probe_other_ssid==1);
            if(variant>=5) assert(c->probe_short_ssid==1);
        }
        if(variant==9 || variant==10) assert(!c->probe_eligible);
        if(variant==25) assert(c->auth_to_us==1 && c->auth_open_request==1);
        if(variant>=26 && variant<=28) assert(c->auth_other==1 && !c->auth_open_request);
        if(variant==29 || variant==33 || variant==35 || variant==37) assert(c->short_header==1);
        if(variant==30 || variant==31 || variant==32) assert(!c->auth_to_us);
        if(variant==34) assert(c->assoc_to_us==1);
        if(variant==36) assert(c->reassoc_to_us==1);
        if(variant==38) assert(c->deauth_to_us==1);
    }
    assert(!m->writes);done("mgmt",variant,window,len);free(x);
}
static void management_bounds(unsigned bytes,unsigned variant)
{
    struct event_model *x=event_new(0);struct model *m=&x->m;
    memcpy(m->pool.nvm_payload+8,synthetic_nvm+4,6);m->result.phase=37;m->result.devinfo_mac_valid=m->result.nvm_equal=1;
    long page=sysconf(_SC_PAGESIZE);assert(page>80);
    c80_u8 *mem=mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(mem!=MAP_FAILED && !mprotect(mem+page,(size_t)page,PROT_NONE));
    c80_u8 raw[80];frame(raw,m->pool.nvm_payload+8,variant?11:4);c80_u8 *p=mem+page-bytes;
    memcpy(p,raw,bytes);c80_management_receive(&m->io,&m->result,p,bytes);
    assert(!m->writes);assert(!munmap(mem,(size_t)page*2));done("bounds",bytes,variant,0);free(x);
}
static void management_rx0(unsigned group,unsigned padding,unsigned translated,unsigned type)
{
    struct event_model *x=event_new(0);struct model *m=&x->m;
    memcpy(m->pool.nvm_payload+8,synthetic_nvm+4,6);m->result.phase=37;m->result.devinfo_mac_valid=m->result.nvm_equal=1;
    unsigned offset=16+16*!!(group&8)+16*!!(group&1)+8*!!(group&2)+24*!!(group&4)+2*padding,total=offset+30;
    c80_u8 *p=m->pool.data[0][0];memset(p,0,160);c80_put32(p,(type<<29)|(group<<25)|total);
    p[6]=(padding?0x40:0)|(translated?0x80:0);frame(p+offset,m->pool.nvm_payload+8,11);
    m->pool.rx[0][0].ctrl=C80_DONE|C80_LS0|(total<<16);
    /* RX0 unit publication intentionally bypasses the full MMIO model. */
    m->io.write=0; /* set below to the minimal RX0 register writer */
    m->io.write=write_reg;
    unsigned phase=m->phase;m->phase=0;
    assert(!c80_radio_receive(&m->io,&m->result));m->phase=phase;
    assert(m->result.management[1].auth_open_request==(type==2 && !translated));
    assert(m->result.rx0_rearmed==1 && m->result.rx0_publishes==1);
    done("rx0",group,padding,translated*8+type);free(x);
}
int main(int argc,char **argv)
{
    assert(argc==4);FILE *f=fopen(argv[3],"rb");assert(f && fread(synthetic_nvm,1,1024,f)==1024 && fgetc(f)==EOF);fclose(f);
    f=fopen(argv[2],"rb");assert(f);
    for(unsigned i=0;i<59;++i) { c80_u8 b[4];assert(fread(b,1,4,f)==4);stock_sizes[i]=c80_get32(b);assert(stock_sizes[i]<=1152 && fread(stock_packets[i],1,stock_sizes[i],f)==stock_sizes[i]); }
    assert(fgetc(f)==EOF);fclose(f);
    const char *names[]={"test_mcu.bin","test_wifi.bin","WIFI_RAM_CODE_iemi.bin","WIFI_RAM_CODE_demi.bin","mt7626_patch_e1_hdr.bin","WIFI_RAM_CODE_7626.bin"};
    for(unsigned i=0;i<6;++i) { char path[4096];snprintf(path,sizeof(path),"%s/%s",argv[1],names[i]);f=fopen(path,"rb");assert(f);firmware[i].bytes=c80_blob_sizes[i];firmware[i].data=malloc(firmware[i].bytes);assert(fread((void *)firmware[i].data,1,firmware[i].bytes,f)==firmware[i].bytes && fgetc(f)==EOF);fclose(f); }
    for(unsigned start=0;start<64;start+=63) for(unsigned fault=0;fault<=14;++fault) event_unit(fault,start);
    for(unsigned bytes=16;bytes<25;++bytes) event_short(bytes);
    event_stream(0,64,0);event_stream(63,2,0);event_stream(63,4097,1);event_stream(0,8193,1);
    full_case(0,0,BSS_GOOD,0);full_case(0,4097,BSS_GOOD,0);full_case(0,8193,BSS_RESET_STUCK,80);full_case(0,129,BSS_DMA_BUSY,81);full_case(1,0,BSS_GOOD,49);
    for(unsigned i=0;i<3;++i) guard_case(i);
    for(unsigned window=0;window<2;++window) for(unsigned variant=0;variant<56;++variant) management_case(variant,window);
    for(unsigned variant=0;variant<2;++variant) for(unsigned bytes=0;bytes<=80;++bytes) management_bounds(bytes,variant);
    for(unsigned group=0;group<16;++group) for(unsigned pad=0;pad<2;++pad) management_rx0(group,pad,0,2);
    for(unsigned type=0;type<8;++type) management_rx0(0,0,0,type);
    management_rx0(15,1,1,2);
    for(unsigned i=0;i<6;++i) free((void *)firmware[i].data);
    printf("PASS: %u actual-core client RX/RX1 recycling scenarios; ASan/UBSan, all MCU/DMA/RF effects synthetic.\n",cases);return 0;
}
