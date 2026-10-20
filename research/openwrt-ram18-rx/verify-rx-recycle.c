/* SPDX-License-Identifier: GPL-2.0-only */
/* Actual C core + independent synthetic RX producer/credits/barrier checks.
 * The 59-outstanding loss model is deliberately based on observed logs;
 * it tests the hypothesis and does NOT establish physical causality. */
#define main c80_inherited_main
#include "verify-core.c"
#undef main
struct rx_model {
    struct model m; /* first member: inherited host model shares this address */
    unsigned mode,produced,limit,inflight,producer,next_tail,published,attempts;
    unsigned publish_barriers,pending_barrier,ticks,rx_type;
};
static void rx_pump(struct rx_model *x,unsigned n)
{
    struct model *m=&x->m;
    while(n-- && x->produced<x->limit && x->inflight<63) {
        unsigned i=x->producer;struct c80_desc *d=&m->pool.rx[0][i];c80_u8 *p=m->pool.data[0][i];
        assert(!(d->ctrl&C80_DONE));assert(d->addr==c80_dma_address(&m->io,p));
        assert((d->ctrl>>16&0x3fff)==1536 && !d->addr1);
        memset(p,0,116);c80_put32(p,(x->rx_type<<29)|(15u<<25)|116);c80_put16(p+80,0x80);
        d->ctrl=C80_DONE|C80_LS0|(116u<<16);++x->produced;++x->inflight;
        x->producer=(i+1)%64;*regptr(m,0x1800440c)=x->producer;*regptr(m,C80_SOURCE)|=1;
    }
}
static c80_u32 rx_read(void *opaque,c80_u32 a)
{
    struct rx_model *x=opaque;
    if(x->mode==3 && x->m.phase==38 && a==C80_GLO && x->inflight>=59 && x->m.result.radio_rx_packets>=59)
        *regptr(&x->m,a)&=~5u;
    return read_reg(opaque,a);
}
static void rx_write(void *opaque,c80_u32 a,c80_u32 v)
{
    struct rx_model *x=opaque;struct model *m=&x->m;
    if(a==0x18004408 && m->phase!=6 && m->phase!=90) {
        struct c80_desc *d=&m->pool.rx[0][v];
        assert(m->io.rx0_rearm_test && v<64 && v==x->next_tail && x->inflight);
        assert(x->pending_barrier==1 && d->ctrl==(C80_LS0|(1536u<<16)));
        assert(d->addr==c80_dma_address(&m->io,m->pool.data[0][v]) && !d->addr1 && !d->info);
        x->pending_barrier=0;++x->attempts;
        if(x->mode==4) return; /* CPU-index write ignored; readback must fail. */
        *regptr(m,a)=v;++x->published;--x->inflight;x->next_tail=(v+1)%64;
        if(x->mode==1) rx_pump(x,1); /* hardware can immediately refill freed credit */
        return;
    }
    write_reg(opaque,a,v);
}
static void rx_barrier(void *opaque,int publish)
{
    struct rx_model *x=opaque;struct model *m=&x->m;
    if(publish && m->result.rx0_rearmed>x->attempts) {
        unsigned i=x->next_tail;struct c80_desc *d=&m->pool.rx[0][i];
        assert(!x->pending_barrier && d->ctrl==(C80_LS0|(1536u<<16)));
        assert(d->addr==c80_dma_address(&m->io,m->pool.data[0][i]) && !d->addr1 && !d->info);
        x->pending_barrier=1;++x->publish_barriers;
    }
    barrier(opaque,publish);
}
static void rx_stage(void *opaque,c80_u32 phase)
{
    struct rx_model *x=opaque;stage(opaque,phase);
    if(phase==38) rx_pump(x,x->mode==1?63:1);
}
static void rx_delay(void *opaque,c80_u32 us)
{
    struct rx_model *x=opaque;delay(opaque,us);
    if(x->m.phase==38 || x->m.phase==37) {
        ++x->ticks;
        if(x->mode!=3 || x->ticks%350==0) rx_pump(x,1);
    }
}
static struct rx_model *rx_new(unsigned mode,unsigned limit,int recycle)
{
    struct rx_model *x=calloc(1,sizeof(*x));struct model *m=&x->m;assert(x);
    x->mode=mode;x->limit=limit;x->rx_type=2;m->us=100;m->fault=BSS_GOOD;
    for(unsigned i=0;i<10;++i) *regptr(m,c80_aon_regs[i])=(c80_u32[]){0,0xe0800022,0,0xffffff20,0x11040,1,0x269f0000,0x0700b644,0x0700b644,0x9000}[i];
    *regptr(m,c80_controls[0])=0x40100000;*regptr(m,c80_controls[1])=0xf0000000;
    *regptr(m,0x180b1010)=0x10040101;*regptr(m,0x18002000)=*regptr(m,0x18002004)=0x8a00;
    *regptr(m,C80_OWN)=0x30001;*regptr(m,C80_GLO)=0x10001870;*regptr(m,C80_SYNC)=2;
    m->io=(struct c80_io){.context=x,.read=rx_read,.write=rx_write,.time_us=model_time,
        .delay_us=rx_delay,.dma_order=rx_barrier,.copy_emi=copy_emi,.crc_emi=crc_emi,.stage=rx_stage,
        .pool=&m->pool,.dma_base=0x41000000,.irq_arm=model_irq_arm,.irq_disarm=model_irq_disarm,
        .nvm_read=model_nvm_read,.devinfo_test=1,.bss_test=1,.radio_test=1,.beacon_test=1,.watch_test=1,.rx0_rearm_test=recycle};
    return x;
}
static unsigned cases;
static void rx_unit(unsigned fault,unsigned type,unsigned start,unsigned count)
{
    struct rx_model *x=rx_new(fault==15?4:fault==18?1:0,fault==18?1000:count,1);struct model *m=&x->m;
    unsigned rc,expected=fault>=1 && fault<=9?40:fault==15?45:0;
    m->phase=38;m->result.rx_next[0]=start;x->producer=x->next_tail=start%64;x->rx_type=type;
    *regptr(m,0x18004408)=(start+63)%64;*regptr(m,C80_GLO)=0x10001c75;
    for(unsigned i=0;i<64;++i) { m->pool.rx[0][i].addr=c80_dma_address(&m->io,m->pool.data[0][i]);m->pool.rx[0][i].ctrl=1536u<<16; }
    if(fault!=9) rx_pump(x,fault==18?63:count);
    struct c80_desc *d=&m->pool.rx[0][start%64];c80_u8 *p=m->pool.data[0][start%64];
    if(fault==1) d->addr^=16;
    if(fault==2) d->addr1=0x41000000;
    if(fault==3) d->ctrl&=~C80_LS0;
    if(fault==4) d->ctrl=C80_DONE|C80_LS0|(15u<<16);
    if(fault==5) d->ctrl=C80_DONE|C80_LS0|(1537u<<16);
    if(fault==6) c80_put16(p,15);
    if(fault==7) c80_put16(p,117);
    if(fault==8) c80_put16(p,32);
    if(fault==10) d->ctrl&=~C80_DONE;
    if(fault==13) p[6]|=0x80;
    if(fault==14) { d->ctrl=C80_DONE|C80_LS0|(1536u<<16);c80_put16(p,1536); }
    rc=c80_radio_receive(&m->io,&m->result);assert(rc==expected);
    if(expected==40 || fault==10) { assert(!x->attempts && !m->result.rx0_rearmed && !m->result.rx0_publishes); }
    else if(expected==45) assert(x->attempts==1 && !x->published && m->result.rx0_readback!=m->result.rx0_last_cpu);
    else {
        unsigned wanted=fault==18?64:count;
        assert(m->result.radio_rx_packets==wanted && m->result.rx0_rearmed==wanted && m->result.rx0_publishes==wanted);
        assert(x->published==wanted && x->publish_barriers==wanted && !x->pending_barrier);
        assert(m->result.rx_next[0]==(start+wanted)%64);
        assert(m->result.radio_beacon_headers==(type==2 && fault!=13?wanted:0));
        assert(m->result.radio_rx_translated==(fault==13?1u:0u));
        assert(!m->result.radio_rx_full);
        if(fault==18) { assert(m->result.rx0_budget_yields==1 && x->produced==127); }
    }
    printf("PASS RX-unit fault%u type%u start%u count%u rc%u returned%u\n",fault,type,start,count,rc,x->published);++cases;free(x);
}
static void rx_full(unsigned mode,unsigned limit,int recycle,unsigned expected)
{
    struct rx_model *x=rx_new(mode,limit,recycle);struct model *m=&x->m;
    if(mode==5) m->fault=BSS_RESET_STUCK;
    if(mode==6) m->fault=BSS_DMA_BUSY;
    if(mode==7) m->io.radio_test=0;
    unsigned rc=c80_run(&m->io,firmware,&m->result);assert(rc==expected);
    if(expected==37) assert(!m->writes && !m->tx_seen && !x->published);
    else if(expected!=80 && expected!=81) assert(m->result.dma_idle && m->result.mcu_stopped && !m->result.cleanup && !m->result.mask_after);
    if(!expected || expected==80 || expected==81) {
        assert(m->result.watch[0].complete && m->result.watch[1].complete && m->result.beacon_complete && m->result.radio_complete && m->result.bss_complete && m->result.devinfo_complete);
        assert(!m->result.watch_fault_phase && m->result.tx_completed==56 && m->result.tx_submitted==56);
        assert(m->result.radio_rx_packets==x->produced && x->produced==x->published && !x->inflight);
        assert(m->result.rx0_rearmed==x->produced && m->result.rx0_publishes==x->produced && m->result.rx_next[0]==x->produced%64);
        if(mode==1) assert(m->result.rx0_budget_yields>0);
        if(mode==2) assert(x->published>=60000);
    } else if(expected==44) {
        assert(!recycle && m->result.radio_rx_packets==59 && x->inflight==59 && !x->attempts);
        assert(m->result.watch_fault_phase==38 && m->result.watch[0].fault_bits==3 && !m->result.beacon_attempted[0]);
    } else if(expected==45) {
        assert(recycle && x->attempts==1 && !x->published && !m->result.beacon_attempted[0]);
    }
    printf("PASS RX-full mode%u limit%u recycle%d rc%u RX%u returned%u budget%u\n",mode,limit,recycle,rc,m->result.radio_rx_packets,x->published,m->result.rx0_budget_yields);++cases;free(x);
}
int main(int argc,char **argv)
{
    unsigned int i; FILE *f; char p[4096];
    const char *names[6]={"test_mcu.bin","test_wifi.bin","WIFI_RAM_CODE_iemi.bin","WIFI_RAM_CODE_demi.bin","mt7626_patch_e1_hdr.bin","WIFI_RAM_CODE_7626.bin"};
    assert(argc==4);
    f=fopen(argv[3],"rb");assert(f && fread(synthetic_nvm,1,1024,f)==1024 && fgetc(f)==EOF);fclose(f);
    f=fopen(argv[2],"rb"); assert(f);
    for(i=0;i<55;++i) {
        unsigned char length[4]; assert(fread(length,1,4,f)==4);
        stock_sizes[i]=length[0]|length[1]<<8|length[2]<<16|length[3]<<24;
        assert(stock_sizes[i]<=1152 && fread(stock_packets[i],1,stock_sizes[i],f)==stock_sizes[i]);
    }
    assert(fgetc(f)==EOF); fclose(f);
    for(i=0;i<6;++i) {
        snprintf(p,sizeof(p),"%s/%s",argv[1],names[i]); f=fopen(p,"rb"); assert(f);
        firmware[i].bytes=c80_blob_sizes[i]; firmware[i].data=malloc(firmware[i].bytes);
        assert(fread((void *)firmware[i].data,1,firmware[i].bytes,f)==firmware[i].bytes);
        assert(fgetc(f)==EOF); fclose(f);
    }
    for(unsigned start=0;start<=63;start+=(start?1:62)) {
        for(unsigned type=0;type<8;++type) rx_unit(0,type,start,1);
        for(unsigned fault=1;fault<=8;++fault) rx_unit(fault,2,start,1);
    }
    rx_unit(9,2,64,0);rx_unit(10,2,0,1);rx_unit(13,2,0,1);rx_unit(14,2,0,1);rx_unit(15,2,0,1);
    rx_unit(0,2,63,2);rx_unit(18,2,0,63);
    rx_full(0,513,1,0);rx_full(1,4097,1,0);rx_full(2,1000000,1,0);
    rx_full(3,500,0,44);rx_full(3,500,1,0);rx_full(4,1,1,45);
    rx_full(5,129,1,80);rx_full(6,129,1,81);rx_full(7,0,1,37);
    for(i=0;i<6;++i) free((void *)firmware[i].data);
    printf("PASS: %u actual-core RX recycling scenarios; all producer/credits/MMIO/MCU effects synthetic.\n",cases);
    return 0;
}
