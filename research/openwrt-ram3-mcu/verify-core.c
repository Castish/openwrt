/* SPDX-License-Identifier: GPL-2.0-only */
/* Actual transport C core, synthetic MMIO/coherent DMA/MCU/clock behavior. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c80_mcu_core.h"

enum fault { GOOD,BAD_FW,AON_BAD,ID_BAD,STALE,TIMER,CONTROL,BOOT_STUCK,READY,
    OWN,OWN_FFFF,OWN_ZERO,GLO_ACTIVE,MASK_ON,RING_OLD,COPY_BAD,TX_STUCK,RX_STUCK,
    RX_Q0,SEQ_BAD,EID_BAD,PKT_BAD,RX_SMALL,RX_LARGE,RX_BAD_LEN,RX_FRAGMENT,
    SEM_FAIL,SEM_ALREADY,RELEASE_BAD,RESET_STUCK,DMA_STUCK,DMA_BUSY,
    RESTORE_GLO_ACTIVE,RESTORE_CONTROL,RESTORE_RING,TIMER_DURING_TX,OTHER_TX_RING,
    RING_PROGRAM,DMA_ENABLE,OTHER_CONTROL_CHANGE,MASK_CHANGE };
struct model {
    enum fault fault; struct c80_io io; struct c80_result result;
    c80_u32 regs[80][2],n,phase,writes,tx_seen,rx_next[2],own_command;
    c80_u64 us; c80_u8 emi[C80_EMI_SIZE];
    struct c80_dma_pool pool;
};
static struct c80_blob firmware[4];
static c80_u8 stock_commands[2][68];
static c80_u32 *regptr(struct model *m,c80_u32 address)
{
    c80_u32 i;
    for(i=0;i<m->n;++i) if(m->regs[i][0]==address) return &m->regs[i][1];
    assert(m->n<80); m->regs[m->n][0]=address;
    return &m->regs[m->n++][1];
}
static c80_u32 read_reg(void *opaque,c80_u32 address)
{
    struct model *m=opaque;
    if(m->phase==90 && m->fault==OTHER_CONTROL_CHANGE && address==c80_controls[0])
        *regptr(m,address)|=0x000b0e20;
    if(m->phase==90 && m->fault==MASK_CHANGE && address==C80_MASK)
        *regptr(m,address)|=1;
    if(address==0x18002600 && !( *regptr(m,C80_RESET)&0x1000))
        return m->fault==READY?0:0x1d1e;
    if(address==C80_OWN && m->own_command) {
        if(m->fault==OWN_FFFF) return ~0u;
        if(m->fault!=OWN) return 0x30000;
    }
    if(address==C80_GLO && m->phase==90 && m->result.dma_started && m->fault==DMA_BUSY)
        return *regptr(m,address)|10;
    return *regptr(m,address);
}
static void produce(struct model *m,c80_u32 ctx)
{
    c80_u32 slot=ctx-1,q=m->fault==RX_Q0?0:1,index=m->rx_next[q]++;
    c80_u8 *packet=m->pool.command[slot],*response=m->pool.data[q][index];
    struct c80_desc *tx=&m->pool.tx[slot],*rx=&m->pool.rx[q][index];
    assert(slot<2 && ctx==m->tx_seen+1 && index<C80_RX_N);
    assert(tx->addr==c80_dma_address(&m->io,packet));
    assert(tx->ctrl==(C80_LS0|(68u<<16)));
    assert(!memcmp(stock_commands[slot],packet,68));
    ++m->tx_seen;
    if(m->fault==TX_STUCK || m->fault==TIMER_DURING_TX) return;
    tx->ctrl|=C80_DONE; *regptr(m,0x180043fc)=ctx;
    if(m->fault==RX_STUCK) return;
    assert(rx->addr==c80_dma_address(&m->io,response));
    assert(rx->ctrl==C80_RX_SIZE<<16);
    memset(response,0,28); c80_put16(response+16,12); c80_put16(response+18,0xe000);
    response[20]=4; response[21]=ctx;
    response[24]=slot?3:2;
    if(m->fault==SEM_FAIL) response[24]=0;
    if(m->fault==SEM_ALREADY) response[24]=1;
    if(slot && m->fault==RELEASE_BAD) response[24]=2;
    if(m->fault==SEQ_BAD) response[21]^=1;
    if(m->fault==EID_BAD) response[20]=0x18;
    if(m->fault==PKT_BAD) response[19]=0xd0;
    if(m->fault==RX_BAD_LEN) c80_put16(response+16,2000);
    rx->ctrl=C80_DONE|C80_LS0|(28u<<16);
    if(m->fault==RX_SMALL) rx->ctrl=C80_DONE|C80_LS0|(20u<<16);
    if(m->fault==RX_LARGE) rx->ctrl=C80_DONE|C80_LS0|(2000u<<16);
    if(m->fault==RX_FRAGMENT) rx->ctrl&=~C80_LS0;
    *regptr(m,C80_SOURCE)|=1u<<(q); /* Synthesized completion, never CPU W1C. */
}
static void write_reg(void *opaque,c80_u32 address,c80_u32 value)
{
    struct model *m=opaque; c80_u32 i,permitted=0;
    for(i=0;i<3;++i)
        if(address==c80_controls[i] || (address>=c80_ring_regs[i] &&
           address<=c80_ring_regs[i]+8 && !((address-c80_ring_regs[i])&3))) permitted=1;
    assert(permitted || address==C80_RESET || address==C80_GLO || address==C80_OWN);
    ++m->writes;
    if(address==C80_RESET) {
        assert((value&0xff000000)==0x88000000);
        if(m->phase==90 && m->fault==RESET_STUCK) return;
        if(m->phase==3 && m->fault==BOOT_STUCK) return;
        value&=0xffffff;
    }
    if(address==C80_OWN) { assert(value==2); m->own_command=1; return; }
    if(m->fault==CONTROL && m->phase==3 && address==c80_controls[1]) return;
    if(m->fault==RING_PROGRAM && m->phase==6 && address==0x18004400) return;
    if(m->fault==DMA_ENABLE && m->phase==6 && address==C80_GLO) return;
    if(m->phase==90) {
        if(m->fault==DMA_STUCK && address==C80_GLO) return;
        if(m->fault==RESTORE_GLO_ACTIVE && address==C80_GLO && value==0x10001870) value|=1;
        if(m->fault==RESTORE_CONTROL && address==c80_controls[0]) return;
        if(m->fault==RESTORE_RING && address==c80_ring_regs[0]) return;
    }
    *regptr(m,address)=value;
    if(address==0x180043f8 && m->phase!=90 && value) {
        assert((*regptr(m,C80_GLO)&5)==5);
        produce(m,value);
    }
}
static c80_u64 model_time(void *opaque)
{ return ((struct model *)opaque)->us; }
static void delay(void *opaque,c80_u32 us)
{
    struct model *m=opaque;
    if(m->fault==TIMER || (m->fault==TIMER_DURING_TX && m->phase==7)) return;
    m->us+=us;
}
static void barrier(void *opaque,int publish) { (void)opaque; (void)publish; }
static void stage(void *opaque,c80_u32 s) { ((struct model *)opaque)->phase=s; }
static void copy_emi(void *opaque,c80_u32 offset,const c80_u8 *src,c80_u32 n)
{
    struct model *m=opaque;
    assert(offset<C80_EMI_SIZE && n<=C80_EMI_SIZE-offset);
    if(offset>=0x75000) {
        assert(!(*regptr(m,C80_RESET)&0x1000));
        assert(!(read_reg(m,C80_OWN)&1));
        assert(!(*regptr(m,C80_GLO)&15));
    } else assert(*regptr(m,C80_RESET)&0x1000);
    memcpy(m->emi+offset,src,n);
    if(m->fault==COPY_BAD && offset==0x146800) m->emi[offset]^=1;
}
static c80_u32 crc_emi(void *opaque,c80_u32 offset,c80_u32 n)
{
    struct model *m=opaque;
    assert(offset<C80_EMI_SIZE && n<=C80_EMI_SIZE-offset);
    return c80_crc(m->emi+offset,n);
}
static void test(const char *name,enum fault fault,c80_u32 expected)
{
    struct model *m=calloc(1,sizeof(*m)); c80_u32 i,j,rc;
    struct c80_blob fw[4]; memcpy(fw,firmware,sizeof(fw));
    assert(m); m->fault=fault; m->us=100;
    for(i=0;i<10;++i) *regptr(m,c80_aon_regs[i])=(c80_u32[]){0,0xe0800022,0,
        0xffffff20,0x11040,1,0x269f0000,0x0700b644,0x0700b644,0x9000}[i];
    *regptr(m,c80_controls[0])=0x40100000; *regptr(m,c80_controls[1])=0xf0000000;
    *regptr(m,0x180b1010)=0x10040101;
    *regptr(m,0x18002000)=*regptr(m,0x18002004)=0x8a00;
    *regptr(m,C80_OWN)=fault==OWN_ZERO?0x30000:0x30001;
    *regptr(m,C80_GLO)=0x10001870;
    if(fault==BAD_FW) fw[2].bytes--;
    if(fault==AON_BAD) *regptr(m,0x10000220)=1<<8;
    if(fault==ID_BAD) *regptr(m,0x18002000)=0x8b00;
    if(fault==STALE) *regptr(m,0x18002600)=0x1d1e;
    if(fault==GLO_ACTIVE) *regptr(m,C80_GLO)|=1;
    if(fault==MASK_ON) *regptr(m,C80_MASK)=1;
    if(fault==RING_OLD) *regptr(m,0x180043f4)=128;
    if(fault==OTHER_TX_RING) *regptr(m,0x18004334)=128;
    m->io=(struct c80_io){.context=m,.read=read_reg,.write=write_reg,.time_us=model_time,
        .delay_us=delay,.dma_order=barrier,.copy_emi=copy_emi,.crc_emi=crc_emi,.stage=stage,
        .pool=&m->pool,.dma_base=0x41000000};
    rc=c80_run(&m->io,fw,&m->result);
    if(rc!=expected) fprintf(stderr,"%s got%u expected%u phase%u get%u rx%u tx%u cleanup%u critical%u\n",
        name,rc,expected,m->phase,m->result.get_status,m->result.rx_packets,
        m->result.tx_completed,m->result.cleanup,m->result.critical);
    assert(rc==expected);
    if(rc==0) {
        assert(m->result.ready && m->result.get_valid && m->result.dma_idle && m->result.mcu_stopped);
        assert(!(*regptr(m,C80_GLO)&15));
        assert(m->result.tx_completed==m->result.tx_submitted);
        if(fault==SEM_ALREADY) assert(m->result.tx_submitted==1 && !m->result.release_valid);
        else assert(m->result.tx_submitted==2 && m->result.release_valid && m->result.release_status==3);
    }
    if(expected==80 || expected==81) {
        assert(m->result.critical && m->result.dma_started);
        /* This is the same retention predicate as the Linux wrapper. */
        assert(m->result.critical || !m->result.dma_idle);
    } else if(m->result.mcu_released) assert(*regptr(m,C80_RESET)&0x1000);
    if(fault==RING_PROGRAM) assert(!m->result.dma_started && !m->tx_seen);
    if(fault==DMA_ENABLE) assert(!m->tx_seen && m->result.dma_idle);
    if(fault==OTHER_CONTROL_CHANGE) {
        assert(m->result.control_diff[0]==0x000b0e20);
        assert(m->result.controls_other_changed==1 && !m->result.controls_owned_bad);
        assert(m->result.controls_after[0]==0x401b0e20 && !m->result.cleanup_flags);
    }
    if(fault==RESTORE_CONTROL) assert(m->result.cleanup_flags==C80_CLEANUP_CONTROL && m->result.controls_owned_bad==1);
    if(fault==RESTORE_RING) assert(m->result.cleanup_flags==C80_CLEANUP_RING && m->result.rings_restore_bad==1);
    if(fault==MASK_CHANGE) assert(m->result.cleanup_flags==C80_CLEANUP_MASK);
    if(m->result.rings_touched && !m->result.critical && fault!=RESTORE_RING)
        for(i=0;i<3;++i) for(j=0;j<3;++j) assert(*regptr(m,c80_ring_regs[i]+j*4)==0);
    printf("PASS %s rc=%u tx=%u rx=%u critical=%u\n",name,rc,
           m->result.tx_completed,m->result.rx_packets,m->result.critical);
    free(m);
}
int main(int argc,char **argv)
{
    unsigned int i; FILE *f; char p[4096];
    const char *names[4]={"test_mcu.bin","test_wifi.bin","WIFI_RAM_CODE_iemi.bin","WIFI_RAM_CODE_demi.bin"};
    assert(argc==3);
    f=fopen(argv[2],"rb"); assert(f);
    assert(fread(stock_commands,1,sizeof(stock_commands),f)==sizeof(stock_commands));
    assert(fgetc(f)==EOF); fclose(f);
    for(i=0;i<4;++i) {
        snprintf(p,sizeof(p),"%s/%s",argv[1],names[i]); f=fopen(p,"rb"); assert(f);
        firmware[i].bytes=c80_blob_sizes[i]; firmware[i].data=malloc(firmware[i].bytes);
        assert(fread((void *)firmware[i].data,1,firmware[i].bytes,f)==firmware[i].bytes);
        assert(fgetc(f)==EOF); fclose(f);
    }
    test("get-and-release",GOOD,0); test("already-host-owned",OWN_ZERO,0);
    test("events-on-RX0",RX_Q0,0); test("patch-already-ready",SEM_ALREADY,0);
    test("firmware-length",BAD_FW,1); test("power-preconditions",AON_BAD,2);
    test("chip-ID",ID_BAD,3); test("stale-ready",STALE,4); test("timer",TIMER,5);
    test("control-write",CONTROL,6); test("reset-release",BOOT_STUCK,6);
    test("MCU-ready-timeout",READY,7); test("ownership-timeout",OWN,8);
    test("ownership-allones",OWN_FFFF,8); test("DMA-already-active",GLO_ACTIVE,9);
    test("interrupt-mask-on",MASK_ON,9); test("main-EMI-copy-CRC",COPY_BAD,10);
    test("rings-already-configured",RING_OLD,11); test("TX-timeout",TX_STUCK,12);
    test("other-TX-ring-configured-before-global-enable",OTHER_TX_RING,11);
    test("ring-readback-fails-no-DMA",RING_PROGRAM,17);
    test("DMA-enable-readback-fails-no-command",DMA_ENABLE,9);
    test("timer-stalls-during-TX",TIMER_DURING_TX,12); test("RX-timeout",RX_STUCK,13);
    test("wrong-sequence",SEQ_BAD,13); test("wrong-event",EID_BAD,13);
    test("wrong-packet-ID",PKT_BAD,13); test("short-event",RX_SMALL,13);
    test("oversize-DMA-frame",RX_LARGE,14); test("event-length-out-of-frame",RX_BAD_LEN,14);
    test("fragmented-frame",RX_FRAGMENT,14); test("semaphore-denied",SEM_FAIL,15);
    test("release-rejected",RELEASE_BAD,15); test("control-restore-fails",RESTORE_CONTROL,16);
    test("ring-restore-fails",RESTORE_RING,16); test("MCU-stop-fails-pool-pinned",RESET_STUCK,80);
    test("DMA-stop-fails-pool-pinned",DMA_STUCK,81); test("DMA-busy-pool-pinned",DMA_BUSY,81);
    test("DMA-reenabled-during-restore-pool-pinned",RESTORE_GLO_ACTIVE,81);
    test("hardware-observed-other-control-bits-preserved-and-reported",OTHER_CONTROL_CHANGE,0);
    test("interrupt-mask-change-still-fails-cleanup",MASK_CHANGE,16);
    for(i=0;i<4;++i) free((void *)firmware[i].data);
    puts("PASS:41 actual-core scenarios; OEM packet oracle; all MCU/DMA/MMIO effects synthetic.");
    return 0;
}
