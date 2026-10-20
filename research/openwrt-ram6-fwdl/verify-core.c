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
    RING_PROGRAM,DMA_ENABLE,OTHER_CONTROL_CHANGE,MASK_CHANGE,PATCH_BAD_FW,ADDRESS_REJECT,FINISH_REJECT,FWDL_STUCK,
    FWDL_RING_PROGRAM,FWDL_RESTORE,PATCH_NOT_READY,VERIFY_RX_STUCK,RELEASE_RX_STUCK,
    GENERIC_EVENT_BAD,GENERIC_SHORT,PATCH_CRC_BAD,MAIN_BAD_FW,MAIN_CRC_BAD,
    SYNC_INITIAL_RUNNING,SYNC_BEFORE_FFFF,SYNC_BEFORE_ZERO,SYNC_SETTLES,
    MAIN_ADDR0_BAD,MAIN_ADDR1_BAD,MAIN_ADDR2_BAD,MAIN_SCATTER_FIRST,
    MAIN_SCATTER_MIDDLE,MAIN_SCATTER_LAST,MAIN_START_BAD,MAIN_START_RX_LOST,
    MAIN_START_TX_STUCK,MAIN_READY_TIMEOUT,MAIN_READY_FFFF,MAIN_TIMER_FROZEN,
    MODE_WRITE_REFUSED,MODE_DROPS,MODE_INHERITED,MODE_RESTORE,
    HW_OBSERVED_STALL,FWDL_DONE_ONLY,FWDL_IDX_ONLY,TX_DONE_ONLY,TX_IDX_ONLY };
struct model {
    enum fault fault; struct c80_io io; struct c80_result result;
    c80_u32 regs[80][2],n,phase,writes,tx_seen,fwdl_seen,sem_gets,main_oracle,sync_reads,rx_next[2],own_command;
    c80_u64 us; c80_u8 emi[C80_EMI_SIZE];
    struct c80_dma_pool pool;
};
static struct c80_blob firmware[6];
static c80_u8 stock_packets[39][1024];
static unsigned stock_sizes[39];
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
    if(address==C80_SYNC) {
        if(m->phase==13) {
            if(m->fault==SYNC_INITIAL_RUNNING) return 6;
            if(m->fault==SYNC_BEFORE_FFFF) return ~0u;
            if(m->fault==SYNC_BEFORE_ZERO) return 0;
            if(m->fault==SYNC_SETTLES) return m->sync_reads++?2:0;
            return 2;
        }
        if(m->phase==18) {
            if(m->fault==MAIN_READY_FFFF) return ~0u;
            if(m->fault==MAIN_READY_TIMEOUT || m->fault==MAIN_TIMER_FROZEN) return 2;
            return 6;
        }
    }
    if(address==C80_GLO && m->phase==90 && m->result.dma_started && m->fault==DMA_BUSY)
        return *regptr(m,address)|10;
    if(address==C80_GLO && m->phase==14 && m->fwdl_seen==4 && m->fault==MODE_DROPS)
        *regptr(m,address)&=~C80_DOWNLOAD_MODE;
    return *regptr(m,address);
}
static void check_packet(struct model *m,c80_u8 *packet,c80_u32 length)
{
    c80_u32 cid=packet[36],k=0; c80_u8 expected[1024];
    if(m->phase>=14 && m->phase<=17) k=6+m->main_oracle++;
    else if(cid==0x10) k=packet[64]?0:5;
    else if(cid==5) k=1;
    else if(cid==0xee) k=length==1024?2:3;
    else if(cid==7) k=4;
    else assert(0);
    assert(length==stock_sizes[k]); memcpy(expected,stock_packets[k],length);
    expected[39]=(m->tx_seen+m->fwdl_seen)%15+1;
    assert(!memcmp(packet,expected,length));
}
static void produce(struct model *m,c80_u32 ctx,int fwdl)
{
    c80_u32 slot=ctx-1,q=m->fault==RX_Q0?0:1,index,cid,operation,len;
    c80_u8 *packet=fwdl?m->pool.fragment[slot]:m->pool.command[slot],*response;
    struct c80_desc *tx=fwdl?&m->pool.fwdl[slot]:&m->pool.tx[slot],*rx;
    assert(slot<(fwdl?C80_FRAGMENT_SLOTS:C80_COMMAND_SLOTS));
    assert(ctx==(fwdl?m->fwdl_seen:m->tx_seen)+1);
    len=tx->ctrl>>16&0x3fff; check_packet(m,packet,len);
    /* Independent OEM callback oracle requires GLO bit9 throughout transfer.
     * No invented scheduler credit model; real credit behavior is unmodeled. */
    assert(*regptr(m,C80_GLO)&C80_DOWNLOAD_MODE);
    assert(tx->addr==c80_dma_address(&m->io,packet));
    assert(tx->ctrl==(C80_LS0|(len<<16)));
    if(fwdl) {
        ++m->fwdl_seen;
        if(m->fault==FWDL_STUCK) return;
        if(m->fault==HW_OBSERVED_STALL && m->fwdl_seen==5) return;
        if(m->fault==FWDL_DONE_ONLY) { tx->ctrl|=C80_DONE; return; }
        if(m->fault==FWDL_IDX_ONLY) { *regptr(m,0x1800433c)=ctx; return; }
        if((m->fault==MAIN_SCATTER_FIRST && m->phase==14 && m->fwdl_seen==3) ||
           (m->fault==MAIN_SCATTER_MIDDLE && m->phase==16 && m->fwdl_seen==18) ||
           (m->fault==MAIN_SCATTER_LAST && m->phase==16 && m->fwdl_seen==31)) return;
        tx->ctrl|=C80_DONE; *regptr(m,0x1800433c)=ctx;
        return;
    }
    ++m->tx_seen;
    if(m->fault==TX_DONE_ONLY) { tx->ctrl|=C80_DONE; return; }
    if(m->fault==TX_IDX_ONLY) { *regptr(m,0x180043fc)=ctx; return; }
    if(m->fault==TX_STUCK || m->fault==TIMER_DURING_TX ||
       (m->fault==MAIN_START_TX_STUCK && packet[36]==2)) return;
    tx->ctrl|=C80_DONE; *regptr(m,0x180043fc)=ctx;
    cid=packet[36];operation=packet[64];
    if(m->fault==RX_STUCK || (m->fault==MAIN_START_RX_LOST && cid==2) || (m->fault==VERIFY_RX_STUCK && m->phase==12) ||
       (m->fault==RELEASE_RX_STUCK && cid==0x10 && !operation)) return;
    index=m->rx_next[q]++; assert(index<C80_RX_N);
    response=m->pool.data[q][index];rx=&m->pool.rx[q][index];
    assert(rx->addr==c80_dma_address(&m->io,response));
    assert(rx->ctrl==C80_RX_SIZE<<16);
    memset(response,0,28); c80_put16(response+16,12); c80_put16(response+18,0xe000);
    response[20]=cid==0x10?4:1; response[21]=packet[39];
    if(cid==0x10) {
        if(operation) {
            response[24]=++m->sem_gets==1?2:1;
            if(m->fault==SEM_ALREADY) response[24]=1;
            if(m->fault==PATCH_NOT_READY) response[24]=2;
        } else response[24]=3;
        if(m->fault==SEM_FAIL) response[24]=0;
        if(!operation && m->fault==RELEASE_BAD) response[24]=2;
    }
    if(cid==1 && ((m->fault==MAIN_ADDR0_BAD && m->phase==14) ||
       (m->fault==MAIN_ADDR1_BAD && m->phase==15) ||
       (m->fault==MAIN_ADDR2_BAD && m->phase==16))) response[24]=1;
    if(cid==2 && m->fault==MAIN_START_BAD) response[24]=2;
    if(cid==5 && m->fault==ADDRESS_REJECT) response[24]=1;
    if(cid==7 && m->fault==FINISH_REJECT) response[24]=2;
    if(m->fault==SEQ_BAD) response[21]^=1;
    if(m->fault==EID_BAD || (m->fault==GENERIC_EVENT_BAD && cid!=0x10)) response[20]=0x18;
    if(m->fault==PKT_BAD) response[19]=0xd0;
    if(m->fault==RX_BAD_LEN) c80_put16(response+16,2000);
    rx->ctrl=C80_DONE|C80_LS0|(28u<<16);
    if(m->fault==RX_SMALL || (m->fault==GENERIC_SHORT && cid!=0x10)) rx->ctrl=C80_DONE|C80_LS0|(20u<<16);
    if(m->fault==RX_LARGE) rx->ctrl=C80_DONE|C80_LS0|(2000u<<16);
    if(m->fault==RX_FRAGMENT) rx->ctrl&=~C80_LS0;
    *regptr(m,C80_SOURCE)|=1u<<q;
}
static void write_reg(void *opaque,c80_u32 address,c80_u32 value)
{
    struct model *m=opaque; c80_u32 i,permitted=0;
    for(i=0;i<4;++i)
        if((i<3 && address==c80_controls[i]) || (address>=c80_ring_regs[i] &&
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
    if(m->fault==FWDL_RING_PROGRAM && m->phase==6 && address==0x18004330) return;
    if(m->fault==DMA_ENABLE && m->phase==6 && address==C80_GLO) return;
    if(m->fault==MODE_WRITE_REFUSED && m->phase==6 && address==C80_GLO && (value&C80_DOWNLOAD_MODE)) return;
    if(m->phase==90) {
        if(m->fault==DMA_STUCK && address==C80_GLO) return;
        if(m->fault==MODE_RESTORE && address==C80_GLO && value==0x10001870) return;
        if(m->fault==RESTORE_GLO_ACTIVE && address==C80_GLO && value==0x10001870) value|=1;
        if(m->fault==RESTORE_CONTROL && address==c80_controls[0]) return;
        if(m->fault==FWDL_RESTORE && address==0x18004330) return;
        if(m->fault==RESTORE_RING && address==c80_ring_regs[0]) return;
    }
    *regptr(m,address)=value;
    if((address==0x180043f8 || address==0x18004338) && m->phase!=90 && value) {
        assert((*regptr(m,C80_GLO)&5)==5);
        produce(m,value,address==0x18004338);
    }
}
static c80_u64 model_time(void *opaque)
{ return ((struct model *)opaque)->us; }
static void delay(void *opaque,c80_u32 us)
{
    struct model *m=opaque;
    if(m->fault==TIMER || (m->fault==MAIN_TIMER_FROZEN && m->phase==18) || (m->fault==TIMER_DURING_TX && m->phase==7)) return;
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
    struct c80_blob fw[6]; memcpy(fw,firmware,sizeof(fw));
    assert(m); m->fault=fault; m->us=100;
    for(i=0;i<10;++i) *regptr(m,c80_aon_regs[i])=(c80_u32[]){0,0xe0800022,0,
        0xffffff20,0x11040,1,0x269f0000,0x0700b644,0x0700b644,0x9000}[i];
    *regptr(m,c80_controls[0])=0x40100000; *regptr(m,c80_controls[1])=0xf0000000;
    *regptr(m,0x180b1010)=0x10040101;
    *regptr(m,0x18002000)=*regptr(m,0x18002004)=0x8a00;
    *regptr(m,C80_OWN)=fault==OWN_ZERO?0x30000:0x30001;
    *regptr(m,C80_GLO)=0x10001870;
    *regptr(m,C80_SYNC)=2;
    if(fault==MODE_INHERITED) *regptr(m,C80_GLO)|=C80_DOWNLOAD_MODE;
    if(fault==BAD_FW) fw[2].bytes--;
    if(fault==MAIN_BAD_FW) fw[5].bytes--;
    if(fault==MAIN_CRC_BAD) ((c80_u8 *)fw[5].data)[0]^=1;
    if(fault==PATCH_BAD_FW) fw[4].bytes--;
    if(fault==PATCH_CRC_BAD) ((c80_u8 *)fw[4].data)[30]^=1;
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
    if(fault==PATCH_CRC_BAD) ((c80_u8 *)fw[4].data)[30]^=1;
    if(fault==MAIN_CRC_BAD) ((c80_u8 *)fw[5].data)[0]^=1;
    if(rc==0) {
        assert(m->result.download_mode_checked);
        assert(m->result.download_enable_glo&C80_DOWNLOAD_MODE);
        assert(m->result.download_last_glo&C80_DOWNLOAD_MODE);
        assert(m->result.glo_after==m->result.glo_before);
        assert(!m->result.failure_snapshot);
        assert(m->result.ready && m->result.get_valid && m->result.dma_idle && m->result.mcu_stopped);
        assert(!(*regptr(m,C80_GLO)&15));
        assert(m->result.tx_completed==m->result.tx_submitted);
        assert(m->result.main_ready && m->result.main_regions_complete==3);
        assert(m->result.main_region_valid==7 && m->result.main_start_valid && !m->result.main_start_status);
        assert(m->result.main_bytes==25616 && m->result.main_chunks==29);
        assert(m->result.main_region_bytes[0]==2896 && m->result.main_region_bytes[1]==1584 && m->result.main_region_bytes[2]==21136);
        assert(m->result.main_region_chunks[0]==4 && m->result.main_region_chunks[1]==2 && m->result.main_region_chunks[2]==23);
        assert(m->main_oracle==33);
        if(fault==SEM_ALREADY) {
            assert(m->result.tx_submitted==34 && !m->result.release_valid && !m->result.patch_uploaded);
            assert(m->result.command_submitted==5 && m->result.fwdl_completed==29 && m->result.sequence==4);
        } else {
            assert(m->result.tx_submitted==40 && m->result.release_valid && m->result.release_status==3);
            assert(m->result.command_submitted==9 && m->result.fwdl_completed==31 && m->result.sequence==10);
            assert(m->result.patch_bytes==1808 && m->result.patch_chunks==2 && m->result.patch_uploaded);
            assert(m->result.patch_ready_valid && m->result.patch_ready_status==1 && !m->result.sem_held);
        }
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
    if(m->result.rings_touched && !m->result.critical && fault!=RESTORE_RING && fault!=FWDL_RESTORE)
        for(i=0;i<4;++i) for(j=0;j<3;++j) assert(*regptr(m,c80_ring_regs[i]+j*4)==0);
    if(fault==ADDRESS_REJECT) assert(m->result.release_valid && !m->fwdl_seen && !m->result.sem_held);
    if(fault==FINISH_REJECT) assert(m->result.release_valid && !m->result.patch_uploaded && !m->result.sem_held);
    if(fault==FWDL_STUCK) assert(m->result.fwdl_submitted==1 && !m->result.fwdl_completed && !m->result.release_attempted);
    if(fault==PATCH_NOT_READY) assert(m->result.patch_ready_status==2 && !m->result.sem_held);
    if(fault==FWDL_RESTORE) assert(m->result.rings_restore_bad==1u<<9 && m->result.cleanup_flags==C80_CLEANUP_RING);
    if(fault==PATCH_CRC_BAD || fault==PATCH_BAD_FW) assert(!m->writes && !m->tx_seen && !m->fwdl_seen);
    if(fault==MAIN_BAD_FW || fault==MAIN_CRC_BAD) assert(!m->writes && !m->tx_seen && !m->fwdl_seen);
    if(fault==SYNC_INITIAL_RUNNING || fault==SYNC_BEFORE_FFFF || fault==SYNC_BEFORE_ZERO)
        assert(!m->result.main_start_attempted && !m->result.main_bytes);
    if(fault==MAIN_ADDR0_BAD || fault==MAIN_ADDR1_BAD || fault==MAIN_ADDR2_BAD ||
       fault==MAIN_SCATTER_FIRST || fault==MAIN_SCATTER_MIDDLE || fault==MAIN_SCATTER_LAST)
        assert(!m->result.main_start_attempted);
    if(fault==MAIN_START_BAD || fault==MAIN_START_RX_LOST || fault==MAIN_START_TX_STUCK)
        assert(m->result.main_start_attempted && !m->result.main_ready && m->result.main_bytes==25616);
    if(fault==MAIN_READY_TIMEOUT || fault==MAIN_READY_FFFF || fault==MAIN_TIMER_FROZEN)
        assert(m->result.main_start_valid && !m->result.main_ready && m->result.main_bytes==25616);
    if(fault==MODE_WRITE_REFUSED) {
        assert(m->result.download_mode_checked && !m->tx_seen && !m->fwdl_seen);
        assert(!m->result.cleanup && m->result.dma_idle && m->result.mcu_stopped);
    }
    if(fault==MODE_DROPS) {
        assert(m->result.main_bytes==1920 && m->fwdl_seen==4);
        assert(!m->result.main_start_attempted && !(m->result.download_last_glo&C80_DOWNLOAD_MODE));
    }
    if(fault==MODE_INHERITED) assert(m->result.glo_after==0x10001a70);
    if(fault==MODE_RESTORE) assert(m->result.cleanup_flags==C80_CLEANUP_GLO);
    if(fault==HW_OBSERVED_STALL) {
        assert(m->result.tx_submitted==11 && m->result.tx_completed==10);
        assert(m->result.command_completed==6 && m->result.fwdl_completed==4);
        assert(m->result.main_bytes==1920 && !m->result.main_start_attempted);
        assert(m->result.failure_snapshot && m->result.failure_phase==14);
        assert(m->result.failure_ring==3 && m->result.failure_slot==4);
        assert(m->result.failure_cpu==5 && m->result.failure_dma==4);
        assert(m->result.failure_desc[1]==0x44000000);
        assert(m->result.failure_desc[0]==c80_dma_address(&m->io,m->pool.fragment[4]));
        assert(m->result.failure_glo==0x10001e75 && m->result.failure_sync==2);
        assert(!m->result.cleanup && m->result.dma_idle && m->result.mcu_stopped);
    }
    if(fault==FWDL_DONE_ONLY || fault==FWDL_IDX_ONLY) {
        assert(m->result.failure_snapshot && m->result.failure_ring==3 && m->result.failure_slot==0);
        assert(!!(m->result.failure_desc[1]&C80_DONE)==(fault==FWDL_DONE_ONLY));
        assert(m->result.failure_dma==(fault==FWDL_IDX_ONLY?1u:0u));
        assert(!m->result.main_start_attempted && !m->result.fwdl_completed);
    }
    if(fault==TX_DONE_ONLY || fault==TX_IDX_ONLY) {
        assert(m->result.failure_snapshot && m->result.failure_ring==15 && m->result.failure_slot==0);
        assert(!!(m->result.failure_desc[1]&C80_DONE)==(fault==TX_DONE_ONLY));
        assert(m->result.failure_dma==(fault==TX_IDX_ONLY?1u:0u));
        assert(!m->result.command_completed && !m->result.main_attempted);
    }
    printf("PASS %s rc=%u tx=%u rx=%u critical=%u\n",name,rc,
           m->result.tx_completed,m->result.rx_packets,m->result.critical);
    free(m);
}
int main(int argc,char **argv)
{
    unsigned int i; FILE *f; char p[4096];
    const char *names[6]={"test_mcu.bin","test_wifi.bin","WIFI_RAM_CODE_iemi.bin","WIFI_RAM_CODE_demi.bin","mt7626_patch_e1_hdr.bin","WIFI_RAM_CODE_7626.bin"};
    assert(argc==3);
    f=fopen(argv[2],"rb"); assert(f);
    for(i=0;i<39;++i) {
        unsigned char length[4]; assert(fread(length,1,4,f)==4);
        stock_sizes[i]=length[0]|length[1]<<8|length[2]<<16|length[3]<<24;
        assert(stock_sizes[i]<=1024 && fread(stock_packets[i],1,stock_sizes[i],f)==stock_sizes[i]);
    }
    assert(fgetc(f)==EOF); fclose(f);
    for(i=0;i<6;++i) {
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
    test("patch-file-length-before-MMIO",PATCH_BAD_FW,1);
    test("patch-file-CRC-before-MMIO",PATCH_CRC_BAD,1);
    test("patch-address-rejected-release-still-attempted",ADDRESS_REJECT,18);
    test("patch-finish-rejected-release-still-attempted",FINISH_REJECT,18);
    test("FWDL-timeout-stop-without-more-commands",FWDL_STUCK,19);
    test("FWDL-ring-program-refused",FWDL_RING_PROGRAM,17);
    test("FWDL-ring-restore-fails",FWDL_RESTORE,16);
    test("patch-not-ready-reacquired-semaphore-released",PATCH_NOT_READY,20);
    test("patch-verification-RX-timeout",VERIFY_RX_STUCK,13);
    test("release-RX-timeout",RELEASE_RX_STUCK,13);
    test("wrong-generic-event",GENERIC_EVENT_BAD,13);
    test("short-generic-event",GENERIC_SHORT,13);
    test("main-firmware-length-before-MMIO",MAIN_BAD_FW,1);
    test("main-firmware-CRC-before-MMIO",MAIN_CRC_BAD,1);
    test("inherited-main-running-refused",SYNC_INITIAL_RUNNING,21);
    test("initial-sync-allones-refused",SYNC_BEFORE_FFFF,21);
    test("initial-sync-never-download-state",SYNC_BEFORE_ZERO,21);
    test("initial-sync-settles-to-download-state",SYNC_SETTLES,0);
    test("main-region0-address-rejected",MAIN_ADDR0_BAD,18);
    test("main-region1-address-rejected",MAIN_ADDR1_BAD,18);
    test("main-region2-address-rejected",MAIN_ADDR2_BAD,18);
    test("main-first-fragment-timeout-no-start",MAIN_SCATTER_FIRST,19);
    test("main-middle-fragment-timeout-no-start",MAIN_SCATTER_MIDDLE,19);
    test("main-last-fragment-timeout-no-start",MAIN_SCATTER_LAST,19);
    test("main-start-rejected",MAIN_START_BAD,18);
    test("main-start-response-timeout",MAIN_START_RX_LOST,13);
    test("main-start-transmit-timeout",MAIN_START_TX_STUCK,12);
    test("main-ready-timeout-after-ACK",MAIN_READY_TIMEOUT,22);
    test("main-ready-allones-not-success",MAIN_READY_FFFF,22);
    test("main-ready-stalled-clock-bounded",MAIN_TIMER_FROZEN,22);
    test("OEM-download-mode-write-refused-no-command",MODE_WRITE_REFUSED,23);
    test("download-mode-lost-no-more-TX",MODE_DROPS,23);
    test("inherited-mode-bit-preserved-by-cleanup",MODE_INHERITED,0);
    test("download-mode-restore-refused-reported",MODE_RESTORE,16);
    test("observed-RAM5-stall-position-snapshot-before-cleanup",HW_OBSERVED_STALL,19);
    test("FWDL-DONE-without-index-not-success",FWDL_DONE_ONLY,19);
    test("FWDL-index-without-DONE-not-success",FWDL_IDX_ONLY,19);
    test("command-DONE-without-index-not-success",TX_DONE_ONLY,12);
    test("command-index-without-DONE-not-success",TX_IDX_ONLY,12);
    for(i=0;i<6;++i) free((void *)firmware[i].data);
    puts("PASS:80 actual-core scenarios; OEM packet/mode oracle; all MCU/DMA/MMIO effects synthetic.");
    return 0;
}
