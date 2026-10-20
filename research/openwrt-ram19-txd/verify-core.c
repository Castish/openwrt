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
    HW_OBSERVED_STALL,FWDL_DONE_ONLY,FWDL_IDX_ONLY,TX_DONE_ONLY,TX_IDX_ONLY,
    QUERY_EXT_BAD,QUERY_SEQ_BAD,QUERY_PKT_BAD,QUERY_ID_BAD,QUERY_CATEGORY_BAD,
    QUERY_COUNT_BAD,QUERY_SHORT,QUERY_LONG,QUERY_RX_LOST,QUERY_TX_LOST,
    QUERY_CLOCK,RUNTIME_MODE_STUCK,RUNTIME_GLO_FFFF,MASK_MAIN_CHANGES,
    MASK_RESET_CHANGES,MASK_RESTORE_REFUSED,QUERY_ZERO,QUERY_ALLONES,MASK_CONTROL_CHANGES,
    IRQ_GOOD,IRQ_DROP,IRQ_BAD_CATEGORY,IRQ_PRE_FFFF,IRQ_STALE,IRQ_ENABLE_REFUSED,IRQ_UNEXPECTED,
    NVM_GOOD,NVM_READ_FAIL,NVM_RADIO_BAD,NVM_ID_BAD,NVM_SET_REJECT,NVM_SET_ECHO,
    NVM_SET_EXT,NVM_SET_SHORT,NVM_SET_TX,NVM_SET_RX,NVM_GET_SOURCE,NVM_GET_FORMAT,
    NVM_GET_OFFSET,NVM_GET_COUNT,NVM_GET_LENGTH,NVM_GET_EXT,NVM_GET_SEQ,NVM_GET_PKT,
    NVM_GET_DATA,NVM_GET_TX,NVM_GET_RX,NVM_GET_9B,
    NVM_SET_DELAY_2100,NVM_SET_DELAY_59999,NVM_SET_AT_DEADLINE,NVM_SET_AFTER_DEADLINE,
    NVM_SET_CLOCK_FROZEN,NVM_SET_CLOCK_BACKWARDS,
    NVM_GET_DELAY_2100,NVM_GET_DELAY_59999,NVM_GET_AT_DEADLINE,NVM_GET_AFTER_DEADLINE,
    NVM_GET_CLOCK_FROZEN,NVM_GET_CLOCK_BACKWARDS,NVM_BOTH_DELAY,
    NVM_SET_SLOW_REJECT,NVM_GET_SLOW_MISMATCH,NVM_SET_POLL_OVERSLEEP,
    NVM_GET_PAD2,NVM_GET_PAD2_NONZERO,NVM_GET_PAD1,NVM_GET_PAD3,NVM_GET_PAD4,
    NVM_GET_PAD2_SHORT_DMA,NVM_GET_PAD2_BAD_COUNT,NVM_GET_PAD2_BAD_SOURCE,
    NVM_GET_PAD2_BAD_FORMAT,NVM_GET_PAD2_BAD_OFFSET,NVM_GET_PAD2_BAD_SEQ,
    NVM_GET_PAD2_BAD_PKT,NVM_GET_PAD2_BAD_EXT,NVM_GET_PAD2_DATA_FIRST,
    NVM_GET_PAD2_DATA_LAST,NVM_GET_PAD2_9B,
    DEV_GOOD,DEV_SPECIFIC_EXT,DEV_RESERVED,DEV_BAD_MAC_ZERO,DEV_BAD_MAC_MULTICAST,DEV_BAD_MAC_FF,DEV_NO_NVM,DEV_ON_REJECT,DEV_ON_REJECT_HIGH,DEV_OFF_REJECT,DEV_OFF_REJECT_HIGH,DEV_ON_ECHO,DEV_OFF_ECHO,DEV_ON_COUNT,DEV_OFF_COUNT,DEV_ON_OWN,DEV_OFF_OWN,DEV_ON_LEN,DEV_OFF_LEN,DEV_ON_SHORT_DMA,DEV_ON_SEQ,DEV_ON_PKT,DEV_ON_EID,DEV_ON_EXT,DEV_ON_TX,DEV_OFF_TX,DEV_ON_RX,DEV_OFF_RX,DEV_NVM_MISMATCH,DEV_CPU_IRQ_DROP,DEV_CLOCK_FROZEN,DEV_RESET_STUCK,DEV_DMA_BUSY,DEV_PATCH_READY,DEV_DELAY_3000,DEV_DELAY_5999,DEV_AT_DEADLINE,DEV_BACKWARDS,VAR_ON40,VAR_OFF40,VAR_BOTH40,VAR_ODD29,VAR_MAX,VAR_TRUNCATED,VAR_OVERDECLARED,VAR_ECHO,VAR_COUNT,VAR_OWN,VAR_REJECT,VAR_HIGH,VAR_OFF_REJECT,VAR_SEQ,VAR_PKT,VAR_EXT,BSS_GOOD,BSS_GENERIC_EXT,BSS_MAX_REPLY,BSS_SHORT_BASE,BSS_OFF_SHORT_BASE,BSS_TRUNCATED,BSS_ECHO,BSS_OFF_ECHO,BSS_INDEX,BSS_OFF_INDEX,BSS_COUNT,BSS_OFF_COUNT,BSS_REJECT,BSS_HIGH_REJECT,BSS_OFF_REJECT,BSS_OFF_HIGH_REJECT,BSS_EXT_BAD,BSS_SEQ_BAD,BSS_PID_BAD,BSS_TX_LOST,BSS_OFF_TX_LOST,BSS_RX_LOST,BSS_OFF_RX_LOST,BSS_DEV_OFF_FAIL,BSS_NO_DEVINFO,BSS_DEV_ON_FAIL,BSS_NVM_FAIL,BSS_DELAY_5999,BSS_FROZEN,BSS_BACKWARDS,BSS_RESET_STUCK,BSS_DMA_BUSY,BSS_PATCH_READY };
struct model {
    enum fault fault; struct c80_io io; struct c80_result result;
    c80_u32 regs[80][2],n,phase,writes,tx_seen,fwdl_seen,sem_gets,main_oracle,sync_reads,rx_next[2],own_command;
    c80_u64 us; c80_u8 emi[C80_EMI_SIZE];
    struct c80_dma_pool pool; c80_u8 mcu_nvm[1024];
    struct c80_desc *deferred_rx; c80_u32 deferred_ctrl;
    c80_u64 deferred_due;
    unsigned rfault,rstep,bfault,bstep,wfault,wwindow;
    c80_u64 watch_start,watch_delay;
};
static struct c80_blob firmware[6];
static c80_u8 stock_packets[55][1152];
static unsigned stock_sizes[55];
static c80_u8 synthetic_nvm[1024];
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
    if(m->io.watch_test && (m->phase==37 || m->phase==38)) {
        unsigned target=(m->phase==37)==m->wwindow;
        unsigned active=target && m->us-m->watch_start>=m->watch_delay;
        if(address==C80_SYNC) return active && m->wfault==7?2:active && m->wfault==8?~0u:6;
        if(address==C80_OWN) return active && m->wfault==5?0x30001:active && m->wfault==6?~0u:0x30000;
        if(address==C80_GLO && active) {
            if(m->wfault>=1 && m->wfault<=3) *regptr(m,address)&=~(m->wfault==1?1u:m->wfault==2?4u:5u);
            if(m->wfault==4) return ~0u;
            if(m->wfault==9) *regptr(m,address)|=C80_DOWNLOAD_MODE;
            if(m->wfault==10) return *regptr(m,address)|10u; /* transient busy */
        }
        if(address==C80_SOURCE && active && m->wfault==11) return 0x80083;
    }
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
            if(m->fault==MASK_MAIN_CHANGES || m->fault==MASK_RESTORE_REFUSED)
                *regptr(m,C80_MASK)=0x20000000;
            if(m->fault==MAIN_READY_FFFF) return ~0u;
            if(m->fault==MAIN_READY_TIMEOUT || m->fault==MAIN_TIMER_FROZEN) return 2;
            return 6;
        }
    }
    if(address==C80_MASK && m->phase==20 && m->fault==IRQ_PRE_FFFF) return ~0u;
    if(address==C80_GLO && m->phase==90 && m->result.dma_started && (m->fault==DMA_BUSY || m->fault==DEV_DMA_BUSY || m->fault==BSS_DMA_BUSY))
        return *regptr(m,address)|10;
    if(address==C80_GLO && m->phase==14 && m->fwdl_seen==4 && m->fault==MODE_DROPS)
        *regptr(m,address)&=~C80_DOWNLOAD_MODE;
    if(address==C80_GLO && m->phase==19 && m->fault==RUNTIME_GLO_FFFF) return ~0u;
    return *regptr(m,address);
}
static void check_packet(struct model *m,c80_u8 *packet,c80_u32 length)
{
    c80_u32 cid=packet[36],k=0; c80_u8 expected[1152];
    if(m->phase==20 && cid==0xed) k=39;
    else if(m->phase==21 && cid==0xed) k=40;
    else if(m->phase==22 && cid==0xed) k=41;
    else if(m->phase>=33 && m->phase<=36) k=51+m->phase-33;
    else if((m->phase>=27 && m->phase<=30) || m->phase==32) k=46+c80_radio_index(m->phase);
    else if(m->phase>=25 && m->phase<=26) k=44+m->phase-25;
    else if(m->phase>=23 && m->phase<=24) k=42+m->phase-23;
    else if(m->phase>=14 && m->phase<=17) k=6+m->main_oracle++;
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
    assert(!!(*regptr(m,C80_GLO)&C80_DOWNLOAD_MODE)==(m->phase<20));
    assert(tx->addr==c80_dma_address(&m->io,packet));
    assert(!(tx->addr&15));
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
    if(m->io.beacon_test && m->phase>=33 && m->phase<=36 &&
       m->bstep==m->phase-33 && m->bfault==12) return;
    if(m->io.radio_test && ((m->phase>=27 && m->phase<=30) || m->phase==32) &&
       m->rstep==c80_radio_index(m->phase) && m->rfault==10) return;
    if((m->fault==NVM_SET_TX && m->phase==21) || (m->fault==NVM_GET_TX && m->phase==22)) return;
    if((m->fault==DEV_ON_TX && m->phase==23) || (m->fault==DEV_OFF_TX && m->phase==24)) return;
    if((m->phase==25 && m->fault==BSS_TX_LOST) || (m->phase==26 && m->fault==BSS_OFF_TX_LOST)) return;
    if(m->fault==QUERY_TX_LOST && packet[36]==0xed) return;
    if(m->fault==TX_DONE_ONLY) { tx->ctrl|=C80_DONE; return; }
    if(m->fault==TX_IDX_ONLY) { *regptr(m,0x180043fc)=ctx; return; }
    if(m->fault==TX_STUCK || m->fault==TIMER_DURING_TX ||
       (m->fault==MAIN_START_TX_STUCK && packet[36]==2)) return;
    tx->ctrl|=C80_DONE; *regptr(m,0x180043fc)=ctx;
    cid=packet[36];operation=packet[64];
    if(cid==0xed && m->phase==20) {
        assert(m->result.main_ready && m->phase==20 && len==168);
        assert(packet[38]==0 && packet[41]==0x3c && packet[43]==1);
        if(m->fault==QUERY_RX_LOST || m->fault==QUERY_CLOCK) return;
    }
    if(m->fault==RX_STUCK || (m->fault==MAIN_START_RX_LOST && cid==2) || (m->fault==VERIFY_RX_STUCK && m->phase==12) ||
       (m->fault==RELEASE_RX_STUCK && cid==0x10 && !operation)) return;
    if(((m->fault==NVM_SET_RX || m->fault==NVM_SET_CLOCK_FROZEN ||
         m->fault==NVM_SET_CLOCK_BACKWARDS || m->fault==NVM_SET_POLL_OVERSLEEP) && m->phase==21) ||
       ((m->fault==NVM_GET_RX || m->fault==NVM_GET_CLOCK_FROZEN ||
         m->fault==NVM_GET_CLOCK_BACKWARDS) && m->phase==22)) return;
    if(m->phase==21) {
        assert(len==1092 && packet[38]==1 && packet[41]==0x21 && packet[43]==1);
        memcpy(m->mcu_nvm,packet+68,1024);
    }
    if((m->phase==23 && (m->fault==DEV_ON_RX || m->fault==DEV_CLOCK_FROZEN || m->fault==DEV_BACKWARDS)) ||
       (m->phase==24 && m->fault==DEV_OFF_RX)) return;
    if((m->phase==25 && (m->fault==BSS_RX_LOST || m->fault==BSS_FROZEN || m->fault==BSS_BACKWARDS)) ||
       (m->phase==26 && m->fault==BSS_OFF_RX_LOST)) return;
    index=m->rx_next[q]++; assert(index<C80_RX_N);
    response=m->pool.data[q][index];rx=&m->pool.rx[q][index];
    assert(rx->addr==c80_dma_address(&m->io,response));
    assert(rx->ctrl==C80_RX_SIZE<<16);
    memset(response,0,28); c80_put16(response+16,12); c80_put16(response+18,0xe000);
    response[20]=cid==0x10?4:1; response[21]=packet[39];
    if(cid==0xed && m->phase==20) {
        memset(response,0,44);c80_put16(response+16,24);c80_put16(response+18,0xe000);
        response[20]=0xed;response[21]=packet[39];response[24]=0x3c;
        c80_put16(response+28,5);response[32]=1;
        c80_put32(response+36,m->fault==QUERY_ZERO?0:m->fault==QUERY_ALLONES?~0u:0x12345678);
        if(m->fault==QUERY_EXT_BAD) response[24]=0x3d;
        if(m->fault==QUERY_SEQ_BAD) response[21]^=1;
        if(m->fault==QUERY_PKT_BAD) response[19]=0xd0;
        if(m->fault==QUERY_ID_BAD) response[20]=1;
        if(m->fault==QUERY_CATEGORY_BAD || m->fault==IRQ_BAD_CATEGORY) response[28]=6;
        if(m->fault==QUERY_COUNT_BAD) response[32]=2;
        rx->ctrl=C80_DONE|C80_LS0|(40u<<16);
        if(m->fault==QUERY_SHORT) { c80_put16(response+16,20);rx->ctrl=C80_DONE|C80_LS0|(36u<<16); }
        if(m->fault==QUERY_LONG) { c80_put16(response+16,25);rx->ctrl=C80_DONE|C80_LS0|(41u<<16); }
        *regptr(m,C80_SOURCE)|=1u<<q;
        if(m->fault==IRQ_UNEXPECTED) *regptr(m,C80_SOURCE)&=~2u;
        if(m->io.irq_arm && m->fault!=IRQ_DROP && m->fault!=DEV_CPU_IRQ_DROP) c80_irq_event(&m->io,&m->result);
        return;
    }
    if(cid==0xed && m->phase>=33 && m->phase<=36) {
        unsigned k=m->phase-33,f=m->bstep==k?m->bfault:0,sync=k==0 || k==3;
        unsigned base=sync?28:20,event_bytes=m->bfault==2?base+1:m->bfault==3?1520:base;
        assert(m->io.beacon_test && m->result.radio_valid[3] && !m->result.radio_status[3]);
        assert(!(*regptr(m,C80_MASK)) && m->result.irq_cpu_stopped && !m->result.bss_attempted[1]);
        if(f==13 || f==16 || f==17) return;
        memset(response,0,C80_RX_SIZE);c80_put16(response+16,event_bytes);c80_put16(response+18,0xe000);
        response[20]=0xed;response[21]=packet[39];response[28]=sync?0x26:0x49;
        if(m->bfault==1) response[24]=response[28];
        if(sync) c80_put16(response+38,1);
        for(unsigned i=16+base;i<16+event_bytes;++i) response[i]=(c80_u8)(i*29+3);
        if(f==4 || f==20) c80_put32(response+32,1);
        if(f==5) c80_put32(response+32,0x80000000u);
        if(f==6) response[28]^=1;
        if(f==7) response[24]=0x7f;
        if(f==8) c80_put16(response+16,base-1);
        if(f==10) response[21]^=1;
        if(f==11) response[19]=0xd0;
        if(f==18 && sync) response[36]=1;
        if((f==19 || f==20) && sync) c80_put16(response+38,0);
        rx->ctrl=C80_DONE|C80_LS0|((16+event_bytes-(f==9))<<16);
        if(f==14 || f==15) {
            m->deferred_rx=rx;m->deferred_ctrl=rx->ctrl;
            m->deferred_due=m->us+6000000u-(f==14?1000u:0u);rx->ctrl=C80_RX_SIZE<<16;
        } else *regptr(m,C80_SOURCE)|=2;
        return;
    }
    if(cid==0xed && ((m->phase>=27 && m->phase<=30) || m->phase==32)) {
        unsigned k=c80_radio_index(m->phase),f=m->rstep==k?m->rfault:0;
        assert(m->io.radio_test && !(*regptr(m,C80_MASK)) && m->result.irq_cpu_stopped);
        assert(m->result.bss_valid[0] && !m->result.bss_status[0] && !m->result.bss_attempted[1]);
        if(f==11 || f==14 || f==15) return;
        memset(response,0,64);c80_put16(response+16,20);c80_put16(response+18,0xe000);
        response[20]=0xed;response[21]=packet[39];response[28]=packet[41];
        if(m->rfault==29) response[24]=packet[41];
        if(f==1) c80_put32(response+32,1);
        if(f==2) c80_put32(response+32,0x80000000u);
        if(f==3) response[28]^=1;
        if(f==4) response[24]=0x7f;
        if(f==5) c80_put16(response+16,19);
        if(f==6) c80_put16(response+16,21);
        if(f==8) response[21]^=1;
        if(f==9) response[19]=0xd0;
        rx->ctrl=C80_DONE|C80_LS0|((f==6?37u:f==7?35u:36u)<<16);
        if(f==12 || f==13) {
            m->deferred_rx=rx;m->deferred_ctrl=rx->ctrl;
            m->deferred_due=m->us+(m->phase==28?5000000u:6000000u)-(f==12?1000u:0u);
            rx->ctrl=C80_RX_SIZE<<16;
        } else *regptr(m,C80_SOURCE)|=2;
        return;
    }
    if(cid==0xed && (m->phase==25 || m->phase==26)) {
        unsigned on=m->phase==25;
        assert(m->io.bss_test && m->result.devinfo_valid[0] && !m->result.devinfo_status[0]);
        assert(!m->result.devinfo_attempted[1] && m->result.nvm_equal && !(*regptr(m,C80_MASK)));
        assert(len==(on?116u:100u) && packet[38]==0 && packet[41]==0x26 && packet[43]==1);
        memset(response,0,C80_RX_SIZE);c80_put16(response+18,0xe000);
        c80_put16(response+16,m->fault==BSS_MAX_REPLY?1520:40);
        response[20]=0xed;response[21]=packet[39];response[24]=m->fault==BSS_GENERIC_EXT?0:0x26;
        response[28]=0x26;c80_put16(response+38,on?2:1);
        for(unsigned i=44;i<(m->fault==BSS_MAX_REPLY?1536u:56u);++i) response[i]=(c80_u8)(i*19+5);
        rx->ctrl=C80_DONE|C80_LS0|((m->fault==BSS_MAX_REPLY?1536u:56u)<<16);
        if((on && m->fault==BSS_SHORT_BASE) || (!on && m->fault==BSS_OFF_SHORT_BASE)) c80_put16(response+16,27);
        if(on && m->fault==BSS_TRUNCATED) rx->ctrl=C80_DONE|C80_LS0|(55u<<16);
        if((on && m->fault==BSS_ECHO) || (!on && m->fault==BSS_OFF_ECHO)) response[28]^=1;
        if((on && m->fault==BSS_INDEX) || (!on && m->fault==BSS_OFF_INDEX)) response[36]=1;
        if((on && m->fault==BSS_COUNT) || (!on && m->fault==BSS_OFF_COUNT)) c80_put16(response+38,on?1:2);
        if((on && m->fault==BSS_REJECT) || (!on && m->fault==BSS_OFF_REJECT)) c80_put32(response+32,1);
        if((on && m->fault==BSS_HIGH_REJECT) || (!on && m->fault==BSS_OFF_HIGH_REJECT)) {
            c80_put32(response+32,0x80000000u);c80_put16(response+38,0);
        }
        if(on && m->fault==BSS_EXT_BAD) response[24]=0x2a;
        if(on && m->fault==BSS_SEQ_BAD) response[21]^=1;
        if(on && m->fault==BSS_PID_BAD) response[19]=0xd0;
        if(on && m->fault==BSS_DELAY_5999) {
            m->deferred_rx=rx;m->deferred_ctrl=rx->ctrl;m->deferred_due=m->us+5999000;
            rx->ctrl=C80_RX_SIZE<<16;
        } else *regptr(m,C80_SOURCE)|=2;
        return;
    }
    if(cid==0xed && (m->phase==23 || m->phase==24)) {
        int on=m->phase==23;
        assert(m->io.devinfo_test && m->result.nvm_equal && m->result.irq_cpu_stopped);
        assert(len==84 && packet[38]==0 && packet[41]==0x2a && packet[43]==1);
        memset(response,0,44);c80_put16(response+16,28);c80_put16(response+18,0xe000);
        response[20]=0xed;response[21]=packet[39];response[28]=0x2a;
        c80_put16(response+38,1);
        if(m->fault==DEV_SPECIFIC_EXT) response[24]=0x2a;
        if(m->fault==DEV_RESERVED) { response[29]=0xa5;response[37]=0x5a;response[40]=0xff; }
        if((on && m->fault==DEV_ON_REJECT) || (!on && m->fault==DEV_OFF_REJECT)) c80_put32(response+32,1);
        if((on && m->fault==DEV_ON_REJECT_HIGH) || (!on && m->fault==DEV_OFF_REJECT_HIGH)) {
            c80_put32(response+32,0x80000000u);c80_put16(response+38,0);
        }
        if((on && m->fault==DEV_ON_ECHO) || (!on && m->fault==DEV_OFF_ECHO)) response[28]^=1;
        if((on && m->fault==DEV_ON_COUNT) || (!on && m->fault==DEV_OFF_COUNT)) c80_put16(response+38,2);
        if((on && m->fault==DEV_ON_OWN) || (!on && m->fault==DEV_OFF_OWN)) response[36]=1;
        rx->ctrl=C80_DONE|C80_LS0|(44u<<16);
        if((on && m->fault==DEV_ON_LEN) || (!on && m->fault==DEV_OFF_LEN)) c80_put16(response+16,27);
        if(on && m->fault==DEV_ON_SHORT_DMA) rx->ctrl=C80_DONE|C80_LS0|(43u<<16);
        if(on && m->fault==DEV_ON_SEQ) response[21]^=1;
        if(on && m->fault==DEV_ON_PKT) response[19]=0xd0;
        if(on && m->fault==DEV_ON_EID) response[20]=1;
        if(on && m->fault==DEV_ON_EXT) response[24]=0x7f;
        if(m->io.bss_test) {
            response[24]=0x2a;c80_put16(response+16,40);rx->ctrl=C80_DONE|C80_LS0|(56u<<16);
            if((on && m->fault==BSS_DEV_ON_FAIL) || (!on && m->fault==BSS_DEV_OFF_FAIL)) c80_put32(response+32,1);
        }
        if(m->fault>=VAR_ON40 && m->fault<=VAR_EXT) {
            unsigned extended=!(on && m->fault==VAR_OFF40) && !(!on && m->fault==VAR_ON40);
            unsigned event_bytes=!extended?28:m->fault==VAR_ODD29?29:m->fault==VAR_MAX?1520:40;
            c80_put16(response+16,event_bytes);
            for(unsigned z=44;z<16+event_bytes;++z) response[z]=(c80_u8)(z*37+9);
            rx->ctrl=C80_DONE|C80_LS0|((16+event_bytes)<<16);
            if(on && m->fault==VAR_TRUNCATED) rx->ctrl=C80_DONE|C80_LS0|(55u<<16);
            if(on && m->fault==VAR_OVERDECLARED) { c80_put16(response+16,1521);rx->ctrl=C80_DONE|C80_LS0|(1536u<<16); }
            if(on && m->fault==VAR_ECHO) response[28]^=1;
            if(on && m->fault==VAR_COUNT) c80_put16(response+38,2);
            if(on && m->fault==VAR_OWN) response[36]=1;
            if((on && m->fault==VAR_REJECT) || (!on && m->fault==VAR_OFF_REJECT)) c80_put32(response+32,1);
            if(on && m->fault==VAR_HIGH) { c80_put32(response+32,0x80000000u);c80_put16(response+38,0); }
            if(on && m->fault==VAR_SEQ) response[21]^=1;
            if(on && m->fault==VAR_PKT) response[19]=0xd0;
            if(on && m->fault==VAR_EXT) response[24]=0x7f;
        }
        if(on && (m->fault==DEV_DELAY_3000 || m->fault==DEV_DELAY_5999 || m->fault==DEV_AT_DEADLINE)) {
            m->deferred_rx=rx;m->deferred_ctrl=rx->ctrl;
            m->deferred_due=m->us+(m->fault==DEV_DELAY_3000?3000000u:m->fault==DEV_DELAY_5999?5999000u:6000000u);
            rx->ctrl=C80_RX_SIZE<<16;
        } else *regptr(m,C80_SOURCE)|=2;
        return;
    }
    if(cid==0xed && m->phase>=21 && m->phase<=22) {
        memset(response,0,C80_RX_SIZE);c80_put16(response+18,0xe000);
        response[20]=0xed;response[21]=packet[39];
        if(m->phase==21) {
            c80_put16(response+16,20);response[28]=0x21;
            if(m->fault==NVM_SET_REJECT || m->fault==NVM_SET_SLOW_REJECT) c80_put32(response+32,1);
            if(m->fault==NVM_SET_ECHO) response[28]=0x20;
            if(m->fault==NVM_SET_EXT) response[24]=0x22;
            rx->ctrl=C80_DONE|C80_LS0|(36u<<16);
            if(m->fault==NVM_SET_SHORT) { c80_put16(response+16,19);rx->ctrl=C80_DONE|C80_LS0|(35u<<16); }
        } else {
            assert(m->phase==22 && len==70 && packet[38]==0 && packet[41]==0x9b);
            c80_u32 padding=m->fault>=NVM_GET_PAD2?2:0;
            if(m->fault==NVM_GET_PAD1) padding=1;
            if(m->fault==NVM_GET_PAD3) padding=3;
            if(m->fault==NVM_GET_PAD4) padding=4;
            c80_put16(response+16,1042+padding);
            response[24]=(m->fault==NVM_GET_9B || m->fault==NVM_GET_PAD2_9B)?0x9b:0x8a;
            response[28]=1;response[29]=1;c80_put16(response+30,0);c80_put16(response+32,1024);
            memcpy(response+34,m->mcu_nvm,1024);
            if(m->fault==NVM_GET_SOURCE || m->fault==NVM_GET_PAD2_BAD_SOURCE) response[28]=0;
            if(m->fault==NVM_GET_FORMAT || m->fault==NVM_GET_PAD2_BAD_FORMAT) response[29]=0;
            if(m->fault==NVM_GET_OFFSET || m->fault==NVM_GET_PAD2_BAD_OFFSET) c80_put16(response+30,1);
            if(m->fault==NVM_GET_COUNT || m->fault==NVM_GET_PAD2_BAD_COUNT) c80_put16(response+32,1025);
            if(m->fault==NVM_GET_EXT || m->fault==NVM_GET_PAD2_BAD_EXT) response[24]=0x7f;
            if(m->fault==NVM_GET_SEQ || m->fault==NVM_GET_PAD2_BAD_SEQ) response[21]^=1;
            if(m->fault==NVM_GET_PKT || m->fault==NVM_GET_PAD2_BAD_PKT) response[19]=0xd0;
            if(m->fault==NVM_GET_DATA || m->fault==NVM_GET_SLOW_MISMATCH || m->fault==DEV_NVM_MISMATCH || m->fault==BSS_NVM_FAIL) response[34+959]^=1;
            if(m->fault==NVM_GET_PAD2_DATA_FIRST) response[34]^=1;
            if(m->fault==NVM_GET_PAD2_DATA_LAST) response[34+1023]^=1;
            if(m->fault==NVM_GET_PAD2_NONZERO) { response[34+1024]=0xa5;response[34+1025]=0x5a; }
            rx->ctrl=C80_DONE|C80_LS0|((1058u+padding)<<16);
            if(m->fault==NVM_GET_PAD2_SHORT_DMA) rx->ctrl=C80_DONE|C80_LS0|(1058u<<16);
            if(m->fault==NVM_GET_LENGTH) { c80_put16(response+16,1041);rx->ctrl=C80_DONE|C80_LS0|(1057u<<16); }
        }
        /* Actual C core sees DONE only at the modeled MCU publication time.
         * This is a delayed synthetic response, not OEM firmware execution. */
        if((m->phase==21 && (m->fault==NVM_SET_DELAY_2100 || m->fault==NVM_SET_DELAY_59999 ||
           m->fault==NVM_SET_AT_DEADLINE || m->fault==NVM_SET_AFTER_DEADLINE ||
           m->fault==NVM_BOTH_DELAY || m->fault==NVM_SET_SLOW_REJECT)) ||
           (m->phase==22 && (m->fault==NVM_GET_DELAY_2100 || m->fault==NVM_GET_DELAY_59999 ||
           m->fault==NVM_GET_AT_DEADLINE || m->fault==NVM_GET_AFTER_DEADLINE ||
           m->fault==NVM_BOTH_DELAY || m->fault==NVM_GET_SLOW_MISMATCH))) {
            c80_u32 wait=2100000;
            if(m->fault==NVM_SET_DELAY_59999 || m->fault==NVM_GET_DELAY_59999) wait=59999000;
            if(m->fault==NVM_SET_AT_DEADLINE || m->fault==NVM_GET_AT_DEADLINE) wait=60000000;
            if(m->fault==NVM_SET_AFTER_DEADLINE || m->fault==NVM_GET_AFTER_DEADLINE) wait=60001000;
            if(m->fault==NVM_BOTH_DELAY) wait=m->phase==21?3000000:4000000;
            m->deferred_rx=rx;m->deferred_ctrl=rx->ctrl;m->deferred_due=m->us+wait;
            rx->ctrl=C80_RX_SIZE<<16;
        } else *regptr(m,C80_SOURCE)|=2;
        return;
    }
    if(cid==0x10) {
        if(operation) {
            response[24]=++m->sem_gets==1?2:1;
            if(m->fault==SEM_ALREADY || m->fault==DEV_PATCH_READY || m->fault==BSS_PATCH_READY) response[24]=1;
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
    if(m->io.watch_test) assert(m->phase!=37 && m->phase!=38); /* watch must never write MMIO */
    for(i=0;i<4;++i)
        if((i<3 && address==c80_controls[i]) || (address>=c80_ring_regs[i] &&
           address<=c80_ring_regs[i]+8 && !((address-c80_ring_regs[i])&3))) permitted=1;
    assert(permitted || address==C80_RESET || address==C80_GLO || address==C80_OWN || address==C80_MASK || address==C80_SOURCE);
    if(address==C80_SOURCE) {
        assert(m->phase==20 && value==C80_IRQ_RX1 && m->result.irq_attempted);
        if(m->fault!=IRQ_STALE) *regptr(m,address)&=~value;
        ++m->writes; return;
    }
    if(address==C80_MASK && m->phase==20) {
        assert(m->io.irq_arm && (value==0 || value==C80_IRQ_RX1));
        if(m->fault==IRQ_ENABLE_REFUSED && value) return;
    } else if(address==C80_MASK) {
        assert(m->phase==90 && !value && m->result.dma_cfg_touched && !m->result.mask_before);
        if(m->fault==MASK_RESTORE_REFUSED) return;
    }
    ++m->writes;
    if(address==C80_RESET) {
        assert((value&0xff000000)==0x88000000);
        if(m->phase==90 && (m->fault==RESET_STUCK || m->fault==DEV_RESET_STUCK || m->fault==BSS_RESET_STUCK)) return;
        if(m->phase==3 && m->fault==BOOT_STUCK) return;
        if(m->phase==90 && m->fault==MASK_RESET_CHANGES) *regptr(m,C80_MASK)=0x20000000;
        value&=0xffffff;
    }
    if(address==C80_OWN) { assert(value==2); m->own_command=1; return; }
    if(m->fault==CONTROL && m->phase==3 && address==c80_controls[1]) return;
    if(m->fault==RING_PROGRAM && m->phase==6 && address==0x18004400) return;
    if(m->fault==FWDL_RING_PROGRAM && m->phase==6 && address==0x18004330) return;
    if(m->fault==DMA_ENABLE && m->phase==6 && address==C80_GLO) return;
    if(m->fault==MODE_WRITE_REFUSED && m->phase==6 && address==C80_GLO && (value&C80_DOWNLOAD_MODE)) return;
    if(m->fault==RUNTIME_MODE_STUCK && m->phase==19 && address==C80_GLO) return;
    if(m->phase==90) {
        if(m->fault==DMA_STUCK && address==C80_GLO) return;
        if(m->fault==MODE_RESTORE && address==C80_GLO && value==0x10001870) return;
        if(m->fault==RESTORE_GLO_ACTIVE && address==C80_GLO && value==0x10001870) value|=1;
        if(m->fault==RESTORE_CONTROL && address==c80_controls[0]) return;
        if(m->fault==FWDL_RESTORE && address==0x18004330) return;
        if(m->fault==RESTORE_RING && address==c80_ring_regs[0]) return;
    }
    *regptr(m,address)=value;
    if(m->phase==90 && m->fault==MASK_CONTROL_CHANGES && address==c80_controls[0])
        *regptr(m,C80_MASK)=0x20000000;
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
    if(m->io.watch_test && (m->phase==37 || m->phase==38) && ((m->phase==37)==m->wwindow)) {
        if(m->wfault==12) return;
        if(m->wfault==13) { m->us=m->watch_start-1;return; }
        if(m->wfault==14) us+=100000;
    }
    if(m->io.beacon_test && m->phase>=33 && m->phase<=36 && m->bstep==m->phase-33) {
        if(m->bfault==16) return;
        if(m->bfault==17) { m->us=0;return; }
    }
    if(m->phase==37 && m->bfault==30) return;
    if(m->phase==37 && m->bfault==31) { m->us=0;return; }
    if(m->io.radio_test && ((m->phase>=27 && m->phase<=30) || m->phase==32) && m->rstep==c80_radio_index(m->phase)) {
        if(m->rfault==14) return;
        if(m->rfault==15) { m->us=0;return; }
    }
    if(m->phase==31 && m->rfault==27) return;
    if(m->phase==31 && m->rfault==28) { m->us=0;return; }
    if(m->phase==25 && m->fault==BSS_FROZEN) return;
    if(m->phase==25 && m->fault==BSS_BACKWARDS) { m->us=0;return; }
    if(m->phase==23 && m->fault==DEV_CLOCK_FROZEN) return;
    if(m->phase==23 && m->fault==DEV_BACKWARDS) { m->us=0;return; }
    if((m->phase==21 && m->fault==NVM_SET_CLOCK_FROZEN) ||
       (m->phase==22 && m->fault==NVM_GET_CLOCK_FROZEN)) return;
    if((m->phase==21 && m->fault==NVM_SET_CLOCK_BACKWARDS) ||
       (m->phase==22 && m->fault==NVM_GET_CLOCK_BACKWARDS)) { m->us=0;return; }
    if(m->fault==TIMER || (m->fault==MAIN_TIMER_FROZEN && m->phase==18) ||
       (m->fault==TIMER_DURING_TX && m->phase==7) || (m->fault==QUERY_CLOCK && m->phase==20)) return;
    m->us+=us;
    if(m->phase==21 && m->fault==NVM_SET_POLL_OVERSLEEP) m->us+=20000;
    if(m->deferred_rx && m->us>=m->deferred_due) {
        m->deferred_rx->ctrl=m->deferred_ctrl;m->deferred_rx=0;
        *regptr(m,C80_SOURCE)|=2;
    }
}
static void barrier(void *opaque,int publish) { (void)opaque; (void)publish; }
static void stage(void *opaque,c80_u32 s)
{
    struct model *m=opaque; m->phase=s;
    if(m->io.watch_test && (s==37 || s==38)) {
        m->watch_start=m->us;
        if(m->wfault==15 && ((s==37)==m->wwindow)) {
            for(unsigned i=0;i<63;++i) {
                c80_u8 *p=m->pool.data[0][i];memset(p,0,128);c80_put32(p,(2u<<29)|(15u<<25)|116);c80_put16(p+80,0x80);
                m->pool.rx[0][i].ctrl=C80_DONE|C80_LS0|(116u<<16);
            }
        }
    }
    if(s==37 && (m->bfault==32 || m->bfault==33)) {
        unsigned count=m->bfault==33?63:1;
        for(unsigned i=0;i<count;++i) {
            c80_u8 *p=m->pool.data[0][i];memset(p,0,128);c80_put32(p,(2u<<29)|(15u<<25)|116);c80_put16(p+80,0x80);
            m->pool.rx[0][i].ctrl=C80_DONE|C80_LS0|(116u<<16);
            if(m->bfault==32) m->pool.rx[0][i].ctrl&=~C80_LS0;
        }
    }
    if(s==37 && m->bfault==34) {
        for(unsigned i=m->result.rx_next[1];i<63;++i) {
            c80_u8 *p=m->pool.data[1][i];memset(p,0,36);c80_put16(p+16,20);c80_put16(p+18,0xe000);
            p[20]=0xed;p[21]=0;p[28]=0xff;m->pool.rx[1][i].ctrl=C80_DONE|C80_LS0|(36u<<16);
        }
    }
    if(s==31 && m->rfault>=21 && m->rfault<=26) {
        unsigned count=m->rfault==22?63:1;
        for(unsigned i=0;i<count;++i) {
            c80_u8 *p=m->pool.data[0][i];memset(p,0,128);
            c80_put32(p,(2u<<29)|(15u<<25)|116);c80_put16(p+80,0x80);
            m->pool.rx[0][i].ctrl=C80_DONE|C80_LS0|(116u<<16);
            if(m->rfault==23) m->pool.rx[0][i].ctrl&=~C80_LS0;
            if(m->rfault==24) m->pool.rx[0][i].addr^=16;
            if(m->rfault==25) c80_put16(p,117);
            if(m->rfault==26) c80_put16(p,32);
        }
    }
}
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
static c80_u32 model_nvm_read(void *opaque,c80_u8 *out,c80_u32 bytes,c80_u32 *crc)
{
    struct model *m=opaque;
    assert(m->phase==2 && !m->writes && bytes==1024);
    if(m->fault==NVM_READ_FAIL) return C80_NVM_BAD_SOURCE;
    *crc=m->fault==NVM_RADIO_BAD?0:C80_RADIO_CRC;
    memcpy(out,synthetic_nvm,1024);
    if(m->fault==NVM_ID_BAD) out[0]^=1;
    if(m->fault==DEV_BAD_MAC_ZERO) memset(out+4,0,6);
    if(m->fault==DEV_BAD_MAC_FF) memset(out+4,255,6);
    if(m->fault==DEV_BAD_MAC_MULTICAST) out[4]|=1;
    return 0;
}
static c80_u32 model_irq_arm(void *opaque,struct c80_result *r)
{
    struct model *m=opaque; c80_u32 rc;
    assert(m->phase==20 && r->main_ready);
    rc=c80_irq_prepare(&m->io,r);
    if(rc) return rc;
    r->irq_cpu_started=1;
    return c80_irq_unmask(&m->io,r);
}
static c80_u32 model_irq_disarm(void *opaque,struct c80_result *r)
{
    struct model *m=opaque; c80_u32 rc=c80_irq_stop(&m->io,r);
    if(r->irq_cpu_started) r->irq_cpu_stopped=1;
    return rc;
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
    if(fault>=IRQ_GOOD) {
        m->io.irq_arm=model_irq_arm; m->io.irq_disarm=model_irq_disarm;
    }
    if(fault>=NVM_GOOD) m->io.nvm_read=model_nvm_read;
    if(fault>=DEV_GOOD) m->io.devinfo_test=1;
    if(fault==DEV_NO_NVM) m->io.nvm_read=0;
    if(fault>=BSS_GOOD) m->io.bss_test=1;
    if(fault==BSS_NO_DEVINFO) m->io.devinfo_test=0;
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
        assert(m->result.counter_query_attempted && m->result.counter_query_valid);
        assert(m->result.counter_category==5 && m->result.counter_count==1);
        assert(m->result.counter_value==(fault==QUERY_ZERO?0u:fault==QUERY_ALLONES?~0u:0x12345678u));
        assert(!(m->result.runtime_glo_after&C80_DOWNLOAD_MODE));
        assert(!m->result.mask_after && m->result.mask_zero_writes==2);
        assert(m->result.ready && m->result.get_valid && m->result.dma_idle && m->result.mcu_stopped);
        assert(!(*regptr(m,C80_GLO)&15));
        assert(m->result.tx_completed==m->result.tx_submitted);
        assert(m->result.main_ready && m->result.main_regions_complete==3);
        assert(m->result.main_region_valid==7 && m->result.main_start_valid && !m->result.main_start_status);
        assert(m->result.main_bytes==25616 && m->result.main_chunks==29);
        assert(m->result.main_region_bytes[0]==2896 && m->result.main_region_bytes[1]==1584 && m->result.main_region_bytes[2]==21136);
        assert(m->result.main_region_chunks[0]==4 && m->result.main_region_chunks[1]==2 && m->result.main_region_chunks[2]==23);
        assert(m->main_oracle==33);
        if(fault==SEM_ALREADY || fault==DEV_PATCH_READY || fault==BSS_PATCH_READY) {
            assert(m->result.tx_submitted==(fault==BSS_PATCH_READY?41u:fault==DEV_PATCH_READY?39u:35u) && !m->result.release_valid && !m->result.patch_uploaded);
            assert(m->result.command_submitted==(fault==BSS_PATCH_READY?12u:fault==DEV_PATCH_READY?10u:6u) && m->result.fwdl_completed==29 && m->result.sequence==(fault==BSS_PATCH_READY?11u:fault==DEV_PATCH_READY?9u:5u));
        } else {
            assert(m->result.tx_submitted==(fault>=BSS_GOOD?47u:fault>=DEV_GOOD?45u:fault>=NVM_GOOD?43u:41u) && m->result.release_valid && m->result.release_status==3);
            assert(m->result.command_submitted==(fault>=BSS_GOOD?16u:fault>=DEV_GOOD?14u:fault>=NVM_GOOD?12u:10u) && m->result.fwdl_completed==31 && m->result.sequence==(fault>=BSS_GOOD?2u:fault>=DEV_GOOD?15u:fault>=NVM_GOOD?13u:11u));
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
    if(fault>=QUERY_EXT_BAD && fault<=QUERY_CLOCK) {
        assert(m->result.main_ready && m->result.counter_query_attempted && !m->result.counter_query_valid);
        assert(!m->result.cleanup && m->result.dma_idle && m->result.mcu_stopped);
    }
    if(fault==RUNTIME_MODE_STUCK || fault==RUNTIME_GLO_FFFF)
        assert(m->result.main_ready && !m->result.counter_query_attempted && m->result.tx_submitted==40);
    if(fault==MASK_MAIN_CHANGES || fault==MASK_RESTORE_REFUSED)
        assert(m->result.mask_main_ready==0x20000000 && m->result.mask_cleanup_entry==0x20000000);
    if(fault==MASK_MAIN_CHANGES)
        assert(!m->result.mask_first_zero && !m->result.mask_after_stop && !m->result.mask_after);
    if(fault==MASK_RESET_CHANGES)
        assert(!m->result.mask_cleanup_entry && !m->result.mask_first_zero && m->result.mask_after_stop==0x20000000 && !m->result.mask_after);
    if(fault==MASK_CONTROL_CHANGES)
        assert(!m->result.mask_after_stop && m->result.mask_before_final_zero==0x20000000 && !m->result.mask_after);
    if(fault==MASK_RESTORE_REFUSED)
        assert(m->result.mask_after==0x20000000 && m->result.cleanup_flags==C80_CLEANUP_MASK);
    if(fault>=IRQ_GOOD && fault<NVM_GOOD) {
        assert(m->result.irq_attempted && !m->result.irq_armed);
        assert(m->result.dma_idle && m->result.mcu_stopped);
        if(fault==IRQ_GOOD) assert(m->result.irq_entries==1 && m->result.irq_events==1 && !m->result.irq_faults);
        if(fault==IRQ_DROP) assert(m->result.counter_query_valid && !m->result.irq_entries);
        if(fault==IRQ_PRE_FFFF || fault==IRQ_STALE || fault==IRQ_ENABLE_REFUSED)
            assert(!m->result.counter_query_attempted);
        if(m->result.irq_cpu_started) assert(m->result.irq_cpu_stopped);
    }
    if(fault>=NVM_GOOD && fault<DEV_GOOD) {
        assert(m->result.nvm_attempted);
        if(fault==NVM_READ_FAIL || fault==NVM_RADIO_BAD || fault==NVM_ID_BAD)
            assert(!m->writes && !m->result.nvm_valid && !m->result.mcu_released && !m->result.irq_attempted);
        else {
            assert(m->result.nvm_valid && m->result.dma_idle && m->result.mcu_stopped);
            assert(m->result.irq_events==1 && m->result.irq_cpu_stopped);
            if(expected==0) {
                assert(m->result.nvm_set_valid && !m->result.nvm_set_status && m->result.nvm_get_valid && m->result.nvm_equal);
                assert(m->result.nvm_get_crc==m->result.nvm_upload_crc && m->result.nvm_get_count==1024);
                assert(m->result.nvm_compared==1024);
                assert(m->result.nvm_get_padding==(fault>=NVM_GET_PAD2?2u:0u));
                assert(memcmp(m->pool.nvm_payload+4,synthetic_nvm,960)==0);
                for(i=960;i<1024;++i) assert(!m->pool.nvm_payload[4+i]);
            }
            if(fault==NVM_GET_DATA) assert(m->result.nvm_mismatch_valid && m->result.nvm_mismatch_offset==959);
            if(fault>=NVM_SET_REJECT && fault<=NVM_SET_RX) assert(!m->result.nvm_get_attempted);
        }
        assert(m->result.nvm_set_polls<=60000 && m->result.nvm_get_polls<=60000);
        if(fault==NVM_SET_DELAY_2100 || fault==NVM_SET_SLOW_REJECT)
            assert(m->result.nvm_set_wait_us==2100000 && m->result.nvm_set_polls==2101);
        if(fault==NVM_GET_DELAY_2100 || fault==NVM_GET_SLOW_MISMATCH)
            assert(m->result.nvm_get_wait_us==2100000 && m->result.nvm_get_polls==2101);
        if(fault==NVM_SET_DELAY_59999)
            assert(m->result.nvm_set_wait_us==59999000 && m->result.nvm_set_polls==60000);
        if(fault==NVM_GET_DELAY_59999)
            assert(m->result.nvm_get_wait_us==59999000 && m->result.nvm_get_polls==60000);
        if(fault==NVM_SET_AT_DEADLINE || fault==NVM_SET_AFTER_DEADLINE || fault==NVM_SET_RX) {
            assert(m->result.nvm_set_wait_us==60000000 && m->result.nvm_set_polls==60000);
            assert(!m->result.nvm_get_attempted && m->tx_seen==11 && m->result.rx_packets==10);
        }
        if(fault==NVM_GET_AT_DEADLINE || fault==NVM_GET_AFTER_DEADLINE || fault==NVM_GET_RX)
            assert(m->result.nvm_get_wait_us==60000000 && m->result.nvm_get_polls==60000);
        if(fault==NVM_SET_CLOCK_FROZEN)
            assert(!m->result.nvm_set_wait_us && m->result.nvm_set_polls==60000 && !m->result.nvm_get_attempted);
        if(fault==NVM_GET_CLOCK_FROZEN)
            assert(!m->result.nvm_get_wait_us && m->result.nvm_get_polls==60000);
        if(fault==NVM_SET_CLOCK_BACKWARDS)
            assert(m->result.nvm_wait_clock_backwards==1 && m->result.nvm_set_polls==1 && !m->result.nvm_get_attempted);
        if(fault==NVM_GET_CLOCK_BACKWARDS)
            assert(m->result.nvm_wait_clock_backwards==2 && m->result.nvm_get_polls==1);
        if(fault==NVM_BOTH_DELAY)
            assert(m->result.nvm_set_wait_us==3000000 && m->result.nvm_get_wait_us==4000000);
        if(fault==NVM_GET_SLOW_MISMATCH)
            assert(m->result.nvm_mismatch_valid && m->result.nvm_mismatch_offset==959);
        if(fault==NVM_SET_POLL_OVERSLEEP) {
            assert(m->result.nvm_set_wait_us>=60000000 && m->result.nvm_set_wait_us<60021000);
            assert(m->result.nvm_set_polls<3000 && !m->result.nvm_get_attempted);
        }
        if(fault>=NVM_GET_PAD2 && expected==0)
            assert(m->result.last_event_len==1044 && m->result.nvm_get_padding==2 && m->result.nvm_compared==1024);
        if(fault==NVM_GET_PAD1 || fault==NVM_GET_PAD3 || fault==NVM_GET_PAD4)
            assert(!m->result.nvm_get_valid && !m->result.nvm_compared && !m->result.nvm_equal);
        if(fault==NVM_GET_PAD2_DATA_FIRST)
            assert(m->result.nvm_mismatch_valid && !m->result.nvm_mismatch_offset && m->result.nvm_compared==1 && !m->result.nvm_equal);
        if(fault==NVM_GET_PAD2_DATA_LAST)
            assert(m->result.nvm_mismatch_valid && m->result.nvm_mismatch_offset==1023 && m->result.nvm_compared==1024 && !m->result.nvm_equal);
    }
    if(fault>=DEV_GOOD && fault<BSS_GOOD) {
        if(expected==31) {
            assert(!m->writes && !m->result.devinfo_mac_valid && !m->result.mcu_released);
        } else {
            assert(m->result.devinfo_mac_valid);
            assert(m->result.devinfo_polls[0]<=6000 && m->result.devinfo_polls[1]<=6000);
            if(fault>=VAR_ON40 && expected==0) {
                for(unsigned k=0;k<2;++k) {
                    unsigned extended=!(k==0 && fault==VAR_OFF40) && !(k==1 && fault==VAR_ON40);
                    unsigned n=!extended?28:fault==VAR_ODD29?29:fault==VAR_MAX?1520:40;
                    assert(m->result.devinfo_event_bytes[k]==n && m->result.devinfo_dma_bytes[k]==n+16);
                    assert(m->result.devinfo_tail_bytes[k]==n-28 && m->result.devinfo_base_read[k] && m->result.devinfo_echo[k]==0x2a);
                }
            }
            if(fault==VAR_TRUNCATED || fault==VAR_OVERDECLARED)
                assert(!m->result.devinfo_base_read[0] && !m->result.devinfo_valid[0] && !m->result.devinfo_attempted[1]);
            if(fault==VAR_HIGH) assert(m->result.devinfo_status[0]==0x80000000u);
            if(fault==DEV_DELAY_3000) assert(m->result.devinfo_wait_us[0]==3000000 && m->result.devinfo_polls[0]==3001);
            if(fault==DEV_DELAY_5999) assert(m->result.devinfo_wait_us[0]==5999000 && m->result.devinfo_polls[0]==6000);
            if(fault==DEV_AT_DEADLINE) assert(m->result.devinfo_wait_us[0]==6000000 && m->result.devinfo_polls[0]==6000);
            if(fault==DEV_CLOCK_FROZEN) assert(!m->result.devinfo_wait_us[0] && m->result.devinfo_polls[0]==6000);
            if(fault==DEV_BACKWARDS) assert(!m->result.devinfo_wait_us[0] && m->result.devinfo_polls[0]==1);
            if(expected!=80 && expected!=81) {
                assert(m->result.dma_idle && m->result.mcu_stopped && !m->result.cleanup);
                assert(!m->result.mask_after && !m->result.rings_restore_bad && !m->result.controls_owned_bad);
            }
            if(fault==DEV_NVM_MISMATCH || fault==DEV_CPU_IRQ_DROP) {
                assert(!m->result.devinfo_attempted[0] && !m->result.devinfo_attempted[1]);
            } else {
                assert(m->result.nvm_equal && m->result.devinfo_attempted[0]);
                if(m->result.devinfo_attempted[1])
                    assert(m->result.devinfo_valid[0] && !m->result.devinfo_status[0]);
                else assert(m->tx_seen==13);
                if(expected==0) assert(m->result.devinfo_complete && m->result.devinfo_valid[1] && !m->result.devinfo_status[1]);
                else if(expected!=80 && expected!=81) assert(!m->result.devinfo_complete);
                if(expected==32) {
                    unsigned k=m->result.devinfo_attempted[1]?1:0;
                    assert(m->result.devinfo_valid[k] && m->result.devinfo_status[k]);
                    if(fault==DEV_ON_REJECT_HIGH || fault==DEV_OFF_REJECT_HIGH)
                        assert(m->result.devinfo_status[k]==0x80000000u);
                }
            }
        }
    }
    if(fault>=BSS_GOOD) {
        if(fault==BSS_NO_DEVINFO) assert(!m->writes && !m->result.mcu_released && !m->result.bss_attempted[0]);
        else {
            assert(m->result.bss_polls[0]<=6000 && m->result.bss_polls[1]<=6000);
            if(fault==BSS_DEV_ON_FAIL || fault==BSS_NVM_FAIL) assert(!m->result.bss_attempted[0] && !m->result.devinfo_attempted[1]);
            else {
                assert(m->result.bss_attempted[0]);
                if(m->result.bss_attempted[1]) assert(m->result.bss_valid[0] && !m->result.bss_status[0]);
                if(m->result.devinfo_attempted[1]) assert(m->result.bss_complete && m->result.bss_valid[1] && !m->result.bss_status[1]);
                else assert(!m->result.devinfo_complete && !m->result.bss_complete);
                if(expected==0) {
                    assert(m->result.bss_complete && m->result.devinfo_complete && m->result.bss_count[0]==2 && m->result.bss_count[1]==1);
                    assert(m->result.rx_packets==(fault==BSS_PATCH_READY?12u:16u));
                }
                if(expected==35) {
                    unsigned k=m->result.bss_attempted[1]?1:0;
                    assert(m->result.bss_valid[k] && m->result.bss_status[k]);
                    if(fault==BSS_HIGH_REJECT || fault==BSS_OFF_HIGH_REJECT) assert(m->result.bss_status[k]==0x80000000u);
                }
                if(fault==BSS_DEV_OFF_FAIL) assert(m->result.bss_complete && !m->result.devinfo_complete);
                if(fault==BSS_DELAY_5999) assert(m->result.bss_wait_us[0]==5999000 && m->result.bss_polls[0]==6000);
                if(fault==BSS_FROZEN) assert(!m->result.bss_wait_us[0] && m->result.bss_polls[0]==6000);
                if(fault==BSS_BACKWARDS) assert(!m->result.bss_wait_us[0] && m->result.bss_polls[0]==1);
            }
            if(expected!=80 && expected!=81) assert(m->result.dma_idle && m->result.mcu_stopped && !m->result.cleanup && !m->result.mask_after);
        }
    }
    printf("PASS %s rc=%u tx=%u rx=%u critical=%u\n",name,rc,
           m->result.tx_completed,m->result.rx_packets,m->result.critical);
    free(m);
}
static void test_radio(unsigned f,unsigned which,c80_u32 expected)
{
    struct model *m=calloc(1,sizeof(*m));c80_u32 i,j,rc;
    assert(m);m->us=100;m->fault=BSS_GOOD;m->rfault=f;m->rstep=which;
    for(i=0;i<10;++i) *regptr(m,c80_aon_regs[i])=(c80_u32[]){0,0xe0800022,0,0xffffff20,0x11040,1,0x269f0000,0x0700b644,0x0700b644,0x9000}[i];
    *regptr(m,c80_controls[0])=0x40100000;*regptr(m,c80_controls[1])=0xf0000000;
    *regptr(m,0x180b1010)=0x10040101;*regptr(m,0x18002000)=*regptr(m,0x18002004)=0x8a00;
    *regptr(m,C80_OWN)=0x30001;*regptr(m,C80_GLO)=0x10001870;*regptr(m,C80_SYNC)=2;
    m->io=(struct c80_io){.context=m,.read=read_reg,.write=write_reg,.time_us=model_time,
        .delay_us=delay,.dma_order=barrier,.copy_emi=copy_emi,.crc_emi=crc_emi,.stage=stage,
        .pool=&m->pool,.dma_base=0x41000000,.irq_arm=model_irq_arm,.irq_disarm=model_irq_disarm,
        .nvm_read=model_nvm_read,.devinfo_test=1,.bss_test=1,.radio_test=1};
    if(f==16) m->fault=BSS_RESET_STUCK;
    if(f==17) m->fault=BSS_DMA_BUSY;
    if(f==18) m->fault=BSS_DEV_ON_FAIL;
    if(f==19) m->fault=BSS_NVM_FAIL;
    if(f==20) m->io.bss_test=0;
    if(f==30) m->fault=BSS_PATCH_READY;
    rc=c80_run(&m->io,firmware,&m->result);
    if(rc!=expected) fprintf(stderr,"radio f%u step%u got%u want%u phase%u\n",f,which,rc,expected,m->phase);
    assert(rc==expected);
    if(f==20) assert(!m->writes && !m->tx_seen);
    else if(f!=16 && f!=17) {
        assert(m->result.dma_idle && m->result.mcu_stopped && !m->result.cleanup && !m->result.mask_after);
        for(i=0;i<4;++i) for(j=0;j<3;++j) assert(*regptr(m,c80_ring_regs[i]+j*4)==0);
    }
    if(expected==0) {
        assert(m->result.radio_complete && m->result.bss_complete && m->result.devinfo_complete);
        assert(m->result.radio_listen_started && (m->result.radio_listen_us==500000 || f==22));
        assert(m->result.command_submitted==(f==30?17u:21u));
        assert(m->result.tx_submitted==(f==30?46u:52u) && m->result.tx_completed==m->result.tx_submitted);
        assert(m->result.sequence==(f==30?1u:7u));
        for(i=0;i<5;++i) assert(m->result.radio_valid[i] && !m->result.radio_status[i]);
        if(f==12) assert(m->result.radio_wait_us[which]==(which==1?4999000u:5999000u));
        if(f==21 || f==22) assert(m->result.radio_rx_packets==(f==22?63u:1u) && m->result.radio_beacon_headers==m->result.radio_rx_packets);
        if(f==22) assert(m->result.radio_rx_full && m->result.rx_next[0]==63);
    } else {
        if(f!=16 && f!=17) assert(!m->result.devinfo_complete);
        if(f<=15) {
            assert(m->result.radio_attempted[which] && !m->result.bss_attempted[1]);
            for(i=which+1;i<5;++i) assert(!m->result.radio_attempted[i]);
        }
        if(f==1 || f==2) assert(m->result.radio_valid[which] && m->result.radio_status[which]==(f==1?1u:0x80000000u));
        if(f==16 || f==17) assert(m->result.critical && m->result.radio_complete);
        if(f>=23 && f<=26) assert(m->result.radio_rx_bad && !m->result.radio_attempted[4]);
    }
    printf("PASS radio-fault%u-step%u rc=%u tx=%u rx=%u\n",f,which,rc,m->result.tx_completed,m->result.rx_packets);free(m);
}
static void test_beacon(unsigned f,unsigned which,c80_u32 expected)
{
    struct model *m=calloc(1,sizeof(*m));c80_u32 i,j,rc;
    assert(m);m->us=100;m->fault=BSS_GOOD;m->bfault=f;m->bstep=which;
    for(i=0;i<10;++i) *regptr(m,c80_aon_regs[i])=(c80_u32[]){0,0xe0800022,0,0xffffff20,0x11040,1,0x269f0000,0x0700b644,0x0700b644,0x9000}[i];
    *regptr(m,c80_controls[0])=0x40100000;*regptr(m,c80_controls[1])=0xf0000000;
    *regptr(m,0x180b1010)=0x10040101;*regptr(m,0x18002000)=*regptr(m,0x18002004)=0x8a00;
    *regptr(m,C80_OWN)=0x30001;*regptr(m,C80_GLO)=0x10001870;*regptr(m,C80_SYNC)=2;
    m->io=(struct c80_io){.context=m,.read=read_reg,.write=write_reg,.time_us=model_time,
        .delay_us=delay,.dma_order=barrier,.copy_emi=copy_emi,.crc_emi=crc_emi,.stage=stage,
        .pool=&m->pool,.dma_base=0x41000000,.irq_arm=model_irq_arm,.irq_disarm=model_irq_disarm,
        .nvm_read=model_nvm_read,.devinfo_test=1,.bss_test=1,.radio_test=1,.beacon_test=1};
    if(f==21) m->io.radio_test=0;
    if(f==22) { m->rfault=1;m->rstep=3; }
    if(f==23) m->fault=BSS_REJECT;
    if(f==24) m->fault=BSS_NVM_FAIL;
    if(f==25) m->fault=BSS_RESET_STUCK;
    if(f==26) m->fault=BSS_DMA_BUSY;
    if(f==37) m->fault=BSS_PATCH_READY;
    rc=c80_run(&m->io,firmware,&m->result);
    if(rc!=expected) fprintf(stderr,"beacon f%u step%u got%u want%u phase%u\n",f,which,rc,expected,m->phase);
    assert(rc==expected);
    if(f==21) assert(!m->writes && !m->tx_seen);
    else if(f!=25 && f!=26) {
        assert(m->result.dma_idle && m->result.mcu_stopped && !m->result.cleanup && !m->result.mask_after);
        for(i=0;i<4;++i) for(j=0;j<3;++j) assert(*regptr(m,c80_ring_regs[i]+j*4)==0);
    }
    if(expected==0) {
        assert(m->result.beacon_complete && m->result.radio_complete && m->result.bss_complete && m->result.devinfo_complete);
        assert(m->result.beacon_window_started && m->result.beacon_window_us==30000000 && m->result.beacon_window_polls==30000);
        assert(!m->result.radio_listen_started);
        assert(m->result.command_submitted==(f==37?21u:25u));
        assert(m->result.tx_submitted==(f==37?50u:56u) && m->result.tx_completed==m->result.tx_submitted);
        assert(m->result.sequence==(f==37?5u:11u));
        for(i=0;i<4;++i) assert(m->result.beacon_valid[i] && !m->result.beacon_status[i]);
        if(f==14) assert(m->result.beacon_wait_us[which]==5999000);
        if(f==33) assert(m->result.radio_rx_full && m->result.rx_next[0]==63 && m->result.radio_beacon_headers==63);
    } else if(f!=25 && f!=26) {
        assert(!m->result.devinfo_complete && !m->result.radio_complete);
        if(f>=4 && f<=20) {
            assert(m->result.beacon_attempted[which] && !m->result.bss_attempted[1] && !m->result.radio_attempted[4]);
            for(i=which+1;i<4;++i) assert(!m->result.beacon_attempted[i]);
        }
        if(f==4 || f==5 || f==20) assert(m->result.beacon_valid[which] && m->result.beacon_status[which]==(f==5?0x80000000u:1u));
        if(f>=30 && f<=34) assert(m->result.beacon_window_started && !m->result.beacon_attempted[2]);
    }
    if(f==25 || f==26) assert(m->result.critical && m->result.beacon_complete && m->result.radio_complete);
    printf("PASS beacon-fault%u-step%u rc=%u tx=%u rx=%u\n",f,which,rc,m->result.tx_completed,m->result.rx_packets);free(m);
}
static void test_watch(unsigned f,unsigned window,c80_u64 at,c80_u32 expected)
{
    struct model *m=calloc(1,sizeof(*m));c80_u32 i,j,rc;
    assert(m);m->us=100;m->fault=BSS_GOOD;m->wfault=f;m->wwindow=window;m->watch_delay=at;
    for(i=0;i<10;++i) *regptr(m,c80_aon_regs[i])=(c80_u32[]){0,0xe0800022,0,0xffffff20,0x11040,1,0x269f0000,0x0700b644,0x0700b644,0x9000}[i];
    *regptr(m,c80_controls[0])=0x40100000;*regptr(m,c80_controls[1])=0xf0000000;
    *regptr(m,0x180b1010)=0x10040101;*regptr(m,0x18002000)=*regptr(m,0x18002004)=0x8a00;
    *regptr(m,C80_OWN)=0x30001;*regptr(m,C80_GLO)=0x10001870;*regptr(m,C80_SYNC)=2;
    m->io=(struct c80_io){.context=m,.read=read_reg,.write=write_reg,.time_us=model_time,
        .delay_us=delay,.dma_order=barrier,.copy_emi=copy_emi,.crc_emi=crc_emi,.stage=stage,
        .pool=&m->pool,.dma_base=0x41000000,.irq_arm=model_irq_arm,.irq_disarm=model_irq_disarm,
        .nvm_read=model_nvm_read,.devinfo_test=1,.bss_test=1,.radio_test=1,.beacon_test=1,.watch_test=1};
    if(f==16) m->io.beacon_test=0;
    if(f==17) m->fault=BSS_RESET_STUCK;
    if(f==18) m->fault=BSS_DMA_BUSY;
    rc=c80_run(&m->io,firmware,&m->result);
    if(rc!=expected) fprintf(stderr,"watch f%u window%u got%u want%u phase%u\n",f,window,rc,expected,m->phase);
    assert(rc==expected);
    if(f==16) assert(!m->writes && !m->tx_seen);
    else if(f!=17 && f!=18) {
        assert(m->result.dma_idle && m->result.mcu_stopped && !m->result.cleanup && !m->result.mask_after);
        for(i=0;i<4;++i) for(j=0;j<3;++j) assert(*regptr(m,c80_ring_regs[i]+j*4)==0);
    }
    if(!expected || f==17 || f==18) {
        assert(m->result.beacon_complete && m->result.radio_complete && m->result.bss_complete && m->result.devinfo_complete);
        assert(m->result.tx_submitted==56 && m->result.tx_completed==56 && m->result.command_submitted==25);
        for(i=0;i<2;++i) {
            const struct c80_watch_window *w=&m->result.watch[i];
            assert(w->complete && !w->fault_bits && w->elapsed_us>=30000000 && w->elapsed_us<=30101000 && w->samples<=30001);
            if(f!=14 || i!=window) assert(w->elapsed_us==30000000 && w->samples==30001);
        }
        if(f==15) assert(m->result.radio_rx_full && m->result.rx_next[0]==63 && m->result.radio_rx_packets==63);
        if(f==10) assert(m->result.watch[window].last.glo&10);
        if(f==11) assert(m->result.watch[window].last.source==0x80083);
    } else if(expected==44 || expected==5) {
        const struct c80_watch_window *w=&m->result.watch[window];
        assert(w->started && !w->complete && !m->result.beacon_complete && !m->result.beacon_attempted[2] && !m->result.radio_attempted[4]);
        if(!window) assert(!m->result.beacon_attempted[0] && !m->result.beacon_attempted[1] && !m->result.watch[1].started);
        else assert(m->result.watch[0].complete && m->result.beacon_valid[1]);
        if(expected==44) {
            static const unsigned bits[]={0,1,2,3,36,8,12,16,20,32};
            assert(w->fault_bits==bits[f] && w->elapsed_us==at);
            if(at) assert(w->last_good_us==at-1000);
            assert(m->result.watch_fault_phase==(window?37u:38u));
            assert(m->result.failure_snapshot && m->result.failure_phase==m->result.watch_fault_phase);
            assert(m->result.failure_desc[1]&C80_DONE); /* no new packet published after loss */
            assert(m->result.failure_cpu==m->result.command_submitted && m->result.failure_dma==m->result.command_completed);
            if(f==3) assert(m->result.failure_glo==0x10001c70); /* RAM16 observed state */
        } else assert(!w->fault_bits && !m->result.watch_fault_phase && w->samples<=30001);
    }
    printf("PASS watch-fault%u-window%u-at%llu rc=%u tx=%u rx=%u\n",f,window,(unsigned long long)at,rc,m->result.tx_completed,m->result.rx_packets);free(m);
}
static void test_radio_rx(void)
{
    /* All OEM offset combinations plus header translation, short payload,
     * nonbeacon/control/version,oversize,addr1,type metadata and saturation. */
    for(unsigned test=0;test<43;++test) {
        struct model *m=calloc(1,sizeof(*m));unsigned group=test<32?test/2:0,pad=test<32?test%2:0;
        unsigned off=16+16*!!(group&8)+16*!!(group&1)+8*!!(group&2)+24*!!(group&4)+2*pad;
        c80_u8 *p=m->pool.data[0][0];c80_u32 rc,wanted=0;
        m->io=(struct c80_io){.context=m,.dma_order=barrier,.pool=&m->pool,.dma_base=0x41000000};
        c80_put32(p,(2u<<29)|(group<<25)|(off+36));p[6]=pad<<6;c80_put16(p+off,0x80);
        m->pool.rx[0][0].addr=c80_dma_address(&m->io,p);m->pool.rx[0][0].ctrl=C80_DONE|C80_LS0|((off+36)<<16);
        if(test==32) p[6]|=0x80;
        if(test==33) c80_put16(p+off,0x40);
        if(test==34) c80_put16(p+off,0x81);
        if(test==35) c80_put16(p,off+35);
        if(test==36) { m->pool.rx[0][0].ctrl=C80_DONE|C80_LS0|(1537u<<16);wanted=40; }
        if(test==37) { m->pool.rx[0][0].addr1=16;wanted=40; }
        if(test==38) { m->pool.rx[0][0].ctrl=C80_DONE|C80_LS0|(15u<<16);wanted=40; }
        if(test==39) { c80_put16(p,15);wanted=40; }
        if(test==40) p[3]=7u<<5;
        if(test==41) m->pool.rx[0][0].ctrl=52u<<16;
        if(test==42) m->result.rx_next[0]=63;
        rc=c80_radio_receive(&m->io,&m->result);assert(rc==wanted);
        if(test<32) assert(m->result.radio_beacon_headers==1 && m->result.radio_raw_frames==1);
        if(test>=32) assert(!m->result.radio_beacon_headers);
        if(test==32) assert(m->result.radio_rx_translated==1);
        if(test==40) assert(m->result.radio_rx_types[7]==1);
        if(test==42) assert(m->result.radio_rx_full && !m->result.radio_rx_packets);
        printf("PASS radio-RX-metadata%u rc=%u\n",test,rc);free(m);
    }
}
struct irq_unit {
    struct c80_io io; struct c80_result r;
    unsigned mode,step,acks,writes; c80_u32 source,mask;
};
static c80_u32 irq_unit_read(void *opaque,c80_u32 address)
{
    struct irq_unit *u=opaque;
    assert(address==C80_MASK || address==C80_SOURCE);
    if(address==C80_MASK && ((u->mode==2 && !u->step) ||
                            (u->mode==17 && u->step==1))) return ~0u;
    if(address==C80_SOURCE && (u->mode==3 ||
                              (u->mode==16 && !u->step && u->acks))) return ~0u;
    return address==C80_MASK?u->mask:u->source;
}
static void irq_unit_write(void *opaque,c80_u32 address,c80_u32 value)
{
    struct irq_unit *u=opaque;
    ++u->writes; assert(u->writes<16);
    assert(address==C80_MASK || address==C80_SOURCE);
    if(address==C80_SOURCE) {
        assert(value==C80_IRQ_RX1); ++u->acks;
        if(u->mode!=5 && !(u->mode==14 && u->step==2)) u->source&=~value;
    } else {
        assert(value==0 || value==C80_IRQ_RX1);
        if((u->mode==4 && !value) || (u->mode==6 && value) ||
           (u->mode==15 && u->step==3)) return;
        u->mask=value;
    }
}
static void test_irq_gate(void)
{
    unsigned mode;
    for(mode=0;mode<18;++mode) {
        struct irq_unit u={.mode=mode,.source=0x80082,.mask=0x20000000};
        c80_u32 rc,stop,expected;
        u.io=(struct c80_io){.context=&u,.read=irq_unit_read,.write=irq_unit_write};
        if(mode==1) { u.mask=0; u.source=0; }
        rc=c80_irq_prepare(&u.io,&u.r);
        if(!rc) {
            if(mode==12) { u.source|=2; c80_irq_event(&u.io,&u.r); }
            u.step=1; rc=c80_irq_unmask(&u.io,&u.r);
        }
        if(!rc && mode!=7) {
            u.step=2;
            u.source=mode==8?0:mode==9?~0u:mode==10?1:0x80082;
            if(mode==13) c80_irq_stop(&u.io,&u.r);
            c80_irq_event(&u.io,&u.r);
            if(mode==11) c80_irq_event(&u.io,&u.r);
        }
        u.step=3;
        if(mode==15) u.mask=2;
        stop=c80_irq_stop(&u.io,&u.r);
        if(!rc) rc=stop;
        expected=mode==0 || mode==1 || mode==14?0:mode==7?25:26;
        if(rc!=expected) fprintf(stderr,"IRQ gate mode%u got%u expected%u faults%x\n",mode,rc,expected,u.r.irq_faults);
        assert(rc==expected && !u.r.irq_armed);
        assert(!u.mask || mode==15 || mode==4);
        if(!rc) assert(u.r.irq_entries==1 && u.r.irq_events==1 && !u.r.irq_unexpected && !u.r.irq_faults);
        if(mode==14) assert(u.r.irq_source_after&2); /* new masked RX is allowed */
        if(mode==7) assert(!u.r.irq_entries && !u.r.irq_events && !u.r.irq_faults);
        if(mode==9) assert(u.acks==1); /* all-ones source never acknowledged */
        if(mode==0) assert(u.source==0x80080 && u.acks==2);
        printf("PASS IRQ gate case%u expected_rc=%u MMIO_writes=%u\n",mode,expected,u.writes);
    }
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
    test("runtime-query-wrong-extension-ignored",QUERY_EXT_BAD,13);
    test("runtime-query-wrong-sequence-ignored",QUERY_SEQ_BAD,13);
    test("runtime-query-wrong-packet-ID-ignored",QUERY_PKT_BAD,13);
    test("runtime-query-wrong-event-ignored",QUERY_ID_BAD,13);
    test("runtime-query-wrong-category-refused",QUERY_CATEGORY_BAD,24);
    test("runtime-query-unrequested-count-refused",QUERY_COUNT_BAD,24);
    test("runtime-query-short-payload-refused",QUERY_SHORT,24);
    test("runtime-query-extra-byte-refused",QUERY_LONG,24);
    test("runtime-query-response-timeout",QUERY_RX_LOST,13);
    test("runtime-query-TX-timeout",QUERY_TX_LOST,12);
    test("runtime-query-stalled-clock-bounded",QUERY_CLOCK,13);
    test("runtime-mode-off-readback-refused-no-query",RUNTIME_MODE_STUCK,23);
    test("runtime-GLO-allones-no-query",RUNTIME_GLO_FFFF,23);
    test("mask-changed-at-main-ready-recorded-and-restored",MASK_MAIN_CHANGES,0);
    test("mask-changed-on-MCU-stop-recorded-and-restored",MASK_RESET_CHANGES,0);
    test("mask-clear-write-refused-still-cleanup-failure",MASK_RESTORE_REFUSED,16);
    test("runtime-counter-zero-is-valid",QUERY_ZERO,0);
    test("runtime-counter-allones-is-valid",QUERY_ALLONES,0);
    test("mask-changed-during-control-restore-cleared-last",MASK_CONTROL_CHANGES,0);
    test("IRQ-RX1-real-core-query-and-mask-stop",IRQ_GOOD,0);
    test("IRQ-missing-even-with-valid-DMA-reply-is-failure",IRQ_DROP,25);
    test("IRQ-entry-does-not-excuse-invalid-reply",IRQ_BAD_CATEGORY,24);
    test("IRQ-mask-allones-precheck-no-query",IRQ_PRE_FFFF,26);
    test("IRQ-stale-source-clear-refused-no-query",IRQ_STALE,26);
    test("IRQ-enable-readback-refused-no-query",IRQ_ENABLE_REFUSED,26);
    test("IRQ-unexpected-source-one-shot-failure",IRQ_UNEXPECTED,26);
    test("NVM-snapshot-SET-GET-equality",NVM_GOOD,0);
    test("NVM-read-failure-before-peripheral-writes",NVM_READ_FAIL,27);
    test("NVM-RADIO-CRC-before-peripheral-writes",NVM_RADIO_BAD,27);
    test("NVM-ID-before-peripheral-writes",NVM_ID_BAD,27);
    test("NVM-SET-firmware-rejection-no-GET",NVM_SET_REJECT,28);
    test("NVM-SET-echo-mismatch",NVM_SET_ECHO,29);
    test("NVM-SET-unrelated-extension-ignored",NVM_SET_EXT,13);
    test("NVM-SET-short-reply",NVM_SET_SHORT,29);
    test("NVM-SET-TX-timeout-no-GET",NVM_SET_TX,12);
    test("NVM-SET-RX-timeout-no-GET",NVM_SET_RX,13);
    test("NVM-GET-wrong-source",NVM_GET_SOURCE,29);
    test("NVM-GET-wrong-format",NVM_GET_FORMAT,29);
    test("NVM-GET-wrong-offset",NVM_GET_OFFSET,29);
    test("NVM-GET-wrong-count",NVM_GET_COUNT,29);
    test("NVM-GET-short-content",NVM_GET_LENGTH,29);
    test("NVM-GET-unrelated-extension-ignored",NVM_GET_EXT,13);
    test("NVM-GET-wrong-sequence",NVM_GET_SEQ,13);
    test("NVM-GET-wrong-packet-ID",NVM_GET_PKT,13);
    test("NVM-GET-byte-mismatch",NVM_GET_DATA,30);
    test("NVM-GET-TX-timeout",NVM_GET_TX,12);
    test("NVM-GET-RX-timeout",NVM_GET_RX,13);
    test("NVM-GET-9b-command-echo-variant",NVM_GET_9B,0);
    test("NVM-SET-delayed-2.1s-accepted-after-old-RAM9-deadline",NVM_SET_DELAY_2100,0);
    test("NVM-SET-delayed-59.999s-accepted",NVM_SET_DELAY_59999,0);
    test("NVM-SET-at-60s-deadline-refused-no-GET",NVM_SET_AT_DEADLINE,13);
    test("NVM-SET-after-60s-deadline-refused-no-GET",NVM_SET_AFTER_DEADLINE,13);
    test("NVM-SET-frozen-clock-bounded-by-polls",NVM_SET_CLOCK_FROZEN,13);
    test("NVM-SET-backwards-clock-bounded-and-reported",NVM_SET_CLOCK_BACKWARDS,13);
    test("NVM-GET-delayed-2.1s-accepted-after-old-RAM9-deadline",NVM_GET_DELAY_2100,0);
    test("NVM-GET-delayed-59.999s-accepted",NVM_GET_DELAY_59999,0);
    test("NVM-GET-at-60s-deadline-refused",NVM_GET_AT_DEADLINE,13);
    test("NVM-GET-after-60s-deadline-refused",NVM_GET_AFTER_DEADLINE,13);
    test("NVM-GET-frozen-clock-bounded-by-polls",NVM_GET_CLOCK_FROZEN,13);
    test("NVM-GET-backwards-clock-bounded-and-reported",NVM_GET_CLOCK_BACKWARDS,13);
    test("NVM-SET-3s-and-GET-4s-have-independent-deadlines",NVM_BOTH_DELAY,0);
    test("NVM-SET-late-firmware-rejection-still-fails",NVM_SET_SLOW_REJECT,28);
    test("NVM-GET-late-content-mismatch-still-fails",NVM_GET_SLOW_MISMATCH,30);
    test("NVM-scheduling-oversleep-obeys-clock-deadline",NVM_SET_POLL_OVERSLEEP,13);
    test("NVM-GET-observed1044-event-two-padding-bytes",NVM_GET_PAD2,0);
    test("NVM-GET-padding-not-part-of-calibration-even-if-nonzero",NVM_GET_PAD2_NONZERO,0);
    test("NVM-GET-one-extra-byte-is-not-valid-alignment",NVM_GET_PAD1,29);
    test("NVM-GET-three-extra-bytes-refused",NVM_GET_PAD3,29);
    test("NVM-GET-four-extra-bytes-refused",NVM_GET_PAD4,29);
    test("NVM-GET-padding-must-fit-declared-DMA-length",NVM_GET_PAD2_SHORT_DMA,14);
    test("NVM-GET-padded-count-still-exact1024",NVM_GET_PAD2_BAD_COUNT,29);
    test("NVM-GET-padded-wrong-source-refused",NVM_GET_PAD2_BAD_SOURCE,29);
    test("NVM-GET-padded-wrong-format-refused",NVM_GET_PAD2_BAD_FORMAT,29);
    test("NVM-GET-padded-wrong-offset-refused",NVM_GET_PAD2_BAD_OFFSET,29);
    test("NVM-GET-padded-wrong-sequence-ignored",NVM_GET_PAD2_BAD_SEQ,13);
    test("NVM-GET-padded-wrong-packetID-ignored",NVM_GET_PAD2_BAD_PKT,13);
    test("NVM-GET-padded-unrelated-extension-ignored",NVM_GET_PAD2_BAD_EXT,13);
    test("NVM-GET-padded-first-data-byte-is-compared",NVM_GET_PAD2_DATA_FIRST,30);
    test("NVM-GET-padded-last-data-byte-is-compared",NVM_GET_PAD2_DATA_LAST,30);
    test("NVM-GET-padded9b-command-echo-variant",NVM_GET_PAD2_9B,0);
    test("dev-good",DEV_GOOD,0);
    test("dev-specific-ext",DEV_SPECIFIC_EXT,0);
    test("dev-reserved",DEV_RESERVED,0);
    test("dev-bad-mac-zero",DEV_BAD_MAC_ZERO,31);
    test("dev-bad-mac-multicast",DEV_BAD_MAC_MULTICAST,31);
    test("dev-bad-mac-ff",DEV_BAD_MAC_FF,31);
    test("dev-no-nvm",DEV_NO_NVM,31);
    test("dev-on-reject",DEV_ON_REJECT,32);
    test("dev-on-reject-high",DEV_ON_REJECT_HIGH,32);
    test("dev-off-reject",DEV_OFF_REJECT,32);
    test("dev-off-reject-high",DEV_OFF_REJECT_HIGH,32);
    test("dev-on-echo",DEV_ON_ECHO,33);
    test("dev-off-echo",DEV_OFF_ECHO,33);
    test("dev-on-count",DEV_ON_COUNT,33);
    test("dev-off-count",DEV_OFF_COUNT,33);
    test("dev-on-own",DEV_ON_OWN,33);
    test("dev-off-own",DEV_OFF_OWN,33);
    test("dev-on-len",DEV_ON_LEN,33);
    test("dev-off-len",DEV_OFF_LEN,33);
    test("dev-on-short-dma",DEV_ON_SHORT_DMA,14);
    test("dev-on-seq",DEV_ON_SEQ,13);
    test("dev-on-pkt",DEV_ON_PKT,13);
    test("dev-on-eid",DEV_ON_EID,13);
    test("dev-on-ext",DEV_ON_EXT,13);
    test("dev-on-tx",DEV_ON_TX,12);
    test("dev-off-tx",DEV_OFF_TX,12);
    test("dev-on-rx",DEV_ON_RX,13);
    test("dev-off-rx",DEV_OFF_RX,13);
    test("dev-nvm-mismatch",DEV_NVM_MISMATCH,30);
    test("dev-cpu-irq-drop",DEV_CPU_IRQ_DROP,25);
    test("dev-clock-frozen",DEV_CLOCK_FROZEN,13);
    test("dev-reset-stuck",DEV_RESET_STUCK,80);
    test("dev-dma-busy",DEV_DMA_BUSY,81);
    test("dev-patch-ready",DEV_PATCH_READY,0);
    test("dev-delayed3s",DEV_DELAY_3000,0);
    test("dev-delayed5.999s",DEV_DELAY_5999,0);
    test("dev-at6s-deadline",DEV_AT_DEADLINE,13);
    test("dev-backwards-clock",DEV_BACKWARDS,13);
    test("var-on40",VAR_ON40,0);
    test("var-off40",VAR_OFF40,0);
    test("var-both40",VAR_BOTH40,0);
    test("var-odd29",VAR_ODD29,0);
    test("var-max",VAR_MAX,0);
    test("var-truncated",VAR_TRUNCATED,14);
    test("var-overdeclared",VAR_OVERDECLARED,14);
    test("var-echo",VAR_ECHO,33);
    test("var-count",VAR_COUNT,33);
    test("var-own",VAR_OWN,33);
    test("var-reject",VAR_REJECT,32);
    test("var-high",VAR_HIGH,32);
    test("var-off-reject",VAR_OFF_REJECT,32);
    test("var-seq",VAR_SEQ,13);
    test("var-pkt",VAR_PKT,13);
    test("var-ext",VAR_EXT,13);
    test("bss-good",BSS_GOOD,0);
    test("bss-generic-ext",BSS_GENERIC_EXT,0);
    test("bss-max-reply",BSS_MAX_REPLY,0);
    test("bss-short-base",BSS_SHORT_BASE,36);
    test("bss-off-short-base",BSS_OFF_SHORT_BASE,36);
    test("bss-truncated",BSS_TRUNCATED,14);
    test("bss-echo",BSS_ECHO,36);
    test("bss-off-echo",BSS_OFF_ECHO,36);
    test("bss-index",BSS_INDEX,36);
    test("bss-off-index",BSS_OFF_INDEX,36);
    test("bss-count",BSS_COUNT,36);
    test("bss-off-count",BSS_OFF_COUNT,36);
    test("bss-reject",BSS_REJECT,35);
    test("bss-high-reject",BSS_HIGH_REJECT,35);
    test("bss-off-reject",BSS_OFF_REJECT,35);
    test("bss-off-high-reject",BSS_OFF_HIGH_REJECT,35);
    test("bss-ext-bad",BSS_EXT_BAD,13);
    test("bss-seq-bad",BSS_SEQ_BAD,13);
    test("bss-pid-bad",BSS_PID_BAD,13);
    test("bss-tx-lost",BSS_TX_LOST,12);
    test("bss-off-tx-lost",BSS_OFF_TX_LOST,12);
    test("bss-rx-lost",BSS_RX_LOST,13);
    test("bss-off-rx-lost",BSS_OFF_RX_LOST,13);
    test("bss-dev-off-fail",BSS_DEV_OFF_FAIL,32);
    test("bss-no-devinfo",BSS_NO_DEVINFO,34);
    test("bss-dev-on-fail",BSS_DEV_ON_FAIL,32);
    test("bss-nvm-fail",BSS_NVM_FAIL,30);
    test("bss-delay-5999",BSS_DELAY_5999,0);
    test("bss-frozen",BSS_FROZEN,13);
    test("bss-backwards",BSS_BACKWARDS,13);
    test("bss-reset-stuck",BSS_RESET_STUCK,80);
    test("bss-dma-busy",BSS_DMA_BUSY,81);
    test("bss-patch-ready",BSS_PATCH_READY,0);
    test_irq_gate();

    test_radio(0,0,0);test_radio(29,0,0);test_radio(30,0,0);
    for(unsigned k=0;k<5;++k) for(unsigned f=1;f<=15;++f) {
        unsigned rc=f<=2?38:f==3||f==5||f==6?39:f==7?14:f==10?12:13;
        if(f==12) rc=0;
        test_radio(f,k,rc);
    }
    test_radio(16,0,80);test_radio(17,0,81);test_radio(18,0,32);test_radio(19,0,30);test_radio(20,0,37);
    test_radio(21,0,0);test_radio(22,0,0);
    for(unsigned f=23;f<=26;++f) test_radio(f,0,40);
    test_radio(27,0,5);test_radio(28,0,5);
    test_radio_rx();
    for(unsigned f=0;f<4;++f) test_beacon(f,0,0);
    for(unsigned k=0;k<4;++k) for(unsigned f=4;f<=17;++f) {
        unsigned rc=f<=5?42:f==6||f==8?43:f==9?14:f==12?12:f==14?0:13;
        test_beacon(f,k,rc);
    }
    for(unsigned k=0;k<4;k+=3) { test_beacon(18,k,43);test_beacon(19,k,43);test_beacon(20,k,42); }
    test_beacon(21,0,41);test_beacon(22,0,38);test_beacon(23,0,35);test_beacon(24,0,30);test_beacon(25,0,80);test_beacon(26,0,81);
    test_beacon(30,0,5);test_beacon(31,0,5);test_beacon(32,0,40);test_beacon(33,0,0);test_beacon(34,0,14);test_beacon(37,0,0);
    test_watch(0,0,0,0);test_watch(10,0,42000,0);test_watch(11,1,42000,0);
    for(unsigned k=0;k<2;++k) {
        for(unsigned f=1;f<=9;++f) test_watch(f,k,42000,44);
        test_watch(12,k,0,5);test_watch(13,k,0,5);
        test_watch(3,k,0,44);test_watch(3,k,30000000,44);
        test_watch(14,k,0,0);test_watch(15,k,0,0);
    }
    test_watch(16,0,0,41);test_watch(17,0,0,80);test_watch(18,0,0,81);
    for(i=0;i<6;++i) free((void *)firmware[i].data);
    puts("PASS:495 actual-core scenarios + 18 IRQ gate cases; OEM packet/mode/query oracle; all MCU/DMA/MMIO effects synthetic.");
    return 0;
}
