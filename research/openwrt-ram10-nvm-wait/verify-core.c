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
    NVM_SET_SLOW_REJECT,NVM_GET_SLOW_MISMATCH,NVM_SET_POLL_OVERSLEEP };
struct model {
    enum fault fault; struct c80_io io; struct c80_result result;
    c80_u32 regs[80][2],n,phase,writes,tx_seen,fwdl_seen,sem_gets,main_oracle,sync_reads,rx_next[2],own_command;
    c80_u64 us; c80_u8 emi[C80_EMI_SIZE];
    struct c80_dma_pool pool; c80_u8 mcu_nvm[1024];
    struct c80_desc *deferred_rx; c80_u32 deferred_ctrl;
    c80_u64 deferred_due;
};
static struct c80_blob firmware[6];
static c80_u8 stock_packets[42][1152];
static unsigned stock_sizes[42];
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
    if(address==C80_GLO && m->phase==90 && m->result.dma_started && m->fault==DMA_BUSY)
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
    if((m->fault==NVM_SET_TX && m->phase==21) || (m->fault==NVM_GET_TX && m->phase==22)) return;
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
        if(m->io.irq_arm && m->fault!=IRQ_DROP) c80_irq_event(&m->io,&m->result);
        return;
    }
    if(cid==0xed && m->phase>=21) {
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
            c80_put16(response+16,1042);response[24]=m->fault==NVM_GET_9B?0x9b:0x8a;
            response[28]=1;response[29]=1;c80_put16(response+30,0);c80_put16(response+32,1024);
            memcpy(response+34,m->mcu_nvm,1024);
            if(m->fault==NVM_GET_SOURCE) response[28]=0;
            if(m->fault==NVM_GET_FORMAT) response[29]=0;
            if(m->fault==NVM_GET_OFFSET) c80_put16(response+30,1);
            if(m->fault==NVM_GET_COUNT) c80_put16(response+32,1025);
            if(m->fault==NVM_GET_EXT) response[24]=0x7f;
            if(m->fault==NVM_GET_SEQ) response[21]^=1;
            if(m->fault==NVM_GET_PKT) response[19]=0xd0;
            if(m->fault==NVM_GET_DATA || m->fault==NVM_GET_SLOW_MISMATCH) response[34+959]^=1;
            rx->ctrl=C80_DONE|C80_LS0|(1058u<<16);
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
        if(m->phase==90 && m->fault==RESET_STUCK) return;
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
static c80_u32 model_nvm_read(void *opaque,c80_u8 *out,c80_u32 bytes,c80_u32 *crc)
{
    struct model *m=opaque;
    assert(m->phase==2 && !m->writes && bytes==1024);
    if(m->fault==NVM_READ_FAIL) return C80_NVM_BAD_SOURCE;
    *crc=m->fault==NVM_RADIO_BAD?0:C80_RADIO_CRC;
    memcpy(out,synthetic_nvm,1024);
    if(m->fault==NVM_ID_BAD) out[0]^=1;
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
        if(fault==SEM_ALREADY) {
            assert(m->result.tx_submitted==35 && !m->result.release_valid && !m->result.patch_uploaded);
            assert(m->result.command_submitted==6 && m->result.fwdl_completed==29 && m->result.sequence==5);
        } else {
            assert(m->result.tx_submitted==(fault>=NVM_GOOD?43u:41u) && m->result.release_valid && m->result.release_status==3);
            assert(m->result.command_submitted==(fault>=NVM_GOOD?12u:10u) && m->result.fwdl_completed==31 && m->result.sequence==(fault>=NVM_GOOD?13u:11u));
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
    if(fault>=NVM_GOOD) {
        assert(m->result.nvm_attempted);
        if(fault==NVM_READ_FAIL || fault==NVM_RADIO_BAD || fault==NVM_ID_BAD)
            assert(!m->writes && !m->result.nvm_valid && !m->result.mcu_released && !m->result.irq_attempted);
        else {
            assert(m->result.nvm_valid && m->result.dma_idle && m->result.mcu_stopped);
            assert(m->result.irq_events==1 && m->result.irq_cpu_stopped);
            if(expected==0) {
                assert(m->result.nvm_set_valid && !m->result.nvm_set_status && m->result.nvm_get_valid && m->result.nvm_equal);
                assert(m->result.nvm_get_crc==m->result.nvm_upload_crc && m->result.nvm_get_count==1024);
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
    }
    printf("PASS %s rc=%u tx=%u rx=%u critical=%u\n",name,rc,
           m->result.tx_completed,m->result.rx_packets,m->result.critical);
    free(m);
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
    for(i=0;i<42;++i) {
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
    test_irq_gate();
    for(i=0;i<6;++i) free((void *)firmware[i].data);
    puts("PASS:144 actual-core scenarios + 18 IRQ gate cases; OEM packet/mode/query oracle; all MCU/DMA/MMIO effects synthetic.");
    return 0;
}
