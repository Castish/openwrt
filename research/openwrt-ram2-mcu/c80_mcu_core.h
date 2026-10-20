/* SPDX-License-Identifier: GPL-2.0-only */
/* Narrow MT7626 MCU transport experiment. No 802.11/RF/flash commands.
 * Shared with the native fault model; OS supplies coherent DMA, uncached EMI,
 * MMIO, monotonic time and barriers. Only little-endian ARM/x86 are supported.
 */
#ifndef C80_MCU_CORE_H
#define C80_MCU_CORE_H
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error This bring-up core requires a little-endian CPU
#endif
typedef unsigned int c80_u32;
typedef unsigned char c80_u8;
typedef unsigned long long c80_u64;
#define C80_TX_N 128u
#define C80_RX_N 64u
#define C80_RX_SIZE 1536u
#define C80_EMI_SIZE 0x200000u
#define C80_HIF 0x18000000u
#define C80_OWN (C80_HIF+0x7000)
#define C80_GLO (C80_HIF+0x4208)
#define C80_MASK (C80_HIF+0x4204)
#define C80_SOURCE (C80_HIF+0x4200)
#define C80_RESET 0x10212018u
#define C80_DONE 0x80000000u
#define C80_LS0 0x40000000u
#define C80_MAX_POLLS 40000u

struct c80_desc { volatile c80_u32 addr, ctrl, addr1, info; };
struct c80_dma_pool {
    struct c80_desc tx[C80_TX_N];
    struct c80_desc rx[2][C80_RX_N];
    c80_u8 command[2][256];
    c80_u8 data[2][C80_RX_N][C80_RX_SIZE];
};
struct c80_blob { const c80_u8 *data; c80_u32 bytes; };
struct c80_io {
    void *context;
    c80_u32 (*read)(void *,c80_u32);
    void (*write)(void *,c80_u32,c80_u32);
    c80_u64 (*time_us)(void *);
    void (*delay_us)(void *,c80_u32);
    void (*dma_order)(void *,int); /* 1:publish before device,0:read device data */
    void (*copy_emi)(void *,c80_u32,const c80_u8 *,c80_u32);
    c80_u32 (*crc_emi)(void *,c80_u32,c80_u32);
    void (*stage)(void *,c80_u32);
    struct c80_dma_pool *pool;
    c80_u32 dma_base;
};
enum c80_failure {
    C80_OK=0,C80_BAD_FW=1,C80_BAD_AON=2,C80_BAD_ID=3,C80_STALE=4,
    C80_BAD_TIMER=5,C80_BOOT_CONTROL=6,C80_READY_TIMEOUT=7,C80_OWN_TIMEOUT=8,
    C80_BAD_DMA=9,C80_MAIN_CRC=10,C80_RINGS_CONFIGURED=11,C80_TX_TIMEOUT=12,
    C80_RX_TIMEOUT=13,C80_RX_BAD=14,C80_SEMAPHORE=15,C80_RESTORE=16,
    C80_RING_PROGRAM=17,
    C80_CRITICAL_RESET=80,C80_CRITICAL_DMA=81
};
struct c80_result {
    c80_u32 phase,primary,cleanup,critical,ready,own_before,own_last,own_sent;
    c80_u32 glo_before,glo_after,mask_before,mask_after,source_after;
    c80_u32 controls_before[3],controls_after[3],aon_before[10],aon_after[10];
    c80_u32 rings_before[3][4],rings_after[3][4];
    c80_u32 main_crc[2],tx_submitted,tx_completed,rx_packets,rx_ignored;
    c80_u32 get_valid,get_status,release_valid,release_status,rx_bad_ctrl;
    c80_u32 last_event_len,last_event_id,last_event_seq,last_packet_id;
    c80_u32 dma_started,dma_idle,mcu_released,mcu_stopped,controls_touched;
    c80_u32 rings_touched,dma_cfg_touched,rx_next[2];
};
static const c80_u32 c80_aon_regs[10]={0x10000220,0x10000228,0x10000230,
    0x10000238,0x10000370,0x10006000,0x10006608,0x1000660c,0x10006610,C80_RESET};
static const c80_u32 c80_controls[3]={0x18002150,0x18001130,0x10210000};
static const c80_u32 c80_control_masks[3]={0x208001,1,12};
static const c80_u32 c80_ring_regs[3]={0x180043f0,0x18004400,0x18004410};
static const c80_u32 c80_blob_sizes[4]={72096,169240,395008,119036};
static const c80_u32 c80_blob_crcs[4]={0x2ede9294,0x4e2c264c,0x10efafc7,0x9d2bbb46};
static const c80_u32 c80_blob_offsets[4]={0,0x43000,0x75000,0x146800};

static c80_u32 c80_crc(const c80_u8 *p,c80_u32 size)
{
    c80_u32 crc=~0u,i;
    while(size--) { crc^=*p++; for(i=0;i<8;++i) crc=(crc>>1)^(0xedb88320u&-(crc&1)); }
    return ~crc;
}
static c80_u32 c80_read(struct c80_io *io,c80_u32 reg)
{ return io->read(io->context,reg); }
static void c80_write(struct c80_io *io,c80_u32 reg,c80_u32 value)
{ io->write(io->context,reg,value); }
static void c80_stage(struct c80_io *io,struct c80_result *r,c80_u32 phase)
{ r->phase=phase; if(io->stage) io->stage(io->context,phase); }
static int c80_poll(struct c80_io *io,c80_u32 reg,c80_u32 mask,c80_u32 value,
                    c80_u32 timeout,c80_u32 *last)
{
    c80_u64 start=io->time_us(io->context),now; c80_u32 i,v;
    for(i=0;i<C80_MAX_POLLS;++i) {
        v=c80_read(io,reg); if(last) *last=v;
        if(v!=0xffffffffu && (v&mask)==value) return 1;
        now=io->time_us(io->context);
        if(now<start || now-start>=timeout) return 0;
        io->delay_us(io->context,50);
    }
    return 0;
}
static c80_u32 c80_dma_address(struct c80_io *io,const volatile void *p)
{ return io->dma_base+(c80_u32)((const volatile c80_u8 *)p-(const volatile c80_u8 *)io->pool); }
static void c80_put16(c80_u8 *p,c80_u32 v) { p[0]=v; p[1]=v>>8; }
static void c80_put32(c80_u8 *p,c80_u32 v)
{ c80_put16(p,v); c80_put16(p+2,v>>16); }
static c80_u32 c80_get16(const c80_u8 *p) { return p[0]|((c80_u32)p[1]<<8); }
static void c80_command(c80_u8 *p,c80_u32 operation,c80_u32 sequence)
{
    c80_u32 i; for(i=0;i<68;++i) p[i]=0;
    c80_put32(p,0x80000044); c80_put32(p+4,0x0200a000);
    c80_put16(p+32,36); c80_put16(p+34,0x8000);
    p[36]=0x10; p[37]=0xa0; p[38]=3; p[39]=sequence;
    c80_put32(p+64,operation);
}
static c80_u32 c80_receive(struct c80_io *io,struct c80_result *r,c80_u32 sequence,
                           c80_u32 *status)
{
    c80_u32 q,index,control,size,n; const c80_u8 *p;
    /* No descriptor rearming: at most63 packets per ring during this test.
     * A bounded single experiment avoids CPU/device writes sharing a slot. */
    for(q=0;q<2;++q) for(n=0;n<C80_RX_N;++n) {
        index=r->rx_next[q];
        if(index>=C80_RX_N-1) return C80_RX_BAD;
        control=io->pool->rx[q][index].ctrl;
        if(!(control&C80_DONE)) break;
        io->dma_order(io->context,0);
        size=(control>>16)&0x3fff;
        ++r->rx_packets; ++r->rx_next[q];
        if(!(control&C80_LS0) || !size || size>C80_RX_SIZE) {
            r->rx_bad_ctrl=control; return C80_RX_BAD;
        }
        p=io->pool->data[q][index];
        /* OEM response handler receives the event after16-byte RX prefix.
         * PATCH_SEM EID4 uses an8-byte event header and status payload. */
        if(size<25) { ++r->rx_ignored; continue; }
        r->last_event_len=c80_get16(p+16);
        r->last_packet_id=c80_get16(p+18);
        r->last_event_id=p[20]; r->last_event_seq=p[21];
        if(r->last_event_len<9 || r->last_event_len>size-16) return C80_RX_BAD;
        if(r->last_packet_id!=0xe000 || p[20]!=4 || p[21]!=sequence) {
            ++r->rx_ignored; continue;
        }
        *status=p[24]; return 0;
    }
    return C80_RX_TIMEOUT;
}
static c80_u32 c80_exchange(struct c80_io *io,struct c80_result *r,
                            c80_u32 operation,c80_u32 *reply)
{
    c80_u32 slot=r->tx_submitted,sequence=slot+1,i,rx=0,tx=0,rc;
    c80_u64 start,now; struct c80_desc *d;
    if(slot>=2) return C80_TX_TIMEOUT;
    c80_command(io->pool->command[slot],operation,sequence);
    d=&io->pool->tx[slot]; d->addr=c80_dma_address(io,io->pool->command[slot]);
    d->addr1=0; d->info=0; d->ctrl=C80_LS0|(68u<<16);
    io->dma_order(io->context,1);
    ++r->tx_submitted; c80_write(io,0x180043f8,r->tx_submitted);
    start=io->time_us(io->context);
    for(i=0;i<C80_MAX_POLLS;++i) {
        if(!tx && (d->ctrl&C80_DONE) && c80_read(io,0x180043fc)==r->tx_submitted) {
            io->dma_order(io->context,0); tx=1; ++r->tx_completed;
        }
        if(!rx) {
            rc=c80_receive(io,r,sequence,reply);
            if(rc==C80_RX_BAD) return rc;
            if(!rc) rx=1;
        }
        if(rx && tx) return 0;
        now=io->time_us(io->context);
        if(now<start || now-start>=2000000) break;
        io->delay_us(io->context,50);
    }
    return tx?C80_RX_TIMEOUT:C80_TX_TIMEOUT;
}
static void c80_cleanup(struct c80_io *io,struct c80_result *r)
{
    c80_u32 v,i,j;
    c80_stage(io,r,90);
    if(r->dma_cfg_touched) {
        v=c80_read(io,C80_GLO); c80_write(io,C80_GLO,v&~5u);
    }
    if(r->mcu_released) {
        v=c80_read(io,C80_RESET);
        c80_write(io,C80_RESET,(v&0xffffff)|0x88001000);
        if(!c80_poll(io,C80_RESET,0x1000,0x1000,20000,0)) {
            r->critical=C80_CRITICAL_RESET; return;
        }
        r->mcu_stopped=1; io->delay_us(io->context,2000);
    }
    if(r->dma_cfg_touched) {
        if(!c80_poll(io,C80_GLO,15,0,200000,0)) {
            r->critical=C80_CRITICAL_DMA; return;
        }
        r->dma_idle=1;
    }
    /* Read-only DMA indices cannot be restored by ordinary register writes.
     * Restore programmed controls only, retain masked IRQ source, cold-cycle. */
    if(r->rings_touched) for(i=0;i<3;++i) for(j=0;j<3;++j)
        c80_write(io,c80_ring_regs[i]+4*j,r->rings_before[i][j]);
    if(r->dma_cfg_touched) c80_write(io,C80_GLO,r->glo_before);
    for(i=3;i;i--) if(r->controls_touched&(1u<<(i-1))) {
        v=c80_read(io,c80_controls[i-1]);
        c80_write(io,c80_controls[i-1],(v&~c80_control_masks[i-1])|
            (r->controls_before[i-1]&c80_control_masks[i-1]));
    }
    for(i=0;i<3;++i) {
        r->controls_after[i]=c80_read(io,c80_controls[i]);
        if(r->controls_touched && r->controls_after[i]!=r->controls_before[i]) r->cleanup=1;
    }
    if(r->ready) {
        r->glo_after=c80_read(io,C80_GLO); r->mask_after=c80_read(io,C80_MASK);
        r->source_after=c80_read(io,C80_SOURCE);
        if((r->dma_cfg_touched || r->rings_touched) && (r->glo_after&15)) {
            r->critical=C80_CRITICAL_DMA; return;
        }
        if(r->dma_cfg_touched && r->glo_after!=r->glo_before) r->cleanup=1;
        if(r->dma_cfg_touched && r->mask_after!=r->mask_before) r->cleanup=1;
    }
    for(i=0;i<10;++i) r->aon_after[i]=c80_read(io,c80_aon_regs[i]);
    if(r->rings_touched) for(i=0;i<3;++i) for(j=0;j<4;++j) {
        r->rings_after[i][j]=c80_read(io,c80_ring_regs[i]+4*j);
        if(j<3 && r->rings_after[i][j]!=r->rings_before[i][j]) r->cleanup=1;
    }
}
static c80_u32 c80_run(struct c80_io *io,const struct c80_blob *fw,
                       struct c80_result *r)
{
    c80_u32 i,j,v,rc=0,programmed[3][3]; c80_u64 start;
    c80_stage(io,r,1);
    for(i=0;i<4;++i) if(!fw[i].data || fw[i].bytes!=c80_blob_sizes[i] ||
       c80_crc(fw[i].data,fw[i].bytes)!=c80_blob_crcs[i]) { r->primary=C80_BAD_FW; return C80_BAD_FW; }
    start=io->time_us(io->context); io->delay_us(io->context,10);
    if(io->time_us(io->context)<=start) { r->primary=C80_BAD_TIMER; return C80_BAD_TIMER; }
    for(i=0;i<10;++i) r->aon_before[i]=c80_read(io,c80_aon_regs[i]);
    if((r->aon_before[0]&0x8104) || (r->aon_before[1]&0x8104) ||
       (r->aon_before[2]&7) || (r->aon_before[3]&7) ||
       (r->aon_before[4]&0xfff)!=0x40 || !(r->aon_before[5]&1) ||
       (r->aon_before[6]&0x20800000)!=0x20800000 ||
       r->aon_before[7]!=r->aon_before[8] ||
       (r->aon_before[7]&0x07000000)!=0x07000000 ||
       (r->aon_before[9]&0x1200)!=0x1000) { r->primary=C80_BAD_AON; return C80_BAD_AON; }
    c80_stage(io,r,2);
    if(c80_read(io,0x180b1010)!=0x10040101 || c80_read(io,0x180b101c)&15 ||
       (c80_read(io,0x18002000)&0xffff)!=0x8a00 ||
       (c80_read(io,0x18002004)&0xffff)!=0x8a00) { r->primary=C80_BAD_ID; return C80_BAD_ID; }
    if(c80_read(io,0x18002600)==0x1d1e) { r->primary=C80_STALE; return C80_STALE; }
    for(i=0;i<3;++i) r->controls_before[i]=c80_read(io,c80_controls[i]);
    c80_stage(io,r,3);
    for(i=0;i<2;++i) {
        io->copy_emi(io->context,c80_blob_offsets[i],fw[i].data,fw[i].bytes);
        if(io->crc_emi(io->context,c80_blob_offsets[i],fw[i].bytes)!=c80_blob_crcs[i]) {
            rc=C80_BAD_FW; goto done;
        }
    }
    for(i=0;i<3;++i) {
        r->controls_touched|=1u<<i;
        c80_write(io,c80_controls[i],r->controls_before[i]|c80_control_masks[i]);
        if((c80_read(io,c80_controls[i])&c80_control_masks[i])!=c80_control_masks[i]) {
            rc=C80_BOOT_CONTROL; goto done;
        }
    }
    v=c80_read(io,C80_RESET); r->mcu_released=1;
    c80_write(io,C80_RESET,((v&0xffffff)&~0x1000u)|0x88000000);
    if(c80_read(io,C80_RESET)&0x1000) { rc=C80_BOOT_CONTROL; goto done; }
    c80_stage(io,r,4);
    if(!c80_poll(io,0x18002600,~0u,0x1d1e,2000000,0)) { rc=C80_READY_TIMEOUT; goto done; }
    r->ready=1; r->own_before=c80_read(io,C80_OWN);
    if(r->own_before==0xffffffffu) { rc=C80_OWN_TIMEOUT; goto done; }
    if(r->own_before&1) { c80_write(io,C80_OWN,2); r->own_sent=1; }
    if(!c80_poll(io,C80_OWN,1,0,2000000,&r->own_last)) { rc=C80_OWN_TIMEOUT; goto done; }
    r->glo_before=c80_read(io,C80_GLO); r->mask_before=c80_read(io,C80_MASK);
    if(r->glo_before==0xffffffffu || (r->glo_before&15) || r->mask_before) {
        rc=C80_BAD_DMA; goto done;
    }
    c80_stage(io,r,5);
    /* Match OEM ordering: main EMI copies AFTER initial MCU/HIF ownership.
     * Linux maps reserved EMI without a cacheable linear alias. */
    for(i=2;i<4;++i) {
        io->copy_emi(io->context,c80_blob_offsets[i],fw[i].data,fw[i].bytes);
        r->main_crc[i-2]=io->crc_emi(io->context,c80_blob_offsets[i],fw[i].bytes);
        if(r->main_crc[i-2]!=c80_blob_crcs[i]) { rc=C80_MAIN_CRC; goto done; }
    }
    c80_stage(io,r,6);
    /* Global enable applies to every TX queue, including FWDL3. Refuse
     * inherited descriptors on any other queue before enabling the engine. */
    for(i=0;i<16;++i) if(c80_read(io,0x18004304+i*16)) {
        rc=C80_RINGS_CONFIGURED; goto done;
    }
    for(i=0;i<3;++i) for(j=0;j<4;++j) {
        r->rings_before[i][j]=c80_read(io,c80_ring_regs[i]+4*j);
        if(r->rings_before[i][j]) { rc=C80_RINGS_CONFIGURED; goto done; }
    }
    for(i=0;i<C80_TX_N;++i) io->pool->tx[i].ctrl=C80_DONE;
    for(i=0;i<2;++i) for(j=0;j<C80_RX_N;++j) {
        io->pool->rx[i][j].addr=c80_dma_address(io,io->pool->data[i][j]);
        io->pool->rx[i][j].ctrl=C80_RX_SIZE<<16;
    }
    r->rings_touched=1;
    programmed[0][0]=c80_dma_address(io,io->pool->tx);
    programmed[0][1]=C80_TX_N; programmed[0][2]=0;
    for(i=0;i<2;++i) {
        programmed[i+1][0]=c80_dma_address(io,io->pool->rx[i]);
        programmed[i+1][1]=C80_RX_N; programmed[i+1][2]=C80_RX_N-1;
    }
    for(i=0;i<3;++i) for(j=0;j<3;++j)
        c80_write(io,c80_ring_regs[i]+4*j,programmed[i][j]);
    for(i=0;i<3;++i) for(j=0;j<3;++j)
        if(c80_read(io,c80_ring_regs[i]+4*j)!=programmed[i][j]) {
            rc=C80_RING_PROGRAM; goto done;
        }
    if(c80_read(io,C80_MASK) || (c80_read(io,C80_GLO)&15)) {
        rc=C80_BAD_DMA; goto done;
    }
    io->dma_order(io->context,1); r->dma_cfg_touched=1;
    c80_write(io,C80_GLO,r->glo_before|0xc45); r->dma_started=1;
    if((c80_read(io,C80_GLO)&0xc45)!=0xc45) { rc=C80_BAD_DMA; goto done; }
    c80_stage(io,r,7);
    rc=c80_exchange(io,r,1,&r->get_status);
    if(rc) goto done;
    r->get_valid=1;
    if(r->get_status==2) {
        c80_stage(io,r,8);
        rc=c80_exchange(io,r,0,&r->release_status);
        if(!rc) r->release_valid=1;
        if(!rc && r->release_status!=3) rc=C80_SEMAPHORE;
    } else if(r->get_status!=1) rc=C80_SEMAPHORE;
done:
    r->primary=rc; c80_cleanup(io,r);
    return r->critical?r->critical:r->cleanup?C80_RESTORE:rc;
}
#endif
