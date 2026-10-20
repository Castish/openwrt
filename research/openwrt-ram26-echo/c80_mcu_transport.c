// SPDX-License-Identifier: GPL-2.0-only
/* C80 RAM-only MCU transport experiment, explicitly run once via sysfs.
 * No MAC80211, RF, calibration or NOR programming. Not a production driver.
 */
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/io.h>
#include <linux/kobject.h>
#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of_reserved_mem.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/spinlock.h>
#include <linux/mtd/mtd.h>
#include "c80_mcu_core.h"

struct c80_window { resource_size_t base,bytes; void __iomem *va; };
struct c80_linux {
    struct device *dev;
    struct c80_window windows[5];
    void __iomem *emi;
    struct c80_io io;
    struct c80_result result;
    struct mutex lock;
    struct kobject *kobj;
    dma_addr_t dma;
    struct c80_dma_pool *pool;
    bool ran,finished,retained;
    int rc;
    int irq;
    raw_spinlock_t irq_lock;
    bool irq_cpu_on;
    int nvm_error;
};
static struct c80_linux *c80_live;
static const char *const c80_filenames[6]={
    "c80/test_mcu.bin","c80/test_wifi.bin",
    "c80/WIFI_RAM_CODE_iemi.bin","c80/WIFI_RAM_CODE_demi.bin",
    "c80/mt7626_patch_e1_hdr.bin","c80/WIFI_RAM_CODE_7626.bin"
};
static void __iomem *c80_address(struct c80_linux *c,c80_u32 address)
{
    unsigned int i;
    for(i=0;i<ARRAY_SIZE(c->windows);++i)
        if(address>=c->windows[i].base &&
           address+4<=c->windows[i].base+c->windows[i].bytes)
            return c->windows[i].va+(address-c->windows[i].base);
    WARN_ON_ONCE(1); return NULL;
}
static c80_u32 c80_linux_read(void *context,c80_u32 address)
{
    void __iomem *p=c80_address(context,address);
    return p?readl(p):~0u;
}
static void c80_linux_write(void *context,c80_u32 address,c80_u32 value)
{
    void __iomem *p=c80_address(context,address);
    if(p) writel(value,p);
}
static c80_u64 c80_linux_time(void *context)
{ return ktime_to_us(ktime_get()); }
static void c80_linux_delay(void *context,c80_u32 us)
{ usleep_range(us,us+50); }
static void c80_linux_barrier(void *context,int publish)
{ if(publish) dma_wmb(); else dma_rmb(); }
static void c80_linux_copy(void *context,c80_u32 offset,const c80_u8 *src,c80_u32 n)
{
    struct c80_linux *c=context;
    if(WARN_ON_ONCE(offset>C80_EMI_SIZE || n>C80_EMI_SIZE-offset)) return;
    memcpy_toio(c->emi+offset,src,n); wmb();
}
static c80_u32 c80_linux_crc(void *context,c80_u32 offset,c80_u32 n)
{
    struct c80_linux *c=context; c80_u32 crc=~0u,i;
    if(WARN_ON_ONCE(offset>C80_EMI_SIZE || n>C80_EMI_SIZE-offset)) return 0;
    while(n--) {
        crc^=readb(c->emi+offset++);
        for(i=0;i<8;++i) crc=(crc>>1)^(0xedb88320u&-(crc&1));
        cond_resched();
    }
    return ~crc;
}
static void c80_linux_stage(void *context,c80_u32 stage)
{
    struct c80_linux *c=context;
    dev_info(c->dev,"MCU transport stage%u\n",stage);
    if(stage==38) dev_info(c->dev,"Control window30s; beacon still disabled\n");
    if(stage==37) dev_info(c->dev,"Beacon test window30s; check Wi-Fi list for C80-RAM16\n");
    if(stage==21 || stage==22)
        dev_info(c->dev,"NVM %s: waiting up to 60000 ms for MCU response\n",stage==21?"SET":"GET");
}
static c80_u32 c80_linux_nvm_read(void *context,c80_u8 *out,c80_u32 bytes,c80_u32 *crc)
{
    struct c80_linux *c=context; struct mtd_info *mtd;
    c80_u8 *sector; size_t done=0; int rc;
    if(bytes!=C80_NVM_BYTES) { c->nvm_error=-EINVAL; return C80_NVM_BAD_SOURCE; }
    mtd=get_mtd_device_nm("30000000.flash");
    if(IS_ERR(mtd)) { c->nvm_error=PTR_ERR(mtd); return C80_NVM_BAD_SOURCE; }
    if(mtd->type!=MTD_ROM || mtd->size!=0x400000 || (mtd->flags&MTD_WRITEABLE)) {
        c->nvm_error=-EINVAL; put_mtd_device(mtd); return C80_NVM_BAD_SOURCE;
    }
    sector=kmalloc(4096,GFP_KERNEL);
    if(!sector) { c->nvm_error=-ENOMEM; put_mtd_device(mtd); return C80_NVM_BAD_SOURCE; }
    rc=mtd_read(mtd,0x3ff000,4096,&done,sector);
    if(rc || done!=4096) c->nvm_error=rc?rc:-EIO;
    else {
        *crc=c80_crc(sector,4096);
        if(*crc!=C80_RADIO_CRC) c->nvm_error=-EBADMSG;
        else memcpy(out,sector,C80_NVM_BYTES);
    }
    memzero_explicit(sector,4096); kfree(sector); put_mtd_device(mtd);
    return c->nvm_error?C80_NVM_BAD_SOURCE:0;
}
static irqreturn_t c80_mcu_irq(int irq,void *context)
{
    struct c80_linux *c=context; unsigned long flags;
    raw_spin_lock_irqsave(&c->irq_lock,flags);
    /* Bound a mistaken route too: never return into an enabled level storm.
     * The IRQ domain owns polarity/GIC state; no direct GIC register writes. */
    if(c->irq_cpu_on) { c->irq_cpu_on=false; disable_irq_nosync(irq); }
    c80_irq_event(&c->io,&c->result);
    raw_spin_unlock_irqrestore(&c->irq_lock,flags);
    return IRQ_HANDLED;
}
static c80_u32 c80_linux_irq_arm(void *context,struct c80_result *r)
{
    struct c80_linux *c=context; unsigned long flags; c80_u32 rc;
    if(r->phase!=20 || !r->main_ready || !r->dma_started) return C80_IRQ_BAD;
    raw_spin_lock_irqsave(&c->irq_lock,flags);
    rc=c80_irq_prepare(&c->io,r);
    if(!rc) { c->irq_cpu_on=true; r->irq_cpu_started=1; }
    raw_spin_unlock_irqrestore(&c->irq_lock,flags);
    if(rc) return rc;
    enable_irq(c->irq);
    raw_spin_lock_irqsave(&c->irq_lock,flags);
    rc=c80_irq_unmask(&c->io,r);
    raw_spin_unlock_irqrestore(&c->irq_lock,flags);
    return rc;
}
static c80_u32 c80_linux_irq_disarm(void *context,struct c80_result *r)
{
    struct c80_linux *c=context; unsigned long flags; unsigned int i;
    if(!r->irq_attempted) return 0;
    /* A valid DMA reply alone is insufficient. Give a delayed CPU IRQ a
     * bounded opportunity, without extending failed transport timeouts. */
    for(i=0;r->counter_query_valid && !READ_ONCE(r->irq_entries) && i<100;++i)
        usleep_range(1000,1200);
    raw_spin_lock_irqsave(&c->irq_lock,flags);
    c80_irq_stop(&c->io,r);
    if(c->irq_cpu_on) { c->irq_cpu_on=false; disable_irq_nosync(c->irq); }
    raw_spin_unlock_irqrestore(&c->irq_lock,flags);
    synchronize_irq(c->irq);
    if(r->irq_cpu_started) r->irq_cpu_stopped=1;
    return r->irq_faults?C80_IRQ_BAD:r->irq_events?0:C80_IRQ_NOT_SEEN;
}
static ssize_t status_show(struct kobject *kobj,struct kobj_attribute *attr,char *buf)
{
    struct c80_linux *c=c80_live; struct c80_result *r; ssize_t n;
    if(!c) return -ENODEV;
    mutex_lock(&c->lock); r=&c->result;
    n=sysfs_emit(buf,
        "ran=%u finished=%u result=%d primary=%u cleanup=%u critical=%u phase=%u\n"
        "ready=%u own_before=%08x own_last=%08x own_sent=%u\n"
        "main_iemi_crc=%08x main_demi_crc=%08x\n"
        "get_valid=%u get_status=%u release_valid=%u release_status=%u\n"
        "tx_submitted=%u tx_completed=%u rx_packets=%u rx_ignored=%u rx_next=%u/%u\n"
        "event_len=%u event_id=%02x event_seq=%u packet_id=%04x rx_bad_ctrl=%08x\n"
        "glo_before=%08x glo_after=%08x mask_before=%08x mask_after=%08x source_after=%08x\n"
        "dma_started=%u dma_idle=%u mcu_released=%u mcu_stopped=%u pools_retained=%u\n"
        "controls_before=%08x/%08x/%08x controls_after=%08x/%08x/%08x\n"
        "cleanup_flags=%08x owned_bad=%x other_changed=%x rings_bad=%08x\n"
        "control_diff=%08x/%08x/%08x owned_masks=00208001/00000001/0000000c\n"
        "tx15_before=%08x/%08x/%08x/%08x after=%08x/%08x/%08x/%08x\n"
        "rx0_before=%08x/%08x/%08x/%08x after=%08x/%08x/%08x/%08x\n"
        "rx1_before=%08x/%08x/%08x/%08x after=%08x/%08x/%08x/%08x\n"
        "tx3_before=%08x/%08x/%08x/%08x after=%08x/%08x/%08x/%08x\n"
        "command_tx=%u/%u fwdl_tx=%u/%u sequence=%u last_status=%u\n"
        "patch_address_valid=%u status=%u finish_valid=%u status=%u\n"
        "patch_bytes=%u chunks=%u uploaded=%u ready_valid=%u ready_status=%u sem_held=%u\n"
        "main_attempted=%u regions=%u/3 region_index=%u bytes=%u chunks=%u\n"
        "main_address_valid=%x status=%u/%u/%u\n"
        "main_region_bytes=%u/%u/%u chunks=%u/%u/%u\n"
        "main_start_attempted=%u valid=%u status=%u ready=%u\n"
        "main_sync_before=%08x after=%08x wanted_state=3\n"
        "download_mode_checked=%u enable_glo=%08x last_glo=%08x mode_mask=00000200\n"
        "failure_snapshot=%u phase=%u ring=%u slot=%u cpu=%08x dma=%08x\n"
        "failure_desc=%08x/%08x/%08x/%08x\n"
        "failure_glo=%08x mask=%08x source=%08x sync=%08x own=%08x\n"
        "runtime_glo_before=%08x after=%08x event_ext=%02x\n"
        "counter_query_attempted=%u valid=%u category=%u count=%u value=%08x\n"
        "mask_at_ready=%08x runtime=%08x cleanup_entry=%08x first_zero=%08x after_stop=%08x before_final=%08x zero_writes=%u\n"
        "wifi_irq=%d raw_gic=243 spi=211 attempted=%u armed=%u entries=%u events=%u unexpected=%u faults=%08x cpu_started=%u cpu_stopped=%u\n"
        "irq_mask_before=%08x enabled=%08x after=%08x source_before=%08x cleared=%08x seen=%08x after=%08x ack_writes=%u\n"
        "nvm_source attempted=%u valid=%u linux_errno=%d radio_crc=%08x raw_crc=%08x upload_crc=%08x bytes=1024 copied=960\n"
        "nvm_set attempted=%u valid=%u status=%u get_attempted=%u valid=%u ext=%02x source=%u format=%u offset=%u count=%u crc=%08x equal=%u mismatch=%u/%u padding=%u compared=%u\n"
        "nvm_wait set_limit_ms=60000 get_limit_ms=60000 set_us=%u set_polls=%u get_us=%u get_polls=%u clock_backwards=%u\n"
        "devinfo mac_valid=%u complete=%u on_attempted=%u valid=%u status=%08x ext=%02x own=%u count=%u wait_us=%u polls=%u\n"
        "devinfo_off attempted=%u valid=%u status=%08x ext=%02x own=%u count=%u wait_us=%u polls=%u\n"
        "devinfo_reply on_event=%u dma=%u tail=%u base_read=%u echo=%02x off_event=%u dma=%u tail=%u base_read=%u echo=%02x\n"
        "bss_complete=%u on_attempted=%u valid=%u status=%08x ext=%02x index=%u count=%u echo=%02x event=%u dma=%u tail=%u base_read=%u wait_us=%u polls=%u\n"
        "bss_off attempted=%u valid=%u status=%08x ext=%02x index=%u count=%u echo=%02x event=%u dma=%u tail=%u base_read=%u wait_us=%u polls=%u\n"
        "fresh_boot_required=%u power_cycle_required=%u wifi_ap_tested=0 flash_writes=0\n",
        c->ran,c->finished,c->rc,r->primary,r->cleanup,r->critical,r->phase,
        r->ready,r->own_before,r->own_last,r->own_sent,r->main_crc[0],r->main_crc[1],
        r->get_valid,r->get_status,r->release_valid,r->release_status,
        r->tx_submitted,r->tx_completed,r->rx_packets,r->rx_ignored,r->rx_next[0],r->rx_next[1],
        r->last_event_len,r->last_event_id,r->last_event_seq,r->last_packet_id,r->rx_bad_ctrl,
        r->glo_before,r->glo_after,r->mask_before,r->mask_after,r->source_after,
        r->dma_started,r->dma_idle,r->mcu_released,r->mcu_stopped,c->retained,
        r->controls_before[0],r->controls_before[1],r->controls_before[2],
        r->controls_after[0],r->controls_after[1],r->controls_after[2],
        r->cleanup_flags,r->controls_owned_bad,r->controls_other_changed,r->rings_restore_bad,
        r->control_diff[0],r->control_diff[1],r->control_diff[2],
        r->rings_before[0][0],r->rings_before[0][1],r->rings_before[0][2],r->rings_before[0][3],
        r->rings_after[0][0],r->rings_after[0][1],r->rings_after[0][2],r->rings_after[0][3],
        r->rings_before[1][0],r->rings_before[1][1],r->rings_before[1][2],r->rings_before[1][3],
        r->rings_after[1][0],r->rings_after[1][1],r->rings_after[1][2],r->rings_after[1][3],
        r->rings_before[2][0],r->rings_before[2][1],r->rings_before[2][2],r->rings_before[2][3],
        r->rings_after[2][0],r->rings_after[2][1],r->rings_after[2][2],r->rings_after[2][3],
        r->rings_before[3][0],r->rings_before[3][1],r->rings_before[3][2],r->rings_before[3][3],
        r->rings_after[3][0],r->rings_after[3][1],r->rings_after[3][2],r->rings_after[3][3],
        r->command_completed,r->command_submitted,r->fwdl_completed,r->fwdl_submitted,
        r->sequence,r->last_event_status,r->patch_address_valid,r->patch_address_status,
        r->patch_finish_valid,r->patch_finish_status,r->patch_bytes,r->patch_chunks,
        r->patch_uploaded,r->patch_ready_valid,r->patch_ready_status,r->sem_held,
        r->main_attempted,r->main_regions_complete,r->main_region_index,r->main_bytes,r->main_chunks,
        r->main_region_valid,r->main_region_status[0],r->main_region_status[1],r->main_region_status[2],
        r->main_region_bytes[0],r->main_region_bytes[1],r->main_region_bytes[2],
        r->main_region_chunks[0],r->main_region_chunks[1],r->main_region_chunks[2],
        r->main_start_attempted,r->main_start_valid,r->main_start_status,r->main_ready,
        r->main_sync_before,r->main_sync_after,
        r->download_mode_checked,r->download_enable_glo,r->download_last_glo,
        r->failure_snapshot,r->failure_phase,r->failure_ring,r->failure_slot,
        r->failure_cpu,r->failure_dma,
        r->failure_desc[0],r->failure_desc[1],r->failure_desc[2],r->failure_desc[3],
        r->failure_glo,r->failure_mask,r->failure_source,r->failure_sync,r->failure_own,
        r->runtime_glo_before,r->runtime_glo_after,r->last_event_ext,
        r->counter_query_attempted,r->counter_query_valid,r->counter_category,r->counter_count,r->counter_value,
        r->mask_main_ready,r->mask_runtime,r->mask_cleanup_entry,r->mask_first_zero,r->mask_after_stop,r->mask_before_final_zero,r->mask_zero_writes,
        c->irq,r->irq_attempted,r->irq_armed,r->irq_entries,r->irq_events,r->irq_unexpected,r->irq_faults,r->irq_cpu_started,r->irq_cpu_stopped,
        r->irq_mask_before,r->irq_mask_enable,r->irq_mask_after,r->irq_source_before,r->irq_source_cleared,r->irq_source_seen,r->irq_source_after,r->irq_ack_writes,
        r->nvm_attempted,r->nvm_valid,c->nvm_error,r->nvm_radio_crc,r->nvm_raw_crc,r->nvm_upload_crc,
        r->nvm_set_attempted,r->nvm_set_valid,r->nvm_set_status,r->nvm_get_attempted,r->nvm_get_valid,r->nvm_get_ext,
        r->nvm_get_source,r->nvm_get_format,r->nvm_get_offset,r->nvm_get_count,r->nvm_get_crc,r->nvm_equal,
        r->nvm_mismatch_valid,r->nvm_mismatch_offset,
        r->nvm_get_padding,r->nvm_compared,
        r->nvm_set_wait_us,r->nvm_set_polls,r->nvm_get_wait_us,r->nvm_get_polls,r->nvm_wait_clock_backwards,
        r->devinfo_mac_valid,r->devinfo_complete,r->devinfo_attempted[0],r->devinfo_valid[0],
        r->devinfo_status[0],r->devinfo_ext[0],r->devinfo_ownmac[0],r->devinfo_count[0],r->devinfo_wait_us[0],r->devinfo_polls[0],
        r->devinfo_attempted[1],r->devinfo_valid[1],r->devinfo_status[1],r->devinfo_ext[1],
        r->devinfo_ownmac[1],r->devinfo_count[1],r->devinfo_wait_us[1],r->devinfo_polls[1],
        r->devinfo_event_bytes[0],r->devinfo_dma_bytes[0],r->devinfo_tail_bytes[0],
        r->devinfo_base_read[0],r->devinfo_echo[0],
        r->devinfo_event_bytes[1],r->devinfo_dma_bytes[1],r->devinfo_tail_bytes[1],
        r->devinfo_base_read[1],r->devinfo_echo[1],
        r->bss_complete,r->bss_attempted[0],r->bss_valid[0],r->bss_status[0],r->bss_ext[0],
        r->bss_index[0],r->bss_count[0],r->bss_echo[0],r->bss_event_bytes[0],r->bss_dma_bytes[0],
        r->bss_tail_bytes[0],r->bss_base_read[0],r->bss_wait_us[0],r->bss_polls[0],
        r->bss_attempted[1],r->bss_valid[1],r->bss_status[1],r->bss_ext[1],
        r->bss_index[1],r->bss_count[1],r->bss_echo[1],r->bss_event_bytes[1],r->bss_dma_bytes[1],
        r->bss_tail_bytes[1],r->bss_base_read[1],r->bss_wait_us[1],r->bss_polls[1],
        c->ran,!!c->result.critical);
    mutex_unlock(&c->lock); return n;
}
/* Separate small attribute keeps the existing status below PAGE_SIZE. */
static ssize_t radio_show(struct kobject *kobj,struct kobj_attribute *attr,char *buf)
{
    struct c80_linux *c=c80_live; struct c80_result *r; ssize_t n=0; unsigned i;
    static const char *const names[]={"mac_off_initial","channel","path","mac_on","mac_off_final"};
    if(!c) return -ENODEV;
    mutex_lock(&c->lock); r=&c->result;
    n+=sysfs_emit_at(buf,n,"complete=%u channel=6 band=0 width_mhz=20 tx_streams=1 rx_streams=1 data_tx=0 AP=0\n",r->radio_complete);
    for(i=0;i<5;++i)
        n+=sysfs_emit_at(buf,n,"%s attempted=%u valid=%u status=%08x ext=%02x echo=%02x event=%u dma=%u wait_us=%u polls=%u\n",
            names[i],r->radio_attempted[i],r->radio_valid[i],r->radio_status[i],r->radio_ext[i],r->radio_echo[i],
            r->radio_event_bytes[i],r->radio_dma_bytes[i],r->radio_wait_us[i],r->radio_polls[i]);
    n+=sysfs_emit_at(buf,n,"listen_started=%u elapsed_us=%u polls=%u RX0_packets=%u bytes=%u full=%u bad=%u\n",
        r->radio_listen_started,r->radio_listen_us,r->radio_listen_polls,r->radio_rx_packets,r->radio_rx_bytes,r->radio_rx_full,r->radio_rx_bad);
    n+=sysfs_emit_at(buf,n,"rx_types=%u/%u/%u/%u/%u/%u/%u/%u raw_frames=%u raw_beacon_headers=%u translated=%u FCS_verified=0\n",
        r->radio_rx_types[0],r->radio_rx_types[1],r->radio_rx_types[2],r->radio_rx_types[3],
        r->radio_rx_types[4],r->radio_rx_types[5],r->radio_rx_types[6],r->radio_rx_types[7],
        r->radio_raw_frames,r->radio_beacon_headers,r->radio_rx_translated);
    n+=sysfs_emit_at(buf,n,"first_valid=%u first_dw0=%08x first_dw1=%08x payload_logged=0\n",
        r->radio_first_valid,r->radio_first_dw0,r->radio_first_dw1);
    n+=sysfs_emit_at(buf,n,"rx0_rearm_enabled=%u rearmed=%u publishes=%u cursor=%u last_cpu=%u readback=%u budget_yields=%u\n",
        c->io.rx0_rearm_test,r->rx0_rearmed,r->rx0_publishes,r->rx_next[0],r->rx0_last_cpu,r->rx0_readback,r->rx0_budget_yields);
    mutex_unlock(&c->lock); return n;
}
static ssize_t beacon_show(struct kobject *kobj,struct kobj_attribute *attr,char *buf)
{
    struct c80_linux *c=c80_live; struct c80_result *r; ssize_t n=0; unsigned i;
    static const char *const names[]={"sync_on","beacon_on","beacon_off","sync_off"};
    if(!c) return -ENODEV;
    mutex_lock(&c->lock); r=&c->result;
    n+=sysfs_emit_at(buf,n,"complete=%u SSID=C80-RAM16 channel=6 width_mhz=20 beacon_TU=100 DTIM=1 rate_mbps=1 template_bytes=94 frame_bytes=62 TIM_pos=88 clients_supported=0 TXD_format=3 frame_type=0 subtype=8\n",r->beacon_complete);
    n+=sysfs_emit_at(buf,n,"BSS_BASIC_period_TU=%u/%u BSS_BASIC_DTIM=%u/%u\n",
        r->bss_period[0],r->bss_period[1],r->bss_dtim[0],r->bss_dtim[1]);
    for(i=0;i<4;++i)
        n+=sysfs_emit_at(buf,n,"%s attempted=%u valid=%u status=%08x ext=%02x echo=%02x index=%u count=%u event=%u dma=%u tail=%u base=%u wait_us=%u polls=%u\n",
            names[i],r->beacon_attempted[i],r->beacon_valid[i],r->beacon_status[i],r->beacon_ext[i],r->beacon_echo[i],r->beacon_index[i],r->beacon_count[i],
            r->beacon_event_bytes[i],r->beacon_dma_bytes[i],r->beacon_tail_bytes[i],r->beacon_base_read[i],r->beacon_wait_us[i],r->beacon_polls[i]);
    n+=sysfs_emit_at(buf,n,"window_started=%u elapsed_us=%u polls=%u target_us=30000000 timestamp_and_FCS_HW_unverified=1 payload_logged=0\n",
        r->beacon_window_started,r->beacon_window_us,r->beacon_window_polls);
    mutex_unlock(&c->lock); return n;
}
/* Emit only saved observations: reading sysfs never accesses MAC MMIO. */
static ssize_t state_show(struct kobject *kobj,struct kobj_attribute *attr,char *buf)
{
    static const char *const names[]={"mac_on","sync_on","beacon_begin","beacon_end","sync_off"};
    struct c80_linux *c=c80_live; struct c80_result *r; ssize_t n=0; unsigned i; const c80_u32 *v;
    if(!c) return -ENODEV;
    mutex_lock(&c->lock); r=&c->result;
    n+=sysfs_emit_at(buf,n,"state=1 snapshots=%02x guard_fault=%02x MMIO_config_writes=0 counters_may_clear_on_read=1 tsf_delta_valid=%u tsf_delta_us=%llu\n",
        r->state_mask,r->state_guard_fault,r->tsf_delta_valid,(unsigned long long)r->tsf_delta_us);
    for(i=0;i<2;++i)
        n+=sysfs_emit_at(buf,n,"tsf_%s attempted=%u valid=%u ext=%02x category=%u low=%08x high=%08x event=%u dma=%u observed_us=%llu wait_us=%u polls=%u\n",
            i?"end":"begin",r->tsf_attempted[i],r->tsf_valid[i],r->tsf_ext[i],r->tsf_category[i],r->tsf_low[i],r->tsf_high[i],r->tsf_event_bytes[i],r->tsf_dma_bytes[i],
            (unsigned long long)r->tsf_observed_us[i],r->tsf_wait_us[i],r->tsf_polls[i]);
    for(i=0;i<5;++i) {
        v=r->state_regs[i];
        n+=sysfs_emit_at(buf,n,"%s valid=%u phase=%u observed_us=%llu allones=%03x arb_scr=%08x tqsm=%08x tqfm=%08x\n",
            names[i],!!(r->state_mask&(1u<<i)),r->state_phase[i],(unsigned long long)r->state_us[i],r->state_allones[i],v[0],v[1],v[2]);
        n+=sysfs_emit_at(buf,n,"%s t0cr=%08x t0tpcr=%08x pisr=%08x mptcr=%08x tmac=%08x\n",names[i],v[3],v[4],v[5],v[6],v[7]);
        n+=sysfs_emit_at(buf,n,"%s mib_scr0=%08x mib_scr1=%08x mib_sdr0=%08x bcn_low16=%u ple_empty=%08x\n",names[i],v[8],v[9],v[10],v[10]&0xffff,v[11]);
    }
    mutex_unlock(&c->lock); return n;
}
static ssize_t watch_show(struct kobject *kobj,struct kobj_attribute *attr,char *buf)
{
    struct c80_linux *c=c80_live; struct c80_result *r; ssize_t n=0; unsigned i,j;
    const struct c80_watch_window *w; const struct c80_hif_sample *s;
    if(!c) return -ENODEV;
    mutex_lock(&c->lock); r=&c->result;
    n+=sysfs_emit_at(buf,n,"watch=1 fault_phase=%u target_us=30000000 max_samples=30001 sample_delay_us=1000 reads_nonatomic=1 auto_reenable=0\n",r->watch_fault_phase);
    for(i=0;i<2;++i) {
        w=&r->watch[i];
        n+=sysfs_emit_at(buf,n,"%s started=%u complete=%u elapsed_us=%u samples=%u last_good_us=%u fault_bits=%02x\n",
            i?"beacon":"control",w->started,w->complete,w->elapsed_us,w->samples,w->last_good_us,w->fault_bits);
        for(j=0;j<2;++j) {
            s=j?&w->last:&w->before;
            n+=sysfs_emit_at(buf,n,"%s_%s glo=%08x own=%08x sync=%08x source=%08x mask=%08x tx_cpu=%u tx_dma=%u rx0_dma=%u rx1_dma=%u\n",
                i?"beacon":"control",j?"last":"first",s->glo,s->own,s->sync,s->source,s->mask,s->tx_cpu,s->tx_dma,s->rx0_dma,s->rx1_dma);
        }
    }
    mutex_unlock(&c->lock); return n;
}
/* Saved scalar counters only. No packet/address storage or MMIO on read. */
static ssize_t mgmt_show(struct kobject *kobj,struct kobj_attribute *attr,char *buf)
{
    struct c80_linux *c=c80_live;struct c80_result *r;struct c80_management_counts *m;ssize_t n=0;unsigned k,i;
    if(!c) return -ENODEV;
    mutex_lock(&c->lock);r=&c->result;
    n+=sysfs_emit_at(buf,n,"enabled=%u responses_submitted=%u full_client_stack=0 FCS_verified=0 packet_or_address_saved=0\n",c->io.management_rx_test,r->auth_submitted);
    for(k=0;k<2;++k) {
        const char *name=k?"beacon":"control";m=&r->management[k];
        n+=sysfs_emit_at(buf,n,"%s headers=%u short=%u bad_fc=%u peer_bad=%u protected_ordered=%u fragments=%u to_us=%u\n",
            name,m->headers,m->short_header,m->bad_fc,m->peer_bad,m->protected_ordered,m->fragments,m->to_us);
        n+=sysfs_emit_at(buf,n,"%s subtype_counts=",name);
        for(i=0;i<16;++i) n+=sysfs_emit_at(buf,n,"%s%u",i?"/":"",m->subtype[i]);
        n+=sysfs_emit_at(buf,n,"\n%s probe_eligible=%u probe_test_ssid=%u probe_wildcard=%u probe_other_ssid=%u probe_first_ssid_bad=%u\n",
            name,m->probe_eligible,m->probe_test_ssid,m->probe_wildcard,m->probe_other_ssid,m->probe_short_ssid);
        n+=sysfs_emit_at(buf,n,"%s auth_to_us=%u auth_open_request=%u auth_other=%u assoc_to_us=%u reassoc_to_us=%u deauth_to_us=%u disassoc_to_us=%u\n",
            name,m->auth_to_us,m->auth_open_request,m->auth_other,m->assoc_to_us,m->reassoc_to_us,m->deauth_to_us,m->disassoc_to_us);
    }
    mutex_unlock(&c->lock);return n;
}
static ssize_t events_show(struct kobject *kobj,struct kobj_attribute *attr,char *buf)
{
    struct c80_linux *c=c80_live;struct c80_result *r;ssize_t n;
    if(!c) return -ENODEV;
    mutex_lock(&c->lock);r=&c->result;
    n=sysfs_emit(buf,"recycle=%u packets=%u rearmed=%u publishes=%u cursor=%u last_cpu=%u readback=%u budget_yields=%u\nunmatched=%u short=%u meta_valid=%02x phase=%u PID=%04x EID=%02x sequence=%u extension=%02x event_bytes=%u DMA_bytes=%u payload_saved=0\n",
        c->io.rx1_rearm_test,r->rx1_packets,r->rx1_rearmed,r->rx1_publishes,r->rx_next[1],r->rx1_last_cpu,r->rx1_readback,r->rx1_budget_yields,
        r->rx1_unmatched,r->rx1_short,r->rx1_meta_valid,r->rx1_meta_phase,r->rx1_meta_pid,r->rx1_meta_eid,r->rx1_meta_seq,r->rx1_meta_ext,r->rx1_meta_event_bytes,r->rx1_meta_dma_bytes);
    mutex_unlock(&c->lock);return n;
}
/* Saved scalar diagnostics only; coherent frame is wiped/freed after safe stop. */
static ssize_t reply_show(struct kobject *kobj,struct kobj_attribute *attr,char *buf)
{
    struct c80_linux *c=c80_live;struct c80_result *r;ssize_t n;
    if(!c) return -ENODEV;
    mutex_lock(&c->lock);r=&c->result;
    n=sysfs_emit(buf,"enabled=%u maximum_responses=1 captured=%u submitted=%u dma_header_done=%u duplicate_skipped=%u late_skipped=%u\n"
        "ring_saved=%u touched=%u programmed=%u restore_bad=%x CPU_readback=%u DMA_index=%u ctrl=%08x polls=%u wait_us=%u\n"
        "pre_submit_BASE=%08x MAX=%u\nring_before=%08x/%08x/%08x/%08x after=%08x/%08x/%08x/%08x\n"
        "same_peer_assoc_candidates=%u auth_transaction=2 status=0 WCID=0 hardware_ring=5 LMAC_queue=16 PHY=CCK1 packet_format=0 token=0 TXD=32 TXP=32 frame_bytes=30\n"
        "buffers_retained_until_reboot_after_submit=1 air_or_ACK_confirmed=0 full_client_stack=0 packet_or_address_in_report=0\n",
        c->io.auth_reply_test,r->auth_captured,r->auth_submitted,r->auth_dma_done,r->auth_duplicate,r->auth_late,
        r->auth_ring_saved,r->auth_ring_touched,r->auth_ring_programmed,r->auth_ring_restore_bad,r->auth_cpu_readback,r->auth_dma_index,r->auth_ctrl,r->auth_polls,r->auth_wait_us,
        r->auth_pre_base,r->auth_pre_count,r->auth_ring_before[0],r->auth_ring_before[1],r->auth_ring_before[2],r->auth_ring_before[3],
        r->auth_ring_after[0],r->auth_ring_after[1],r->auth_ring_after[2],r->auth_ring_after[3],r->auth_same_peer_assoc);
    mutex_unlock(&c->lock);return n;
}
static ssize_t completion_show(struct kobject *k,struct kobj_attribute *a,char *buf)
{
    struct c80_linux *c=c80_live;struct c80_result *r;ssize_t n=0;
    if(!c) return -ENODEV;
    mutex_lock(&c->lock);r=&c->result;
    n+=sysfs_emit_at(buf,n,"enabled=%u RX1_types=%u/%u/%u/%u/%u/%u/%u/%u non_event=%u unknown=%u\n",
        c->io.rx1_packet_test,r->rx1_type[0],r->rx1_type[1],r->rx1_type[2],r->rx1_type[3],r->rx1_type[4],r->rx1_type[5],r->rx1_type[6],r->rx1_type[7],r->rx1_non_event,r->rx1_unknown);
    n+=sysfs_emit_at(buf,n,"last_non_event_type=%u DMA_bytes=%u DW0=%08x\n",r->rx1_last_type,r->rx1_last_bytes,r->rx1_last_dw0);
    n+=sysfs_emit_at(buf,n,"TX_free_reports=%u valid=%u bad=%u other_report=%u tokens=%u ours=%u foreign=%u before_submit=%u duplicate=%u auth_token_returned=%u\n",
        r->txfree_reports,r->txfree_valid,r->txfree_bad,r->txfree_other,r->txfree_tokens,r->txfree_ours,r->txfree_foreign,r->txfree_before_submit,r->txfree_duplicate,r->auth_token_returned);
    n+=sysfs_emit_at(buf,n,"last_TX_free_DMA_bytes=%u DW0=%08x DW1=%08x report_type=%u count=%u version=%u\n",
        r->txfree_bytes,r->txfree_dw0,r->txfree_dw1,r->txfree_report_type,r->txfree_count,r->txfree_version);
    n+=sysfs_emit_at(buf,n,"packet_or_address_saved=0 pool_release_on_report=0 RF_ACK_confirmed=0 full_client_stack=0\n");
    mutex_unlock(&c->lock);return n;
}
static ssize_t association_show(struct kobject *kobj,struct kobj_attribute *attr,char *buf)
{
    struct c80_linux *c=c80_live;struct c80_result *r;ssize_t n=0;unsigned i;
    if(!c) return -ENODEV;
    mutex_lock(&c->lock);r=&c->result;
    n+=sysfs_emit_at(buf,n,"enabled=%u maximum_responses=1 captured=%u duplicate=%u late=%u request_bad=%u cap=%04x listen=%u CCK_mask=%x\n",
        c->io.assoc_reply_test,r->assoc_captured,r->assoc_duplicate,r->assoc_late,r->assoc_request_bad,r->assoc_request_cap,r->assoc_listen,r->assoc_rate_mask);
    for(i=0;i<2;++i) n+=sysfs_emit_at(buf,n,"STA_%s attempted=%u valid=%u status=%08x echo=%02x ext=%02x event=%u DMA=%u tail=%u wait_us=%u polls=%u meta=%u BSS=%u WCID=%u TLVs=%u MUAR=%u\n",
        i?"delete":"create",r->sta_attempted[i],r->sta_valid[i],r->sta_status[i],r->sta_echo[i],r->sta_ext[i],r->sta_event_bytes[i],r->sta_dma_bytes[i],r->sta_tail[i],r->sta_wait_us[i],r->sta_polls[i],r->sta_meta_valid[i],r->sta_meta_bss[i],r->sta_meta_wcid[i],r->sta_meta_count[i],r->sta_meta_muar[i]);
    n+=sysfs_emit_at(buf,n,"submitted=%u DMA_header_done=%u token1_returned=%u CPU_readback=%u DMA_index=%u ctrl=%08x wait_us=%u polls=%u pre_BASE=%08x MAX=%u\n",
        r->assoc_submitted,r->assoc_dma_done,r->assoc_token_returned,r->assoc_cpu_readback,r->assoc_dma_index,r->assoc_ctrl,r->assoc_wait_us,r->assoc_polls,r->assoc_pre_base,r->assoc_pre_count);
    n+=sysfs_emit_at(buf,n,"token1_before_submit=%u duplicate=%u lifecycle_complete=%u same_peer_data_candidates=%u null_candidates=%u\n",
        r->assoc_free_before,r->assoc_free_duplicate,r->assoc_complete,r->assoc_data_candidates,r->assoc_null_candidates);
    n+=sysfs_emit_at(buf,n,"WCID=1 AID=1 token=1 ring_slot=1 PHY=CCK1 frame_bytes=36 firmware_packets=create_BASIC_WTBL_delete_BASIC pool_pinned_until_reboot=1\n");
    n+=sysfs_emit_at(buf,n,"peer_address_or_packet_logged=0 FCS_verified=0 RF_ACK_confirmed=0 data_path_or_DHCP_supported=0\n");
    mutex_unlock(&c->lock);return n;
}
static ssize_t data_show(struct kobject *kobj,struct kobj_attribute *attr,char *buf)
{
    struct c80_linux *c=c80_live;struct c80_result *r;ssize_t n=0;unsigned int i;
    if(!c) return -ENODEV;
    mutex_lock(&c->lock);r=&c->result;
    n+=sysfs_emit_at(buf,n,"enabled=%u endpoint=192.168.2.1 client=192.168.2.2 max_ARP=1 max_ICMP=1 ICMP_payload_max=64\n",c->io.data_echo_test);
    n+=sysfs_emit_at(buf,n,"seen=%u raw=%u translated=%u bad_length=%u bad_status=%u wrong_peer=%u bad_format=%u bad_LLC=%u\n",r->data_seen,r->data_raw,r->data_translated,r->data_bad_length,r->data_bad_status,r->data_wrong_peer,r->data_bad_format,r->data_bad_llc);
    n+=sysfs_emit_at(buf,n,"ARP=%u target=%u IPv4=%u ICMP=%u DHCP_port_candidates=%u other=%u bad_protocol=%u bad_checksum=%u late=%u\n",r->data_arp,r->data_arp_target,r->data_ipv4,r->data_icmp,r->data_dhcp_candidates,r->data_other,r->data_bad_protocol,r->data_bad_checksum,r->data_late);
    n+=sysfs_emit_at(buf,n,"last_RXD1=%08x RXD2=%08x FC=%04x ethertype=%04x submitted_total=%u\n",r->data_last_rxd1,r->data_last_rxd2,r->data_last_fc,r->data_last_ethertype,r->diag_submissions);
    for(i=0;i<2;++i) n+=sysfs_emit_at(buf,n,"%s captured=%u duplicate=%u bytes=%u submitted=%u header_done=%u token_returned=%u slot=%u CPU=%u DMA=%u ctrl=%08x wait_us=%u polls=%u token_early=%u duplicate_free=%u\n",i?"ICMP":"ARP",r->diag_captured[i],r->diag_duplicate[i],r->diag_bytes[i],r->diag_submitted[i],r->diag_dma_done[i],r->diag_token_returned[i],r->diag_slot[i],r->diag_cpu[i],r->diag_dma[i],r->diag_ctrl[i],r->diag_wait_us[i],r->diag_polls[i],r->diag_early[i],r->diag_dup_free[i]);
    n+=sysfs_emit_at(buf,n,"HW_FCS_error_checked=1 independent_FCS=0 RF_ACK_confirmed=0 WLAN_netdev_DHCP_general_IP_stack=0 pool_pinned_until_reboot=1 packet_or_address_logged=0\n");
    mutex_unlock(&c->lock);return n;
}
static ssize_t run_store(struct kobject *kobj,struct kobj_attribute *attr,
                          const char *buf,size_t count)
{
    struct c80_linux *c=c80_live;
    const struct firmware *fw[6]={}; struct c80_blob blobs[6];
    unsigned int i; int rc;
    if(!c || !sysfs_streq(buf,"1")) return -EINVAL;
    if(!mutex_trylock(&c->lock)) return -EBUSY;
    if(c->ran) { mutex_unlock(&c->lock); return -EALREADY; }
    c->ran=true;
    for(i=0;i<6;++i) {
        rc=request_firmware_direct(&fw[i],c80_filenames[i],c->dev);
        if(rc) { c->rc=rc; goto done; }
        if(fw[i]->size>UINT_MAX) { c->rc=-EFBIG; goto done; }
        blobs[i].data=fw[i]->data; blobs[i].bytes=fw[i]->size;
    }
    c->pool=dma_alloc_coherent(c->dev,sizeof(*c->pool),&c->dma,GFP_KERNEL);
    if(!c->pool) { c->rc=-ENOMEM; goto done; }
    memset(c->pool,0,sizeof(*c->pool));
    if(upper_32_bits(c->dma) || c->dma<0x40200000 ||
       c->dma+sizeof(*c->pool)>0x42000000 || (c->dma&255)) {
        c->rc=-ERANGE; goto done;
    }
    c->io.pool=c->pool; c->io.dma_base=(c80_u32)c->dma;
    c->rc=c80_run(&c->io,blobs,&c->result);
done:
    if(c->pool) {
        /* TXP payload fetch can outlive the header's DDONE. This experiment
         * has no independently validated TX-free/payload-engine drain path.
         * After ANY management submission keep the complete pool unchanged
         * until system reset, even when MCU/WPDMA stop checks passed.
         * Critical/failed DMA stop also pins every allocation as before. */
        if(c->result.auth_submitted || c->result.assoc_submitted || c->result.diag_submissions || c->result.critical ||
           (c->result.dma_started && !c->result.dma_idle)) c->retained=true;
        else {
            memzero_explicit(c->pool,sizeof(*c->pool));
            dma_free_coherent(c->dev,sizeof(*c->pool),c->pool,c->dma); c->pool=NULL;
        }
    }
    for(i=0;i<6;++i) release_firmware(fw[i]);
    c->finished=true;
    dev_info(c->dev,"MCU bounded ARP/ICMP test result=%d critical=%u; fresh boot required\n",
             c->rc,c->result.critical);
    mutex_unlock(&c->lock); return count;
}
static struct kobj_attribute reply_attr=__ATTR_RO(reply);
static struct kobj_attribute data_attr=__ATTR_RO(data);
static struct kobj_attribute association_attr=__ATTR_RO(association);
static struct kobj_attribute completion_attr=__ATTR_RO(completion);
static struct kobj_attribute mgmt_attr=__ATTR_RO(mgmt);
static struct kobj_attribute events_attr=__ATTR_RO(events);
static struct kobj_attribute state_attr=__ATTR_RO(state);
static struct kobj_attribute watch_attr=__ATTR_RO(watch);
static struct kobj_attribute beacon_attr=__ATTR_RO(beacon);
static struct kobj_attribute radio_attr=__ATTR_RO(radio);
static struct kobj_attribute status_attr=__ATTR_RO(status);
static struct kobj_attribute run_attr=__ATTR(run,0200,NULL,run_store);
static struct attribute *c80_attrs[]={&data_attr.attr,&completion_attr.attr,&association_attr.attr,&reply_attr.attr,&mgmt_attr.attr,&events_attr.attr,&status_attr.attr,&radio_attr.attr,&beacon_attr.attr,&state_attr.attr,&watch_attr.attr,&run_attr.attr,NULL};
static const struct attribute_group c80_group={.attrs=c80_attrs};

static int c80_mcu_probe(struct platform_device *pdev)
{
    static const resource_size_t expected_base[5]={0x18000000,0x10000000,
        0x10006000,0x10212018,0x10210000};
    static const resource_size_t expected_bytes[5]={0x100000,0x1000,0x1000,4,0x1000};
    struct device_node *memory; struct reserved_mem *rmem;
    struct c80_linux *c; struct resource *res; unsigned int i; int rc;
    if(c80_live) return -EBUSY;
    memory=of_parse_phandle(pdev->dev.of_node,"memory-region",0);
    if(!memory) return -EINVAL;
    rmem=of_reserved_mem_lookup(memory);
    rc=of_property_read_bool(memory,"no-map")?0:-EINVAL;
    of_node_put(memory);
    if(rc || !rmem || rmem->base!=0x40000000 || rmem->size!=C80_EMI_SIZE)
        return dev_err_probe(&pdev->dev,-EINVAL,"Exact2MiB no-map EMI reservation required\n");
    for(i=0;i<C80_EMI_SIZE;i+=PAGE_SIZE)
        if(memblock_is_map_memory(0x40000000+i))
            return dev_err_probe(&pdev->dev,-EINVAL,"EMI has a cacheable linear RAM alias\n");
    c=devm_kzalloc(&pdev->dev,sizeof(*c),GFP_KERNEL);
    if(!c) return -ENOMEM;
    c->dev=&pdev->dev; mutex_init(&c->lock); raw_spin_lock_init(&c->irq_lock);
    for(i=0;i<ARRAY_SIZE(c->windows);++i) {
        res=platform_get_resource(pdev,IORESOURCE_MEM,i);
        if(!res || res->start!=expected_base[i] ||
           resource_size(res)!=expected_bytes[i]) return -EINVAL;
        c->windows[i].base=res->start; c->windows[i].bytes=resource_size(res);
        c->windows[i].va=devm_ioremap_resource(&pdev->dev,res);
        if(IS_ERR(c->windows[i].va)) return PTR_ERR(c->windows[i].va);
    }
    c->emi=devm_ioremap(&pdev->dev,rmem->base,rmem->size);
    if(!c->emi) return -ENOMEM;
    rc=dma_set_mask_and_coherent(&pdev->dev,DMA_BIT_MASK(32));
    if(rc) return rc;
    c->io=(struct c80_io){.context=c,.read=c80_linux_read,.write=c80_linux_write,
        .time_us=c80_linux_time,.delay_us=c80_linux_delay,.dma_order=c80_linux_barrier,
        .copy_emi=c80_linux_copy,.crc_emi=c80_linux_crc,.stage=c80_linux_stage,
        .irq_arm=c80_linux_irq_arm,.irq_disarm=c80_linux_irq_disarm,
        .nvm_read=c80_linux_nvm_read,.devinfo_test=1,.bss_test=1,.radio_test=1,.beacon_test=1,.watch_test=1,.rx0_rearm_test=1,.beacon_state_test=1,.bss_period_test=1,.rx1_rearm_test=1,.management_rx_test=1,.rx1_packet_test=1,.auth_reply_test=1,.assoc_reply_test=1,.data_echo_test=1};
    c->irq=platform_get_irq(pdev,0);
    if(c->irq<0) return c->irq;
    rc=devm_request_irq(&pdev->dev,c->irq,c80_mcu_irq,IRQF_NO_AUTOEN,
                        "c80-mcu-rx1",c);
    if(rc) return dev_err_probe(&pdev->dev,rc,"Cannot reserve Wi-Fi IRQ\n");
    c->kobj=kobject_create_and_add("c80_wifi",kernel_kobj);
    if(!c->kobj) return -ENOMEM;
    c80_live=c;
    rc=sysfs_create_group(c->kobj,&c80_group);
    if(rc) { c80_live=NULL; kobject_put(c->kobj); return rc; }
    platform_set_drvdata(pdev,c);
    dev_info(&pdev->dev,"RAM MCU main-firmware test available in /sys/kernel/c80_wifi; inactive until run=1\n");
    return 0;
}
static const struct of_device_id c80_mcu_match[]={
    {.compatible="tplink,c80-mcu-transport-test"},{}
};
static struct platform_driver c80_mcu_driver={
    .probe=c80_mcu_probe,.driver={.name="c80-mcu-test",.of_match_table=c80_mcu_match,
    .suppress_bind_attrs=true},
};
builtin_platform_driver(c80_mcu_driver);
MODULE_LICENSE("GPL");
