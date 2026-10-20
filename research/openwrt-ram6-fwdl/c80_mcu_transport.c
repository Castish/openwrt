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
        c->ran,!!c->result.critical);
    mutex_unlock(&c->lock); return n;
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
        /* DMA must never retain a pointer to returned kernel pages. A failed
         * stop pins the entire pool for the remaining lifetime of this boot. */
        if(c->result.critical ||
           (c->result.dma_started && !c->result.dma_idle)) c->retained=true;
        else { dma_free_coherent(c->dev,sizeof(*c->pool),c->pool,c->dma); c->pool=NULL; }
    }
    for(i=0;i<6;++i) release_firmware(fw[i]);
    c->finished=true;
    dev_info(c->dev,"MCU main firmware test result=%d critical=%u; fresh boot required\n",
             c->rc,c->result.critical);
    mutex_unlock(&c->lock); return count;
}
static struct kobj_attribute status_attr=__ATTR_RO(status);
static struct kobj_attribute run_attr=__ATTR(run,0200,NULL,run_store);
static struct attribute *c80_attrs[]={&status_attr.attr,&run_attr.attr,NULL};
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
    c->dev=&pdev->dev; mutex_init(&c->lock);
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
        .copy_emi=c80_linux_copy,.crc_emi=c80_linux_crc,.stage=c80_linux_stage};
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
