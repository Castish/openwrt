// SPDX-License-Identifier: GPL-2.0-only
/* MT7626 system restart. Register sequence recovered from the supplied
 * factory U-Boot reset_cpu/mtk_arch_reset. No timer is armed at probe.
 */
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/reboot.h>

static int c80_restart(struct sys_off_data *data)
{
    void __iomem *base=data->cb_data;
    u32 mode; unsigned int attempt;
    writel(0x1971,base+8);
    mode=readl(base);
    /* OEM enables external reset. Clear IRQ-only mode, as the upstream
     * MediaTek watchdog restart handler does. */
    writel((mode&~BIT(3))|BIT(2)|0x22000000,base);
    udelay(100);
    for(attempt=0;attempt<100;++attempt) {
        writel(0x1209,base+0x14);
        mdelay(5);
    }
    pr_emerg("C80 system reset did not assert; trying other restart handlers\n");
    return NOTIFY_DONE;
}

static int c80_restart_probe(struct platform_device *pdev)
{
    struct resource *res=platform_get_resource(pdev,IORESOURCE_MEM,0);
    void __iomem *base; int rc;
    if(!res || res->start!=0x10212000 || resource_size(res)!=0x18)
        return -EINVAL;
    base=devm_ioremap_resource(&pdev->dev,res);
    if(IS_ERR(base)) return PTR_ERR(base);
    rc=devm_register_sys_off_handler(&pdev->dev,SYS_OFF_MODE_RESTART,192,
                                    c80_restart,base);
    if(!rc) dev_info(&pdev->dev,"MT7626 system restart registered; use reboot\n");
    return rc;
}
static const struct of_device_id c80_restart_match[]={
    {.compatible="tplink,c80-mt7626-restart"},{}
};
static struct platform_driver c80_restart_driver={
    .probe=c80_restart_probe,.driver={.name="c80-restart",
    .of_match_table=c80_restart_match,.suppress_bind_attrs=true},
};
builtin_platform_driver(c80_restart_driver);
MODULE_LICENSE("GPL");
