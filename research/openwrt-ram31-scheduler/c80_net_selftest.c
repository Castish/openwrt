// SPDX-License-Identifier: GPL-2.0-only
/* QEMU-only software peer for the actual Linux packet callbacks.
 * No C80 MCU, DMA or radio is emulated. Never enable in a router kernel. */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
typedef unsigned char c80_u8;
typedef unsigned int c80_u32;
typedef unsigned long long c80_u64;
#include "c80_net_types.h"
struct c80_linux {
    struct device *dev;struct net_device *netdev;spinlock_t net_lock;
    struct sk_buff_head net_queue;struct rtnl_link_stats64 net_stats;
    bool net_accept,net_stop_requested;
};
#include "c80_net_linux.h"
#define CAPTURE_N 32
struct c80_selftest {
    struct c80_linux adapter;
    struct delayed_work poll;spinlock_t lock;struct kobject *kobj;
    unsigned head,tail,count;
    unsigned bytes[CAPTURE_N];c80_u8 packets[CAPTURE_N][C80_NET_ETH_MAX];
};
static struct c80_selftest *test;
static void c80_selftest_poll(struct work_struct *work)
{
    struct c80_selftest *s=container_of(to_delayed_work(work),struct c80_selftest,poll);
    c80_u8 packet[C80_NET_ETH_MAX];c80_u32 bytes;unsigned i;unsigned long flags;
    for(i=0;i<C80_NET_QUEUE_N;++i) {
        bytes=c80_linux_net_dequeue(&s->adapter,packet,sizeof(packet));if(!bytes) break;
        spin_lock_irqsave(&s->lock,flags);
        if(s->count==CAPTURE_N) { s->tail=(s->tail+1)%CAPTURE_N;--s->count; }
        s->bytes[s->head]=bytes;memcpy(s->packets[s->head],packet,bytes);
        s->head=(s->head+1)%CAPTURE_N;++s->count;
        spin_unlock_irqrestore(&s->lock,flags);
        c80_linux_net_complete(&s->adapter,bytes);
    }
    if(!c80_linux_net_stop_requested(&s->adapter)) schedule_delayed_work(&s->poll,msecs_to_jiffies(10));
}
static ssize_t inject_write(struct file *file,struct kobject *kobj,
        struct bin_attribute *attr,char *buf,loff_t off,size_t count)
{
    if(off || count<ETH_HLEN || count>C80_NET_ETH_MAX) return -EINVAL;
    if(c80_linux_net_receive(&test->adapter,buf,count)) return -ENOBUFS;
    return count;
}
static ssize_t capture_read(struct file *file,struct kobject *kobj,
        struct bin_attribute *attr,char *buf,loff_t off,size_t count)
{
    struct c80_selftest *s=test;unsigned long flags;unsigned bytes;
    if(off) return 0;
    spin_lock_irqsave(&s->lock,flags);
    if(!s->count) { spin_unlock_irqrestore(&s->lock,flags);return 0; }
    bytes=s->bytes[s->tail];
    if(count<bytes) { spin_unlock_irqrestore(&s->lock,flags);return -EMSGSIZE; }
    memcpy(buf,s->packets[s->tail],bytes);s->tail=(s->tail+1)%CAPTURE_N;--s->count;
    spin_unlock_irqrestore(&s->lock,flags);return bytes;
}
static const struct bin_attribute inject_attr=__BIN_ATTR(inject,0200,NULL,inject_write,C80_NET_ETH_MAX);
static const struct bin_attribute capture_attr=__BIN_ATTR(capture,0400,capture_read,NULL,0);
static int __init c80_selftest_init(void)
{
    static const u8 mac[6]={0x02,0xc0,0x80,0x28,0x00,0x01};
    struct platform_device *pdev;struct c80_selftest *s;int rc;
    if(!IS_ENABLED(CONFIG_ARCH_VIRT)) return -ENODEV;
    pdev=platform_device_register_simple("c80-net-selftest",-1,NULL,0);
    if(IS_ERR(pdev)) return PTR_ERR(pdev);
    s=kzalloc(sizeof(*s),GFP_KERNEL);if(!s) { rc=-ENOMEM;goto device; }
    s->adapter.dev=&pdev->dev;spin_lock_init(&s->adapter.net_lock);
    skb_queue_head_init(&s->adapter.net_queue);spin_lock_init(&s->lock);
    rc=c80_linux_net_prepare(&s->adapter,mac);if(rc) goto memory;
    s->kobj=kobject_create_and_add("c80_net_selftest",kernel_kobj);
    if(!s->kobj) { rc=-ENOMEM;goto netdev; }
    test=s;rc=sysfs_create_bin_file(s->kobj,&inject_attr);if(rc) goto kobj;
    rc=sysfs_create_bin_file(s->kobj,&capture_attr);if(rc) goto inject;
    c80_linux_net_link(&s->adapter,1);INIT_DELAYED_WORK(&s->poll,c80_selftest_poll);
    schedule_delayed_work(&s->poll,msecs_to_jiffies(10));
    pr_info("C80 QEMU SOFTWARE PEER ONLY: real Linux netdev callbacks, no C80 MCU/DMA/radio\n");
    return 0;
inject:sysfs_remove_bin_file(s->kobj,&inject_attr);
kobj:test=NULL;kobject_put(s->kobj);
netdev:unregister_netdev(s->adapter.netdev);free_netdev(s->adapter.netdev);
memory:kfree(s);
device:platform_device_unregister(pdev);return rc;
}
late_initcall(c80_selftest_init);
MODULE_LICENSE("GPL");
