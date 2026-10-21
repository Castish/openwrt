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
#include <linux/mutex.h>
typedef unsigned char c80_u8;
typedef unsigned int c80_u32;
typedef unsigned long long c80_u64;
#include "c80_net_types.h"
#include "c80_security_types.h"
static c80_u32 c80_get16(const c80_u8 *p) { return p[0]|(p[1]<<8); }
#include "c80_rsn.h"
struct c80_linux {
    struct device *dev;struct net_device *netdev;spinlock_t net_lock;
    struct sk_buff_head net_queue;struct rtnl_link_stats64 net_stats;
    struct c80_cfg *cfg;const u8 *peer_address;bool cfg_test_only;
    bool wpa2,net_authorized;const u8 *peer_rsn;u32 peer_rsn_len;
    int (*key_test)(struct c80_linux *,struct c80_key_request *);
    bool net_accept,net_stop_requested;
};
#include "c80_net_linux.h"
#include "c80_cfg80211.h"
#define CAPTURE_N 32
struct c80_selftest {
    struct c80_linux adapter;
    struct delayed_work poll;spinlock_t lock;struct kobject *kobj;
    c80_u8 poll_packet[C80_NET_ETH_MAX];
    unsigned head,tail,count;u8 ptk[16],gtk[16];u32 key_adds,key_deletes,authorizations;
    unsigned bytes[CAPTURE_N];c80_u8 packets[CAPTURE_N][C80_NET_ETH_MAX];
};
static struct c80_selftest *test;
static int c80_selftest_key(struct c80_linux *c,struct c80_key_request *req)
{
    /* Test-only acceptance stub: never linked in a physical kernel. The
     * independent shared-core suite checks actual serialized MCU commands. */
    struct c80_selftest *s=container_of(c,struct c80_selftest,adapter);
    if(req->operation==C80_KEY_ADD) {
        memcpy(req->pairwise?s->ptk:s->gtk,req->key,16);++s->key_adds;
    } else if(req->operation==C80_KEY_DEL) {
        memzero_explicit(req->pairwise?s->ptk:s->gtk,16);++s->key_deletes;
    } else if(req->operation==C80_KEY_AUTHORIZE) ++s->authorizations;
    return 0;
}
static ssize_t keycheck_write(struct file *file,struct kobject *kobj,
        struct bin_attribute *attr,char *buf,loff_t off,size_t count)
{
    /* Compare synthetic handshake-derived PTK, never expose installed bytes. */
    if(off || count!=16 || !test || !test->adapter.cfg->ptk_set) return -EINVAL;
    return memcmp(test->ptk,buf,16)?-EKEYREJECTED:count;
}
static const struct bin_attribute keycheck_attr=__BIN_ATTR(keycheck,0200,NULL,keycheck_write,16);
static void c80_selftest_poll(struct work_struct *work)
{
    struct c80_selftest *s=container_of(to_delayed_work(work),struct c80_selftest,poll);
    c80_u8 *packet=s->poll_packet;c80_u32 bytes;unsigned i;unsigned long flags;
    for(i=0;i<C80_NET_QUEUE_N;++i) {
        bytes=c80_linux_net_dequeue(&s->adapter,packet,C80_NET_ETH_MAX);if(!bytes) break;
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
static ssize_t station_store(struct kobject *kobj,struct kobj_attribute *attr,const char *buf,size_t count)
{
    if(!test || !test->adapter.cfg || !test->adapter.cfg->active) return -EAGAIN;
    if(sysfs_streq(buf,"1")) c80_linux_net_link(&test->adapter,1);
    else if(sysfs_streq(buf,"0")) { c80_linux_net_link(&test->adapter,0);memzero_explicit(test->ptk,16); }
    else if(sysfs_streq(buf,"2")) {
        /* QEMU-only unsolicited interface-stop event, not a device failure. */
        c80_linux_net_link(&test->adapter,0);
        WRITE_ONCE(test->adapter.cfg->active,false);
        WRITE_ONCE(test->adapter.cfg->finished,true);
        cfg80211_stop_iface(test->adapter.cfg->wdev.wiphy,&test->adapter.cfg->wdev,GFP_KERNEL);
    } else return -EINVAL;
    return count;
}
static struct kobj_attribute station_attr=__ATTR(station,0200,NULL,station_store);
static ssize_t control_show(struct kobject *kobj,struct kobj_attribute *attr,char *buf)
{
    struct c80_cfg *a=test?test->adapter.cfg:NULL;
    if(!a) return -ENODEV;
    return sysfs_emit(buf,"starts=%u stops=%u active=%u finished=%u gtk=%u ptk=%u authorized=%u key_adds=%u authorizations=%u\n",
        READ_ONCE(a->starts),READ_ONCE(a->stops),READ_ONCE(a->active),READ_ONCE(a->finished),
        READ_ONCE(a->gtk_set),READ_ONCE(a->ptk_set),READ_ONCE(a->owner->net_authorized),test->key_adds,test->authorizations);
}
static struct kobj_attribute control_attr=__ATTR_RO(control);
static const struct bin_attribute inject_attr=__BIN_ATTR(inject,0200,NULL,inject_write,C80_NET_ETH_MAX);
static const struct bin_attribute capture_attr=__BIN_ATTR(capture,0400,capture_read,NULL,0);
static int __init c80_selftest_init(void)
{
    static const u8 peer[6]={0x02,0xc0,0x80,0x28,0,2};
    static const u8 mac[6]={0x02,0xc0,0x80,0x28,0x00,0x01};
    struct platform_device *pdev;struct c80_selftest *s;int rc;
    if(!IS_ENABLED(CONFIG_ARCH_VIRT)) return -ENODEV;
    pdev=platform_device_register_simple("c80-net-selftest",-1,NULL,0);
    if(IS_ERR(pdev)) return PTR_ERR(pdev);
    s=kzalloc(sizeof(*s),GFP_KERNEL);if(!s) { rc=-ENOMEM;goto device; }
    s->adapter.dev=&pdev->dev;s->adapter.cfg_test_only=true;s->adapter.wpa2=true;
    s->adapter.key_test=c80_selftest_key;
    {
        static const u8 rsn[]={48,20,1,0,0,0x0f,0xac,4,1,0,0,0x0f,0xac,4,1,0,0,0x0f,0xac,2,0,0};
        s->adapter.peer_rsn=rsn;s->adapter.peer_rsn_len=sizeof(rsn);
    }
    s->adapter.peer_address=peer;spin_lock_init(&s->adapter.net_lock);
    skb_queue_head_init(&s->adapter.net_queue);spin_lock_init(&s->lock);
    rc=c80_linux_net_prepare(&s->adapter,mac);if(rc) goto memory;
    s->kobj=kobject_create_and_add("c80_net_selftest",kernel_kobj);
    if(!s->kobj) { rc=-ENOMEM;goto netdev; }
    test=s;rc=sysfs_create_bin_file(s->kobj,&inject_attr);if(rc) goto kobj;
    rc=sysfs_create_bin_file(s->kobj,&keycheck_attr);if(rc) goto inject;
    rc=sysfs_create_bin_file(s->kobj,&capture_attr);if(rc) goto inject;
    rc=sysfs_create_file(s->kobj,&station_attr.attr);if(rc) goto inject;
    rc=sysfs_create_file(s->kobj,&control_attr.attr);if(rc) goto inject;
    c80_linux_net_link(&s->adapter,1);INIT_DELAYED_WORK(&s->poll,c80_selftest_poll);
    schedule_delayed_work(&s->poll,msecs_to_jiffies(10));
    pr_info("C80 QEMU SOFTWARE PEER ONLY: real Linux netdev callbacks, no C80 MCU/DMA/radio\n");
    return 0;
inject:sysfs_remove_bin_file(s->kobj,&inject_attr);
kobj:test=NULL;kobject_put(s->kobj);
netdev:unregister_netdev(s->adapter.netdev);c80_cfg_detach(&s->adapter);free_netdev(s->adapter.netdev);
memory:kfree(s);
device:platform_device_unregister(pdev);return rc;
}
late_initcall(c80_selftest_init);
MODULE_LICENSE("GPL");
