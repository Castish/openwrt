/* SPDX-License-Identifier: MIT
 * Test-only Linux API/MMIO model. The driver logic itself is included unchanged.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>

typedef uint32_t u32;
typedef uint8_t u8;
typedef uint32_t dma_addr_t;
typedef int spinlock_t;
typedef int netdev_tx_t;
#define __iomem
#define ETH_ALEN 6
#define ETH_MIN_MTU 68
#define ETH_DATA_LEN 1500
#define GFP_KERNEL 0
#define HZ 100
#define NETDEV_TX_OK 0
#define NETDEV_TX_BUSY 0x10
#define CHECKSUM_NONE 0
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x, value) (*(volatile __typeof__(x) *)&(x) = (value))
#define unlikely(x) (x)
#define DMA_BIT_MASK(bits) ((1ull << (bits)) - 1)
#define BUILD_BUG_ON(x) _Static_assert(!(x), "build assertion")
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define dma_wmb() __sync_synchronize()
#define dma_rmb() __sync_synchronize()
#define spin_lock_init(lock) (*(lock) = 0)
#define spin_lock(lock) do { assert(!*(lock)); *(lock) = 1; } while (0)
#define spin_unlock(lock) do { assert(*(lock)); *(lock) = 0; } while (0)
#define spin_lock_bh(lock) spin_lock(lock)
#define spin_unlock_bh(lock) spin_unlock(lock)
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define from_timer(value, ptr, member) container_of(ptr, __typeof__(*value), member)

static unsigned char model_fe[0x20000] __attribute__((aligned(64)));
static unsigned char model_pcs[0x200] __attribute__((aligned(64)));
static unsigned char model_ethsys[0x1000] __attribute__((aligned(64)));
static unsigned mmio_writes, dma_alloc_calls, dma_free_calls, dma_live;
static unsigned skb_live, received_packets, received_length, netdev_live;
static unsigned char received_data[2048];
static int fail_allocation = -1, fail_rx_skb, fail_skb_copy;
static bool stuck_dma;
static dma_addr_t next_dma = 0x41000000;
static unsigned long jiffies;

static void model_put(void *base, unsigned offset, u32 value) { memcpy((char *)base + offset, &value, 4); }
static u32 model_get(const void *base, unsigned offset) { u32 v; memcpy(&v, (const char *)base + offset, 4); return v; }
static u32 readl(const void *address)
{
    u32 value;
    memcpy(&value, address, 4);
    if (address == model_fe + 0xa04) {
        if (stuck_dma) value |= 0xa;
        else value &= ~0xau;
    }
    return value;
}
static void writel(u32 value, void *address)
{
    uintptr_t offset = (uintptr_t)address - (uintptr_t)model_fe;
    static const unsigned allowed[] = {0x800, 0x804, 0x808, 0x900, 0x904,
                                      0x908, 0xa04, 0xa08, 0xa28, 0x500};
    bool found = false;
    for (unsigned i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++)
        if (offset == allowed[i]) found = true;
    assert(found && "Unexpected MMIO write outside the PDMA/GDMA test allowlist");
    mmio_writes++;
    model_put(model_fe, offset, value);
}
#define readl_poll_timeout(address, value, condition, interval, timeout) ({ \
    int result = -ETIMEDOUT; \
    for (unsigned n = 0; n < 100; n++) { value = readl(address); if (condition) { result = 0; break; } } \
    result; })

struct device { void *data; };
struct platform_device { struct device dev; };
struct timer_list { void (*callback)(struct timer_list *); bool armed; };
struct net_device;
struct sk_buff { unsigned char *head, *data; unsigned len, capacity; unsigned protocol, ip_summed; };
#define STAT_FIELDS unsigned long tx_packets, tx_bytes, rx_packets, rx_bytes, tx_dropped, rx_dropped, rx_errors
struct net_device_stats { STAT_FIELDS; };
struct rtnl_link_stats64 { STAT_FIELDS; };
struct net_device_ops {
    int (*ndo_open)(struct net_device *);
    int (*ndo_stop)(struct net_device *);
    netdev_tx_t (*ndo_start_xmit)(struct sk_buff *, struct net_device *);
    void (*ndo_get_stats64)(struct net_device *, struct rtnl_link_stats64 *);
    void (*ndo_tx_timeout)(struct net_device *, unsigned);
    int (*ndo_validate_addr)(struct net_device *);
};
struct net_device {
    void *priv;
    struct device *parent;
    struct net_device_stats stats;
    const struct net_device_ops *netdev_ops;
    unsigned watchdog_timeo, min_mtu, max_mtu, features, hw_features;
    unsigned char address[6];
    char name[16];
    bool queue_stopped, carrier, registered;
};
struct attribute { int unused; };
struct device_attribute { struct attribute attr; };
struct attribute_group { struct attribute **attrs; };
struct of_device_id { const char *compatible; };
struct platform_driver {
    int (*probe)(struct platform_device *);
    struct { const char *name; const struct of_device_id *of_match_table; bool suppress_bind_attrs; } driver;
};
#define DEVICE_ATTR_RO(name) struct device_attribute dev_attr_##name
#define builtin_platform_driver(driver)
#define MODULE_LICENSE(value)
#define MODULE_DESCRIPTION(value)
#define SET_NETDEV_DEV(ndev, dev) ((ndev)->parent = (dev))
#define dev_info(...) ((void)0)
#define dev_err(...) ((void)0)
#define netdev_info(...) ((void)0)
#define netdev_err(...) ((void)0)

static void *dev_get_drvdata(struct device *dev) { return dev->data; }
static void platform_set_drvdata(struct platform_device *pdev, void *data) { pdev->dev.data = data; }
static void *netdev_priv(struct net_device *ndev) { return ndev->priv; }
static int dma_set_mask_and_coherent(struct device *dev, uint64_t mask) { assert(mask == 0xffffffff); return 0; }
static void *devm_platform_ioremap_resource_byname(struct platform_device *pdev, const char *name)
{
    if (!strcmp(name, "fe")) return model_fe;
    if (!strcmp(name, "sgmii")) return model_pcs;
    assert(!strcmp(name, "ethsys")); return model_ethsys;
}
static struct net_device *alloc_etherdev(size_t private_size)
{
    struct net_device *dev = calloc(1, sizeof(*dev));
    assert(dev); dev->priv = calloc(1, private_size); assert(dev->priv);
    netdev_live++; return dev;
}
static void free_netdev(struct net_device *dev) { free(dev->priv); free(dev); assert(netdev_live); netdev_live--; }
static int register_netdev(struct net_device *dev) { strcpy(dev->name, "eth0"); dev->registered = true; return 0; }
static void unregister_netdev(struct net_device *dev) { dev->registered = false; }
static int devm_device_add_group(struct device *dev, const struct attribute_group *group) { return 0; }
static bool is_valid_ether_addr(const u8 *addr)
{
    unsigned nonzero = 0; for (unsigned i = 0; i < 6; i++) nonzero |= addr[i];
    return nonzero && !(addr[0] & 1);
}
static void eth_hw_addr_set(struct net_device *dev, const u8 *addr) { memcpy(dev->address, addr, 6); }
static int eth_validate_addr(struct net_device *dev) { return is_valid_ether_addr(dev->address) ? 0 : -EINVAL; }
static void *dma_alloc_coherent(struct device *dev, size_t size, dma_addr_t *dma, int flags)
{
    if ((int)dma_alloc_calls++ == fail_allocation) return NULL;
    void *cpu = calloc(1, size); assert(cpu); *dma = next_dma;
    next_dma += (size + 4095) & ~4095u; dma_live++; return cpu;
}
static void dma_free_coherent(struct device *dev, size_t size, void *cpu, dma_addr_t dma)
{
    assert(!(readl(model_fe + 0xa04) & 0x4f) && "DMA memory freed while engine enabled or busy");
    assert(cpu && dma_live); dma_live--; dma_free_calls++; free(cpu);
}
static void timer_setup(struct timer_list *timer, void (*fn)(struct timer_list *), unsigned flags) { timer->callback = fn; timer->armed = false; }
static void mod_timer(struct timer_list *timer, unsigned long deadline) { timer->armed = true; }
static void del_timer_sync(struct timer_list *timer) { timer->armed = false; }
static void netif_carrier_on(struct net_device *dev) { dev->carrier = true; }
static void netif_carrier_off(struct net_device *dev) { dev->carrier = false; }
static void netif_start_queue(struct net_device *dev) { dev->queue_stopped = false; }
static void netif_stop_queue(struct net_device *dev) { dev->queue_stopped = true; }
static void netif_tx_disable(struct net_device *dev) { dev->queue_stopped = true; }
static void netif_wake_queue(struct net_device *dev) { dev->queue_stopped = false; }
static bool netif_queue_stopped(struct net_device *dev) { return dev->queue_stopped; }
static void netdev_stats_to_stats64(struct rtnl_link_stats64 *out, const struct net_device_stats *in) { memcpy(out, in, sizeof(*out)); }
static struct sk_buff *make_skb(unsigned size)
{
    struct sk_buff *skb = calloc(1, sizeof(*skb)); assert(skb);
    skb->head = calloc(1, size + 2); assert(skb->head); skb->data = skb->head + 2;
    skb->capacity = size; skb_live++; return skb;
}
static void dev_kfree_skb_any(struct sk_buff *skb) { assert(skb_live); skb_live--; free(skb->head); free(skb); }
static struct sk_buff *netdev_alloc_skb_ip_align(struct net_device *dev, unsigned size)
{
    if (fail_rx_skb) { fail_rx_skb = 0; return NULL; }
    return make_skb(size);
}
static void *skb_put(struct sk_buff *skb, unsigned size)
{
    assert(skb->len + size <= skb->capacity); void *data = skb->data + skb->len; skb->len += size; return data;
}
static int skb_copy_bits(struct sk_buff *skb, unsigned offset, void *dest, unsigned size)
{
    if (fail_skb_copy) { fail_skb_copy = 0; return -EIO; }
    assert(offset + size <= skb->len); memcpy(dest, skb->data + offset, size); return 0;
}
static unsigned eth_type_trans(struct sk_buff *skb, struct net_device *dev)
{
    assert(skb->len >= 14); unsigned proto = skb->data[12] << 8 | skb->data[13];
    skb->data += 14; skb->len -= 14; return proto;
}
static void netif_rx(struct sk_buff *skb)
{
    assert(skb->len <= sizeof(received_data)); received_packets++; received_length = skb->len;
    memcpy(received_data, skb->data, skb->len); dev_kfree_skb_any(skb);
}
static ssize_t sysfs_emit(char *buffer, const char *format, ...)
{
    va_list args; va_start(args, format); int n = vsnprintf(buffer, 4096, format, args); va_end(args); return n;
}
