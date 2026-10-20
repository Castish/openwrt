// SPDX-License-Identifier: GPL-2.0-only
/*
 * Temporary Archer C80/MT7626 Linux RAM test of the confirmed PDMA path.
 * Requires TFTP to have configured MAC/SGMII/RTL8367S. No clocks, resets,
 * PCS or NOR programming is performed here. MDIO management is separate
 * and limited to snapshots, with no switch port/link configuration. The measured
 * common IRQ uses the standard MediaTek sysirq polarity controller.
 * Register offsets and 16-byte descriptor fields follow the C80 GPL BSP.
 */
#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/skbuff.h>

#include "c80_pdma_core.h"
#include "c80_ram_mdio.h"

#define TX_BASE 0x0800
#define TX_COUNT 0x0804
#define TX_CPU 0x0808
#define TX_DMA 0x080c
#define RX_BASE 0x0900
#define RX_COUNT 0x0904
#define RX_CPU 0x0908
#define RX_DMA 0x090c
#define DMA_CFG 0x0a04
#define DMA_RESET_IDX 0x0a08
#define DMA_IRQ_STATUS 0x0a20
#define DMA_IRQ_MASK 0x0a28
#define DMA_IRQ_DONE 0x00010001
#define FE_IRQ_GROUP 0x0020
#define DMA_IRQ_GROUP0 0x0a50
#define DMA_IRQ_GROUP1 0x0a54
#define GDM_FWD 0x0500
#define GDM_MAC_LO 0x0508
#define GDM_MAC_HI 0x050c
#define GMAC_CTRL 0x10100
#define GMAC_STATUS 0x10108

enum { TX_DESC, RX_DESC, TX_BUFFER, RX_BUFFER, BLOCK_COUNT };
static const size_t block_sizes[BLOCK_COUNT] = {
	C80_TX_COUNT * sizeof(struct c80_desc), C80_RX_COUNT * sizeof(struct c80_desc),
	C80_TX_COUNT * C80_BUFFER_SIZE, C80_RX_COUNT * C80_BUFFER_SIZE,
};

struct c80_block { void *cpu; dma_addr_t dma; };
struct c80_ram_eth {
	struct net_device *ndev;
	struct device *dev;
	void __iomem *fe, *pcs, *ethsys;
	struct mii_bus *mdio;
	struct c80_block block[BLOCK_COUNT];
	struct c80_desc *txd, *rxd;
	spinlock_t lock;
	struct napi_struct napi;
	int irq, pending_check;
	unsigned int tx_head, tx_tail, tx_pending, rx_next;
	unsigned short tx_bytes[C80_TX_COUNT];
	u32 saved_fwd, last_rx_info, timeout_count;
	u32 irq_count, irq_tx, irq_rx, irq_faults, napi_polls;
	bool running, irq_enabled, napi_enabled, irq_fault;
};

static u32 c80_read(struct c80_ram_eth *p, unsigned int reg)
{
	return readl(p->fe + reg);
}

static void c80_write(struct c80_ram_eth *p, unsigned int reg, u32 value)
{
	writel(value, p->fe + reg);
}

static bool c80_guard(struct c80_ram_eth *p)
{
	u32 route = readl(p->ethsys + 0x14), mcr = c80_read(p, GMAC_CTRL);
	u32 pcs = readl(p->pcs), mode = readl(p->pcs + 0x20);
	u32 power = readl(p->pcs + 0xe8), ana = readl(p->pcs + 0x128);
	u32 pdma = c80_read(p, DMA_CFG);

	if (readl(p->pcs + 4) != 0x4d544950 ||
	    (readl(p->pcs + 0x14) >> 16) != 1 ||
	    !c80_inherited_state_ok(route, mcr, pcs, mode, power, ana, pdma)) {
		dev_err(p->dev, "inherited Ethernet state differs: route=%08x mcr=%08x pcs=%08x mode=%08x power=%08x ana=%08x pdma=%08x\n",
			route, mcr, pcs, mode, power, ana, pdma);
		return false;
	}
	if (c80_read(p, FE_IRQ_GROUP) || c80_read(p, DMA_IRQ_GROUP0) ||
	    c80_read(p, DMA_IRQ_GROUP1) || c80_read(p, DMA_IRQ_MASK)) {
		dev_err(p->dev, "IRQ grouping/mask differs from measured inherited ID255 path\n");
		return false;
	}
	return true;
}

/* This UP-only test's sysirq/GIC chips have no sleeping bus-lock callbacks.
 * Temporarily enable only this line while local CPU IRQs stay disabled;
 * reject an asserted idle line before installing rings or starting DMA.
 */
static int c80_check_idle_irq(struct c80_ram_eth *p)
{
	unsigned long flags;
	bool pending = true;
	int ret;

	local_irq_save(flags);
	enable_irq(p->irq);
	udelay(10);
	ret = irq_get_irqchip_state(p->irq, IRQCHIP_STATE_PENDING, &pending);
	disable_irq_nosync(p->irq);
	local_irq_restore(flags);
	p->pending_check = ret ? ret : pending;
	if (ret || pending) {
		dev_err(p->dev, "idle IRQ check failed: rc=%d pending=%u; DMA not started\n", ret, pending);
		return -EIO;
	}
	return 0;
}

static void c80_irq_fault(struct c80_ram_eth *p)
{
	if (!p->irq_fault)
		netdev_err(p->ndev, "IRQ without PDMA done status; IRQ disabled, use netdown\n");
	p->irq_fault = true;
	p->irq_faults++;
	c80_write(p, DMA_IRQ_MASK, 0);
	if (p->irq_enabled) {
		p->irq_enabled = false;
		disable_irq_nosync(p->irq);
	}
	netif_stop_queue(p->ndev);
}

static irqreturn_t c80_irq(int irq, void *data)
{
	struct c80_ram_eth *p = data;
	u32 status = c80_read(p, DMA_IRQ_STATUS) & DMA_IRQ_DONE;

	c80_write(p, DMA_IRQ_MASK, 0);
	c80_read(p, DMA_IRQ_MASK); /* Flush masking before GIC EOI. */
	if (!status) {
		c80_irq_fault(p);
		return IRQ_HANDLED;
	}
	p->irq_count++;
	if (status & 1)
		p->irq_tx++;
	if (status & 0x10000)
		p->irq_rx++;
	if (READ_ONCE(p->running) && !READ_ONCE(p->irq_fault))
		napi_schedule_irqoff(&p->napi);
	return IRQ_HANDLED;
}

static int c80_dma_quiet(struct c80_ram_eth *p)
{
	u32 value = c80_read(p, DMA_CFG);

	c80_write(p, DMA_CFG, value & ~C80_DMA_ENABLE);
	return readl_poll_timeout(p->fe + DMA_CFG, value,
				 !(value & (C80_DMA_BUSY | C80_DMA_ENABLE)), 20, 100000);
}

/* Caller has proved DMA quiet, or has never installed these buffers. */
static void c80_free_buffers(struct c80_ram_eth *p)
{
	int i;

	for (i = 0; i < BLOCK_COUNT; i++) {
		if (!p->block[i].cpu)
			continue;
		dma_free_coherent(p->dev, block_sizes[i], p->block[i].cpu, p->block[i].dma);
		p->block[i].cpu = NULL;
	}
	p->txd = NULL;
	p->rxd = NULL;
}

static int c80_alloc_buffers(struct c80_ram_eth *p)
{
	unsigned int i;

	for (i = 0; i < BLOCK_COUNT; i++) {
		p->block[i].cpu = dma_alloc_coherent(p->dev, block_sizes[i],
						    &p->block[i].dma, GFP_KERNEL);
		if (!p->block[i].cpu) {
			c80_free_buffers(p);
			return -ENOMEM;
		}
		memset(p->block[i].cpu, 0, block_sizes[i]);
	}
	p->txd = p->block[TX_DESC].cpu;
	p->rxd = p->block[RX_DESC].cpu;
	for (i = 0; i < C80_TX_COUNT; i++) {
		p->txd[i].word[0] = p->block[TX_BUFFER].dma + i * C80_BUFFER_SIZE;
		p->txd[i].word[1] = C80_DDONE | C80_LAST;
		p->txd[i].word[3] = C80_TX_PORT1;
	}
	for (i = 0; i < C80_RX_COUNT; i++) {
		p->rxd[i].word[0] = p->block[RX_BUFFER].dma + i * C80_BUFFER_SIZE;
		p->rxd[i].word[1] = C80_BUFFER_SIZE << 16;
	}
	p->tx_head = p->tx_tail = p->tx_pending = p->rx_next = 0;
	return 0;
}

static int c80_poll(struct napi_struct *napi, int budget)
{
	struct c80_ram_eth *p = container_of(napi, struct c80_ram_eth, napi);
	struct net_device *ndev = p->ndev;
	unsigned long flags;
	int work = 0;
	u32 status;

	p->napi_polls++;
	if (!READ_ONCE(p->running) || READ_ONCE(p->irq_fault)) {
		if (budget)
			napi_complete_done(napi, 0);
		return 0;
	}
	/* Acknowledge before draining rings: a later completion remains latched
	 * across the final empty-ring check and interrupt rearm. Budget-zero
	 * calls reclaim TX only and must not acknowledge or complete RX NAPI.
	 */
	if (budget) {
		status = c80_read(p, DMA_IRQ_STATUS) & DMA_IRQ_DONE;
		if (status)
			c80_write(p, DMA_IRQ_STATUS, status);
	}
	spin_lock(&p->lock);
	while (p->tx_pending && (READ_ONCE(p->txd[p->tx_tail].word[1]) & C80_DDONE)) {
		dma_rmb();
		ndev->stats.tx_packets++;
		ndev->stats.tx_bytes += p->tx_bytes[p->tx_tail];
		p->tx_tail = c80_next(p->tx_tail, C80_TX_COUNT);
		p->tx_pending--;
	}
	if (netif_queue_stopped(ndev) && p->tx_pending < C80_TX_COUNT - 1)
		netif_wake_queue(ndev);
	spin_unlock(&p->lock);
	if (!budget)
		return 0;

	while (work < budget) {
		struct c80_desc *desc = &p->rxd[p->rx_next];
		u32 control = READ_ONCE(desc->word[1]);
		unsigned int size;
		struct sk_buff *skb;

		if (!(control & C80_DDONE))
			break;
		dma_rmb();
		size = c80_rx_length(control);
		p->last_rx_info = READ_ONCE(desc->word[3]);
		if (!size || ((p->last_rx_info >> 19) & 7) == 6) {
			ndev->stats.rx_errors++;
			ndev->stats.rx_dropped++;
		} else {
			skb = netdev_alloc_skb_ip_align(ndev, size);
			if (!skb) {
				ndev->stats.rx_dropped++;
			} else {
				memcpy(skb_put(skb, size), p->block[RX_BUFFER].cpu +
				       p->rx_next * C80_BUFFER_SIZE, size);
				skb->protocol = eth_type_trans(skb, ndev);
				skb->ip_summed = CHECKSUM_NONE;
				ndev->stats.rx_packets++;
				ndev->stats.rx_bytes += size;
				napi_gro_receive(napi, skb);
			}
		}
		WRITE_ONCE(desc->word[3], 0);
		dma_wmb();
		WRITE_ONCE(desc->word[1], C80_BUFFER_SIZE << 16);
		dma_wmb();
		c80_write(p, RX_CPU, p->rx_next);
		p->rx_next = c80_next(p->rx_next, C80_RX_COUNT);
		work++;
	}
	if (work < budget && napi_complete_done(napi, work)) {
		local_irq_save(flags);
		if (READ_ONCE(p->running) && !READ_ONCE(p->irq_fault))
			c80_write(p, DMA_IRQ_MASK, DMA_IRQ_DONE);
		local_irq_restore(flags);
	}
	return work;
}

static netdev_tx_t c80_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct c80_ram_eth *p = netdev_priv(ndev);
	unsigned int size = c80_tx_length(skb->len), index;
	void *buffer;

	if (!size) {
		ndev->stats.tx_dropped++;
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
	spin_lock_bh(&p->lock);
	if (unlikely(p->tx_pending >= C80_TX_COUNT - 1)) {
		netif_stop_queue(ndev);
		spin_unlock_bh(&p->lock);
		return NETDEV_TX_BUSY;
	}
	index = p->tx_head;
	buffer = p->block[TX_BUFFER].cpu + index * C80_BUFFER_SIZE;
	if (unlikely(skb_copy_bits(skb, 0, buffer, skb->len))) {
		ndev->stats.tx_dropped++;
		spin_unlock_bh(&p->lock);
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
	if (size > skb->len)
		memset(buffer + skb->len, 0, size - skb->len);
	p->tx_bytes[index] = skb->len;
	dma_wmb();
	WRITE_ONCE(p->txd[index].word[1], c80_tx_control(size));
	dma_wmb();
	p->tx_head = c80_next(index, C80_TX_COUNT);
	p->tx_pending++;
	c80_write(p, TX_CPU, p->tx_head);
	if (p->tx_pending == C80_TX_COUNT - 1)
		netif_stop_queue(ndev);
	spin_unlock_bh(&p->lock);
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static int c80_open(struct net_device *ndev)
{
	struct c80_ram_eth *p = netdev_priv(ndev);
	int ret;

	if (p->block[0].cpu) {
		if (c80_dma_quiet(p))
			return -EBUSY;
		c80_free_buffers(p);
	}
	if (!c80_guard(p))
		return -EINVAL;
	c80_write(p, DMA_IRQ_MASK, 0);
	c80_write(p, DMA_IRQ_STATUS, DMA_IRQ_DONE);
	if (c80_read(p, DMA_IRQ_STATUS) & DMA_IRQ_DONE) {
		dev_err(p->dev, "PDMA done status did not clear while DMA halted\n");
		return -EIO;
	}
	ret = c80_check_idle_irq(p);
	if (ret)
		return ret;
	ret = c80_alloc_buffers(p);
	if (ret)
		return ret;
	p->saved_fwd = c80_read(p, GDM_FWD);
	c80_write(p, DMA_IRQ_MASK, 0);
	c80_write(p, GDM_FWD, p->saved_fwd & ~C80_GDMA_ROUTE_MASK);
	dma_wmb();
	c80_write(p, TX_BASE, p->block[TX_DESC].dma);
	c80_write(p, TX_COUNT, C80_TX_COUNT);
	c80_write(p, TX_CPU, 0);
	c80_write(p, RX_BASE, p->block[RX_DESC].dma);
	c80_write(p, RX_COUNT, C80_RX_COUNT);
	c80_write(p, RX_CPU, C80_RX_COUNT - 1);
	c80_write(p, DMA_RESET_IDX, (1 << 16) | 1);
	p->irq_fault = false;
	napi_enable(&p->napi);
	p->napi_enabled = true;
	WRITE_ONCE(p->running, true);
	c80_write(p, DMA_CFG, 0x00001410 | C80_DMA_ENABLE);
	netif_carrier_on(ndev);
	netif_start_queue(ndev);
	p->irq_enabled = true;
	enable_irq(p->irq);
	c80_write(p, DMA_IRQ_MASK, DMA_IRQ_DONE);
	netdev_info(ndev, "RAM PDMA IRQ/NAPI enabled (irq=%d, GIC ID255); inherited CPU-switch path\n", p->irq);
	return 0;
}

static int c80_stop(struct net_device *ndev)
{
	struct c80_ram_eth *p = netdev_priv(ndev);
	unsigned long flags;

	netif_tx_disable(ndev);
	netif_carrier_off(ndev);
	WRITE_ONCE(p->running, false);
	c80_write(p, DMA_IRQ_MASK, 0);
	local_irq_save(flags);
	if (p->irq_enabled) {
		p->irq_enabled = false;
		disable_irq_nosync(p->irq);
	}
	local_irq_restore(flags);
	synchronize_irq(p->irq);
	if (p->napi_enabled) {
		napi_disable(&p->napi);
		p->napi_enabled = false;
	}
	if (c80_dma_quiet(p)) {
		/* Never release memory which a stuck DMA engine can still access. */
		netdev_err(ndev, "DMA did not stop; buffers pinned until reset\n");
		return -EBUSY;
	}
	c80_write(p, GDM_FWD, p->saved_fwd);
	c80_free_buffers(p);
	return 0;
}

static void c80_timeout(struct net_device *ndev, unsigned int queue)
{
	struct c80_ram_eth *p = netdev_priv(ndev);

	p->timeout_count++;
	netdev_err(ndev, "TX timeout: head=%u tail=%u pending=%u, ctx=%u dtx=%u\n",
		   p->tx_head, p->tx_tail, p->tx_pending,
		   c80_read(p, TX_CPU), c80_read(p, TX_DMA));
}

static void c80_get_stats(struct net_device *ndev, struct rtnl_link_stats64 *out)
{
	struct c80_ram_eth *p = netdev_priv(ndev);

	spin_lock_bh(&p->lock);
	netdev_stats_to_stats64(out, &ndev->stats);
	spin_unlock_bh(&p->lock);
}

static const struct net_device_ops c80_netdev_ops = {
	.ndo_open = c80_open, .ndo_stop = c80_stop, .ndo_start_xmit = c80_xmit,
	.ndo_get_stats64 = c80_get_stats, .ndo_tx_timeout = c80_timeout,
	.ndo_validate_addr = eth_validate_addr,
};

static ssize_t ram_state_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct c80_ram_eth *p = dev_get_drvdata(dev);
	ssize_t count;
	unsigned long flags;

	spin_lock_irqsave(&p->lock, flags);
	count = sysfs_emit(buf,
		"running=%u pools=%u tx_head=%u tx_tail=%u tx_pending=%u rx_next=%u timeouts=%u\n"
		"pdma=%08x tx_ctx=%08x tx_dtx=%08x rx_calc=%08x rx_drx=%08x irq_mask=%08x\n"
		"mcr=%08x msr=%08x route=%08x pcs=%08x mode=%08x ana=%08x last_rx_info=%08x\n"
		"irq=%d irq_enabled=%u events=%u tx_events=%u rx_events=%u napi_polls=%u irq_fault=%u faults=%u idle_pending=%d irq_status=%08x\n",
		p->running, !!p->block[0].cpu, p->tx_head, p->tx_tail, p->tx_pending, p->rx_next, p->timeout_count,
		c80_read(p, DMA_CFG), c80_read(p, TX_CPU), c80_read(p, TX_DMA),
		c80_read(p, RX_CPU), c80_read(p, RX_DMA), c80_read(p, DMA_IRQ_MASK),
		c80_read(p, GMAC_CTRL), c80_read(p, GMAC_STATUS), readl(p->ethsys + 0x14),
		readl(p->pcs), readl(p->pcs + 0x20), readl(p->pcs + 0x128), p->last_rx_info,
		p->irq, p->irq_enabled, p->irq_count, p->irq_tx, p->irq_rx, p->napi_polls,
		p->irq_fault, p->irq_faults, p->pending_check, c80_read(p, DMA_IRQ_STATUS));
	spin_unlock_irqrestore(&p->lock, flags);
	return count;
}
static DEVICE_ATTR_RO(ram_state);
static ssize_t switch_state_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct c80_ram_eth *p = dev_get_drvdata(dev);

	return c80_mdio_snapshot(p->mdio, buf);
}
static DEVICE_ATTR_RO(switch_state);
static struct attribute *c80_attrs[] = {
	&dev_attr_ram_state.attr, &dev_attr_switch_state.attr, NULL
};
static const struct attribute_group c80_group = { .attrs = c80_attrs };

static int c80_probe(struct platform_device *pdev)
{
	struct net_device *ndev;
	struct c80_ram_eth *p;
	u32 hi, lo;
	u8 address[ETH_ALEN];
	int ret;

	BUILD_BUG_ON(sizeof(struct c80_desc) != 16);
	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
	if (ret)
		return ret;
	ndev = alloc_etherdev(sizeof(*p));
	if (!ndev)
		return -ENOMEM;
	p = netdev_priv(ndev);
	p->ndev = ndev;
	p->dev = &pdev->dev;
	p->pending_check = -1;
	p->fe = devm_platform_ioremap_resource_byname(pdev, "fe");
	p->pcs = devm_platform_ioremap_resource_byname(pdev, "sgmii");
	p->ethsys = devm_platform_ioremap_resource_byname(pdev, "ethsys");
	if (IS_ERR(p->fe) || IS_ERR(p->pcs) || IS_ERR(p->ethsys)) {
		ret = -ENODEV;
		goto free;
	}
	if (!c80_guard(p)) {
		ret = -EINVAL;
		goto free;
	}
	p->irq = platform_get_irq(pdev, 0);
	if (p->irq < 0) {
		ret = p->irq;
		goto free;
	}
	hi = c80_read(p, GDM_MAC_HI);
	lo = c80_read(p, GDM_MAC_LO);
	address[0] = hi >> 8; address[1] = hi;
	address[2] = lo >> 24; address[3] = lo >> 16;
	address[4] = lo >> 8; address[5] = lo;
	if (!is_valid_ether_addr(address)) {
		dev_err(&pdev->dev, "invalid inherited GDMA1 MAC address\n");
		ret = -EINVAL;
		goto free;
	}
	eth_hw_addr_set(ndev, address);
	SET_NETDEV_DEV(ndev, &pdev->dev);
	ndev->netdev_ops = &c80_netdev_ops;
	ndev->watchdog_timeo = 5 * HZ;
	ndev->min_mtu = ETH_MIN_MTU;
	ndev->max_mtu = ETH_DATA_LEN;
	ndev->features = 0;
	ndev->hw_features = 0;
	spin_lock_init(&p->lock);
	netif_napi_add_weight(ndev, &p->napi, c80_poll, 64);
	ret = request_irq(p->irq, c80_irq, IRQF_NO_AUTOEN | IRQF_NO_THREAD | IRQF_TRIGGER_LOW,
			  "c80-ram-pdma", p);
	if (ret)
		goto del_napi;
	p->mdio = c80_mdio_register(&pdev->dev, p->fe);
	if (IS_ERR(p->mdio)) {
		ret = PTR_ERR(p->mdio);
		goto free_irq;
	}
	netif_carrier_off(ndev);
	platform_set_drvdata(pdev, p);
	ret = register_netdev(ndev);
	if (ret)
		goto free_irq;
	ret = devm_device_add_group(&pdev->dev, &c80_group);
	if (ret) {
		unregister_netdev(ndev);
		goto free_irq;
	}
	dev_info(&pdev->dev, "registered %s; IRQ/NAPI, inherited GIC ID255 via active-low sysirq, initially down\n", ndev->name);
	return 0;
free_irq:
	free_irq(p->irq, p);
del_napi:
	netif_napi_del(&p->napi);
free:
	platform_set_drvdata(pdev, NULL);
	free_netdev(ndev);
	return ret;
}

static const struct of_device_id c80_match[] = {
	{ .compatible = "tplink,c80-ram-pdma" }, { }
};
static struct platform_driver c80_driver = {
	.probe = c80_probe,
	.driver = { .name = "c80-ram-pdma", .of_match_table = c80_match,
		    .suppress_bind_attrs = true },
};
builtin_platform_driver(c80_driver);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Experimental C80 Linux RAM PDMA IRQ/NAPI test");
