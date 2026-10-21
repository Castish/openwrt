#include <linux/unaligned.h>
struct c80_cfg;
static int c80_cfg_attach(struct c80_linux *,struct net_device *,const c80_u8 *);
static void c80_cfg_detach(struct c80_linux *);
static void c80_cfg_peer(struct c80_linux *,int);
/* SPDX-License-Identifier: GPL-2.0-only */
/* Linux packet adapter. The run thread exclusively owns device DMA;
 * ndo_start_xmit only queues an skb. No pointer into an skb reaches DMA. */
#define C80_NET_QUEUE_N 16u
static struct c80_linux *c80_net_owner(struct net_device *dev)
{ return *(struct c80_linux **)netdev_priv(dev); }
static void c80_linux_net_purge(struct c80_linux *c)
{
    struct sk_buff *skb;unsigned long flags;
    for(;;) {
        spin_lock_irqsave(&c->net_lock,flags);
        skb=__skb_dequeue(&c->net_queue);
        if(skb) ++c->net_stats.tx_dropped;
        spin_unlock_irqrestore(&c->net_lock,flags);
        if(!skb) break;
        dev_kfree_skb_any(skb);
    }
}
static int c80_linux_ndo_open(struct net_device *dev)
{
    struct c80_linux *c=c80_net_owner(dev);
    if(READ_ONCE(c->net_accept)) netif_start_queue(dev);
    else netif_stop_queue(dev);
    return 0;
}
static int c80_linux_ndo_stop(struct net_device *dev)
{
    netif_stop_queue(dev);c80_linux_net_purge(c80_net_owner(dev));return 0;
}
static netdev_tx_t c80_linux_ndo_xmit(struct sk_buff *skb,struct net_device *dev)
{
    struct c80_linux *c=c80_net_owner(dev);unsigned long flags;
    if(skb->len<ETH_HLEN || skb->len>C80_NET_ETH_MAX || skb_is_gso(skb) ||
       (skb->ip_summed==CHECKSUM_PARTIAL && skb_checksum_help(skb))) goto drop;
    spin_lock_irqsave(&c->net_lock,flags);
    if(!c->net_accept || !netif_running(dev) ||
       (c->wpa2 && !c->net_authorized && skb->protocol!=htons(ETH_P_PAE))) {
        spin_unlock_irqrestore(&c->net_lock,flags);goto drop;
    }
    if(skb_queue_len(&c->net_queue)>=C80_NET_QUEUE_N) {
        netif_stop_queue(dev);spin_unlock_irqrestore(&c->net_lock,flags);
        return NETDEV_TX_BUSY; /* skb remains owned by the caller. */
    }
    __skb_queue_tail(&c->net_queue,skb);
    if(skb_queue_len(&c->net_queue)==C80_NET_QUEUE_N) netif_stop_queue(dev);
    spin_unlock_irqrestore(&c->net_lock,flags);return NETDEV_TX_OK;
drop:
    spin_lock_irqsave(&c->net_lock,flags);++c->net_stats.tx_dropped;
    spin_unlock_irqrestore(&c->net_lock,flags);
    dev_kfree_skb_any(skb);return NETDEV_TX_OK;
}
static void c80_linux_ndo_stats(struct net_device *dev,struct rtnl_link_stats64 *out)
{
    struct c80_linux *c=c80_net_owner(dev);unsigned long flags;
    spin_lock_irqsave(&c->net_lock,flags);*out=c->net_stats;
    spin_unlock_irqrestore(&c->net_lock,flags);
}
/* OpenWrt hostapd explicitly sets the BSSID while bringing the interface up.
 * This profile uses the NVM address in DEVINFO/BSS; acknowledge only the same
 * address. An arbitrary software-only MAC change would break that contract. */
static int c80_linux_ndo_set_mac(struct net_device *dev,void *address)
{
    struct sockaddr *a=address;
    return ether_addr_equal(dev->dev_addr,a->sa_data)?0:-EOPNOTSUPP;
}
static const struct net_device_ops c80_net_ops={
    .ndo_open=c80_linux_ndo_open,.ndo_stop=c80_linux_ndo_stop,
    .ndo_start_xmit=c80_linux_ndo_xmit,.ndo_get_stats64=c80_linux_ndo_stats,
    .ndo_set_mac_address=c80_linux_ndo_set_mac,.ndo_validate_addr=eth_validate_addr,
};
static int c80_linux_net_prepare(void *context,const c80_u8 *mac)
{
    struct c80_linux *c=context;struct net_device *dev;int rc;
    if(c->netdev || !is_valid_ether_addr(mac)) return -EINVAL;
    dev=alloc_etherdev(sizeof(struct c80_linux *));if(!dev) return -ENOMEM;
    *(struct c80_linux **)netdev_priv(dev)=c;
    strscpy(dev->name,"c80wlan0",IFNAMSIZ);dev->netdev_ops=&c80_net_ops;
    dev->mtu=dev->min_mtu=C80_NET_MTU;dev->max_mtu=C80_NET_MTU;
    dev->tx_queue_len=C80_NET_QUEUE_N;dev->flags&=~IFF_MULTICAST;
    dev->features=0;dev->hw_features=0;dev->vlan_features=0;
    eth_hw_addr_set(dev,mac);SET_NETDEV_DEV(dev,c->dev);netif_carrier_off(dev);
    c->netdev=dev;rc=c80_cfg_attach(c,dev,mac);
    if(rc) { c->netdev=NULL;free_netdev(dev);return rc; }
    rc=register_netdev(dev);
    if(rc) { c80_cfg_detach(c);c->netdev=NULL;free_netdev(dev);return rc; }
    dev_info(c->dev,"c80wlan0 registered; Linux IPv4 stack, MTU%u; transport owns TX completion\n",
             C80_NET_MTU);
    return 0;
}
static void c80_linux_net_link(void *context,int on)
{
    struct c80_linux *c=context;unsigned long flags;
    if(!c->netdev) return;
    spin_lock_irqsave(&c->net_lock,flags);c->net_accept=!!on;
    spin_unlock_irqrestore(&c->net_lock,flags);
    if(on) {
        netif_carrier_on(c->netdev);
        if(netif_running(c->netdev)) netif_wake_queue(c->netdev);
    } else {
        netif_carrier_off(c->netdev);netif_tx_disable(c->netdev);
        c80_linux_net_purge(c);
    }
    if(c->wpa2 && !c->cfg_test_only) {
        /* Result is owned by the run thread at this notification point. */
        c->peer_rsn_len=c->peer_rsn?c->peer_rsn[1]+2:0;
    }
    c80_cfg_peer(c,on);
}
static c80_u32 c80_linux_net_dequeue(void *context,c80_u8 *out,c80_u32 capacity)
{
    struct c80_linux *c=context;struct sk_buff *skb;unsigned long flags;c80_u32 len;bool wake;
    spin_lock_irqsave(&c->net_lock,flags);
    skb=c->net_accept?__skb_dequeue(&c->net_queue):NULL;
    wake=c->net_accept && netif_running(c->netdev) && skb_queue_len(&c->net_queue)<C80_NET_QUEUE_N;
    spin_unlock_irqrestore(&c->net_lock,flags);
    if(wake) netif_wake_queue(c->netdev);
    if(!skb) return 0;
    len=skb->len;
    if(len>capacity || skb_copy_bits(skb,0,out,len)) {
        spin_lock_irqsave(&c->net_lock,flags);++c->net_stats.tx_dropped;
        spin_unlock_irqrestore(&c->net_lock,flags);len=0;
    }
    dev_kfree_skb_any(skb);return len;
}
static void c80_linux_net_complete(void *context,c80_u32 bytes)
{
    struct c80_linux *c=context;unsigned long flags;
    spin_lock_irqsave(&c->net_lock,flags);++c->net_stats.tx_packets;c->net_stats.tx_bytes+=bytes;
    spin_unlock_irqrestore(&c->net_lock,flags);
}
static int c80_linux_net_receive(void *context,const c80_u8 *packet,c80_u32 bytes)
{
    struct c80_linux *c=context;struct sk_buff *skb;unsigned long flags;int rc;
    if(!c->netdev || !READ_ONCE(c->net_accept) || !netif_running(c->netdev) ||
       bytes<ETH_HLEN || bytes>C80_NET_ETH_MAX ||
       (c->wpa2 && !READ_ONCE(c->net_authorized) && get_unaligned_be16(packet+12)!=ETH_P_PAE)) goto drop;
    skb=netdev_alloc_skb_ip_align(c->netdev,bytes);if(!skb) goto drop;
    skb_put_data(skb,packet,bytes);skb->protocol=eth_type_trans(skb,c->netdev);
    skb->ip_summed=CHECKSUM_NONE;rc=netif_rx(skb); /* consumes skb on every return */
    if(rc==NET_RX_DROP) goto drop;
    spin_lock_irqsave(&c->net_lock,flags);++c->net_stats.rx_packets;c->net_stats.rx_bytes+=bytes;
    spin_unlock_irqrestore(&c->net_lock,flags);return 0;
drop:
    spin_lock_irqsave(&c->net_lock,flags);++c->net_stats.rx_dropped;
    spin_unlock_irqrestore(&c->net_lock,flags);return -ENOBUFS;
}

static int c80_linux_net_stop_requested(void *context)
{ return READ_ONCE(((struct c80_linux *)context)->net_stop_requested); }
