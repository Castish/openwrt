/* SPDX-License-Identifier: GPL-2.0-only */
/* Single AP, device SME, CCK/channel6 transport. No encryption is advertised.
 * All MCU/DMA access stays in the run thread; nl80211 uses completions only.
 * Included after the Linux packet callbacks in both real and QEMU adapters. */
#ifndef C80_CFG80211_H
#define C80_CFG80211_H
#include <net/cfg80211.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/unaligned.h>
#define C80_CFG_BEACON_MAX 480u /* 512-byte firmware template minus32-byte TXD. */
struct c80_cfg {
    struct c80_linux *owner;
    struct wireless_dev wdev;
    struct ieee80211_channel channel;
    struct ieee80211_rate rates[4];
    struct ieee80211_supported_band band;
    struct completion started,stopped;
    bool prepared,requested,active,finished,peer_present,authorized;
    u8 peer[ETH_ALEN],ssid[32],beacon[C80_CFG_BEACON_MAX];
    u32 ssid_len,beacon_len,tim_offset;
    unsigned long peer_since;
    struct rtnl_link_stats64 peer_base;
    u32 starts,stops,rejected,peer_adds,peer_deletes;
    int stop_rc;
};
static struct c80_cfg *c80_cfg_from_wiphy(struct wiphy *wiphy)
{ return wiphy_priv(wiphy); }

static int c80_cfg_beacon(struct net_device *dev,const struct cfg80211_beacon_data *b,
                         u8 *out,u32 *bytes,u32 *tim,const u8 *ssid,u32 ssid_len)
{
    const u8 *parts[2]={b->head,b->tail};size_t lengths[2]={b->head_len,b->tail_len};
    size_t k,pos,n;bool found_ssid=false,found_rates=false,found_channel=false;
    if(!b->head || b->head_len<36 || b->head_len>C80_CFG_BEACON_MAX-6 ||
       b->tail_len>C80_CFG_BEACON_MAX-6-b->head_len || (b->tail_len && !b->tail)) return -EINVAL;
    if(get_unaligned_le16(b->head)!=IEEE80211_STYPE_BEACON ||
       !is_broadcast_ether_addr(b->head+4) ||
       !ether_addr_equal(b->head+10,dev->dev_addr) || !ether_addr_equal(b->head+16,dev->dev_addr) ||
       get_unaligned_le16(b->head+32)!=100 || get_unaligned_le16(b->head+34)!=WLAN_CAPABILITY_ESS) return -EOPNOTSUPP;
    for(k=0;k<2;++k) for(pos=k?0:36;pos<lengths[k];pos+=n+2) {
        u8 id;const u8 *p=parts[k]+pos;
        if(lengths[k]-pos<2 || (n=p[1])>lengths[k]-pos-2) return -EINVAL;
        id=p[0];
        if(id==WLAN_EID_SSID) {
            if(found_ssid || n!=ssid_len || memcmp(p+2,ssid,n)) return -EINVAL;
            found_ssid=true;
        } else if(id==WLAN_EID_SUPP_RATES) {
            static const u8 supported[]={0x82,0x84,0x8b,0x96};
            if(found_rates || n!=4 || memcmp(p+2,supported,4)) return -EOPNOTSUPP;
            found_rates=true;
        } else if(id==WLAN_EID_DS_PARAMS) {
            if(found_channel || n!=1 || p[2]!=6) return -EOPNOTSUPP;
            found_channel=true;
        } else if(id==WLAN_EID_TIM || id==WLAN_EID_RSN || id==WLAN_EID_HT_CAPABILITY ||
                  id==WLAN_EID_HT_OPERATION || id==WLAN_EID_VHT_CAPABILITY ||
                  id==WLAN_EID_VHT_OPERATION || id==WLAN_EID_EXT_SUPP_RATES ||
                  id==WLAN_EID_VENDOR_SPECIFIC || id==WLAN_EID_EXTENSION) return -EOPNOTSUPP;
    }
    if(!found_ssid || !found_rates || !found_channel) return -EINVAL;
    memcpy(out,b->head,b->head_len);*tim=b->head_len;
    memcpy(out+*tim,(const u8[]){WLAN_EID_TIM,4,0,1,0,0},6);
    if(b->tail_len) memcpy(out+*tim+6,b->tail,b->tail_len);
    *bytes=b->head_len+6+b->tail_len;return 0;
}

static int c80_cfg_start_ap(struct wiphy *wiphy,struct net_device *dev,
                           struct cfg80211_ap_settings *s)
{
    struct c80_cfg *a=c80_cfg_from_wiphy(wiphy);struct c80_linux *c=a->owner;
    u8 frame[C80_CFG_BEACON_MAX];u32 bytes,tim;int rc;
    if(!s->ssid || !s->ssid_len || s->ssid_len>32 || s->hidden_ssid!=NL80211_HIDDEN_SSID_NOT_IN_USE ||
       s->beacon_interval!=100 || s->dtim_period!=1 || s->privacy || s->crypto.wpa_versions ||
       s->crypto.cipher_group || s->crypto.n_ciphers_pairwise || s->crypto.n_akm_suites ||
       (s->auth_type!=NL80211_AUTHTYPE_OPEN_SYSTEM && s->auth_type!=NL80211_AUTHTYPE_AUTOMATIC) ||
       !s->chandef.chan || s->chandef.chan->center_freq!=2437 ||
       s->chandef.center_freq1!=2437 || s->chandef.center_freq2 ||
       s->chandef.width!=NL80211_CHAN_WIDTH_20_NOHT) { ++a->rejected;return -EOPNOTSUPP; }
    rc=c80_cfg_beacon(dev,&s->beacon,frame,&bytes,&tim,s->ssid,s->ssid_len);
    if(rc) { ++a->rejected;return rc; }
    if(a->requested || a->active || a->finished) return -EALREADY;
    if(!READ_ONCE(a->prepared)) return -EAGAIN;
    memcpy(a->ssid,s->ssid,s->ssid_len);a->ssid_len=s->ssid_len;
    memcpy(a->beacon,frame,bytes);a->beacon_len=bytes;a->tim_offset=tim;
    ++a->starts;smp_store_release(&a->requested,true);
    if(IS_ENABLED(CONFIG_C80_NET_SELFTEST) && c->cfg_test_only) {
        WRITE_ONCE(a->active,true);return 0;
    }
    if(!wait_for_completion_timeout(&a->started,msecs_to_jiffies(10000))) {
        WRITE_ONCE(c->net_stop_requested,true);return -ETIMEDOUT;
    }
    return READ_ONCE(a->active) && !READ_ONCE(a->finished)?0:-EIO;
}
static int c80_cfg_stop_ap(struct wiphy *wiphy,struct net_device *dev,unsigned int link_id)
{
    struct c80_cfg *a=c80_cfg_from_wiphy(wiphy);struct c80_linux *c=a->owner;
    if(link_id) return -EINVAL;
    ++a->stops;
    if(IS_ENABLED(CONFIG_C80_NET_SELFTEST) && c->cfg_test_only) {
        c80_linux_net_link(c,0);WRITE_ONCE(a->active,false);WRITE_ONCE(a->finished,true);return 0;
    }
    WRITE_ONCE(c->net_stop_requested,true);
    if(!wait_for_completion_timeout(&a->stopped,msecs_to_jiffies(20000))) return -ETIMEDOUT;
    return a->stop_rc; /* Completion also reports failed/critical cleanup. */
}
static int c80_cfg_change_beacon(struct wiphy *wiphy,struct net_device *dev,struct cfg80211_ap_update *s)
{
    struct c80_cfg *a=c80_cfg_from_wiphy(wiphy);u8 frame[C80_CFG_BEACON_MAX];u32 n,tim;int rc;
    rc=c80_cfg_beacon(dev,&s->beacon,frame,&n,&tim,a->ssid,a->ssid_len);
    if(rc) return rc;
    /* This first control port freezes the offloaded template for this run. */
    return n==a->beacon_len && tim==a->tim_offset && !memcmp(frame,a->beacon,n)?0:-EOPNOTSUPP;
}
static int c80_cfg_change_iface(struct wiphy *wiphy,struct net_device *dev,
                               enum nl80211_iftype type,struct vif_params *params)
{ return type==NL80211_IFTYPE_AP?0:-EOPNOTSUPP; }
static int c80_cfg_change_bss(struct wiphy *wiphy,struct net_device *dev,struct bss_parameters *p)
{
    static const u8 rates[4]={2,4,11,22};
    if(p->use_short_preamble>0 || p->use_short_slot_time>0 || p->use_cts_prot>0 || p->ap_isolate>0 ||
       p->ht_opmode>=0 || (p->basic_rates_len && (p->basic_rates_len!=4 || memcmp(p->basic_rates,rates,4)))) return -EOPNOTSUPP;
    return 0;
}
static int c80_cfg_get_channel(struct wiphy *wiphy,struct wireless_dev *wdev,
                              unsigned int link_id,struct cfg80211_chan_def *chandef)
{
    if(link_id) return -EINVAL;
    cfg80211_chandef_create(chandef,&c80_cfg_from_wiphy(wiphy)->channel,NL80211_CHAN_NO_HT);return 0;
}
static int c80_cfg_station(struct wiphy *wiphy,struct net_device *dev,const u8 *mac,struct station_info *s)
{
    struct c80_cfg *a=c80_cfg_from_wiphy(wiphy);struct rtnl_link_stats64 st,base;
    unsigned long flags,since;
    spin_lock_irqsave(&a->owner->net_lock,flags);
    if(!a->peer_present || !ether_addr_equal(mac,a->peer)) {
        spin_unlock_irqrestore(&a->owner->net_lock,flags);return -ENOENT;
    }
    st=a->owner->net_stats;base=a->peer_base;since=a->peer_since;
    spin_unlock_irqrestore(&a->owner->net_lock,flags);
    s->filled=BIT_ULL(NL80211_STA_INFO_RX_PACKETS)|BIT_ULL(NL80211_STA_INFO_TX_PACKETS)|
        BIT_ULL(NL80211_STA_INFO_RX_BYTES64)|BIT_ULL(NL80211_STA_INFO_TX_BYTES64)|
        BIT_ULL(NL80211_STA_INFO_CONNECTED_TIME)|BIT_ULL(NL80211_STA_INFO_STA_FLAGS);
    s->rx_packets=st.rx_packets-base.rx_packets;s->tx_packets=st.tx_packets-base.tx_packets;
    s->rx_bytes=st.rx_bytes-base.rx_bytes;s->tx_bytes=st.tx_bytes-base.tx_bytes;
    s->connected_time=jiffies_to_msecs(jiffies-since)/1000;
    s->sta_flags.mask=BIT(NL80211_STA_FLAG_AUTHENTICATED)|BIT(NL80211_STA_FLAG_ASSOCIATED)|BIT(NL80211_STA_FLAG_AUTHORIZED);
    s->sta_flags.set=s->sta_flags.mask;
    if(!READ_ONCE(a->authorized)) s->sta_flags.set&=~BIT(NL80211_STA_FLAG_AUTHORIZED);
    return 0;
}
static int c80_cfg_dump_station(struct wiphy *wiphy,struct net_device *dev,int idx,u8 *mac,struct station_info *s)
{
    struct c80_cfg *a=c80_cfg_from_wiphy(wiphy);
    if(idx || !READ_ONCE(a->peer_present)) return -ENOENT;
    ether_addr_copy(mac,a->peer);return c80_cfg_station(wiphy,dev,mac,s);
}
static int c80_cfg_change_station(struct wiphy *wiphy,struct net_device *dev,const u8 *mac,struct station_parameters *p)
{
    struct c80_cfg *a=c80_cfg_from_wiphy(wiphy);
    unsigned long flags;
    u32 allowed=BIT(NL80211_STA_FLAG_AUTHENTICATED)|BIT(NL80211_STA_FLAG_ASSOCIATED)|BIT(NL80211_STA_FLAG_AUTHORIZED);
    if(!READ_ONCE(a->peer_present) || !ether_addr_equal(mac,a->peer)) return -ENOENT;
    if(p->sta_flags_set&~allowed || p->vlan || p->plink_action) return -EOPNOTSUPP;
    if(p->sta_flags_mask&~p->sta_flags_set&
       (BIT(NL80211_STA_FLAG_AUTHENTICATED)|BIT(NL80211_STA_FLAG_ASSOCIATED))) return -EOPNOTSUPP;
    if(p->sta_flags_mask&BIT(NL80211_STA_FLAG_AUTHORIZED)) {
        WRITE_ONCE(a->authorized,!!(p->sta_flags_set&BIT(NL80211_STA_FLAG_AUTHORIZED)));
        spin_lock_irqsave(&a->owner->net_lock,flags);
        WRITE_ONCE(a->owner->net_accept,READ_ONCE(a->authorized));
        spin_unlock_irqrestore(&a->owner->net_lock,flags);
    }
    return 0;
}
static int c80_cfg_del_station(struct wiphy *wiphy,struct net_device *dev,struct station_del_parameters *p)
{
    struct c80_cfg *a=c80_cfg_from_wiphy(wiphy);
    if(!READ_ONCE(a->peer_present)) return 0;
    /* Peer-initiated frames use the run-thread session state machine.
     * Operator-initiated kick/deauth through nl80211 is not implemented. */
    return -EOPNOTSUPP;
}
/* hostapd's generic nl80211 initialization requires the CONNECT command in
 * GET_WIPHY even for an AP-only device. Station interfaces are never exposed;
 * this entry rejects that operation rather than claiming a connection. */
static int c80_cfg_station_connect_unsupported(struct wiphy *wiphy,struct net_device *dev,
                                              struct cfg80211_connect_params *params)
{ return -EOPNOTSUPP; }
static int c80_cfg_station_disconnect_unsupported(struct wiphy *wiphy,struct net_device *dev,u16 reason)
{ return -EOPNOTSUPP; }
static const struct cfg80211_ops c80_cfg_ops={
    .change_virtual_intf=c80_cfg_change_iface,.start_ap=c80_cfg_start_ap,
    .stop_ap=c80_cfg_stop_ap,.change_beacon=c80_cfg_change_beacon,
    .change_bss=c80_cfg_change_bss,.get_channel=c80_cfg_get_channel,
    .get_station=c80_cfg_station,.dump_station=c80_cfg_dump_station,
    .change_station=c80_cfg_change_station,.del_station=c80_cfg_del_station,
    .connect=c80_cfg_station_connect_unsupported,
    .disconnect=c80_cfg_station_disconnect_unsupported,
};
static int c80_cfg_attach(struct c80_linux *c,struct net_device *dev,const u8 *mac)
{
    struct wiphy *wiphy;struct c80_cfg *a;int rc;unsigned i;
    static const int bitrates[4]={10,20,55,110};
    wiphy=wiphy_new(&c80_cfg_ops,sizeof(*a));if(!wiphy) return -ENOMEM;
    a=wiphy_priv(wiphy);a->owner=c;
    init_completion(&a->started);init_completion(&a->stopped);
    a->channel=(struct ieee80211_channel){.band=NL80211_BAND_2GHZ,.center_freq=2437,.hw_value=6,.max_power=20};
    for(i=0;i<4;++i) a->rates[i]=(struct ieee80211_rate){.bitrate=bitrates[i],.hw_value=i};
    a->band=(struct ieee80211_supported_band){.channels=&a->channel,.n_channels=1,.bitrates=a->rates,.n_bitrates=4};
    set_wiphy_dev(wiphy,c->dev);ether_addr_copy(wiphy->perm_addr,mac);
    wiphy->bands[NL80211_BAND_2GHZ]=&a->band;wiphy->interface_modes=BIT(NL80211_IFTYPE_AP);
    wiphy->flags|=WIPHY_FLAG_HAVE_AP_SME;wiphy->signal_type=CFG80211_SIGNAL_TYPE_MBM;
    wiphy->max_ap_assoc_sta=1;
    wiphy->available_antennas_tx=1;wiphy->available_antennas_rx=1;
    rc=wiphy_register(wiphy);if(rc) { wiphy_free(wiphy);return rc; }
    a->wdev.wiphy=wiphy;a->wdev.netdev=dev;a->wdev.iftype=NL80211_IFTYPE_AP;
    dev->ieee80211_ptr=&a->wdev;c->cfg=a;
    if(IS_ENABLED(CONFIG_C80_NET_SELFTEST) && c->cfg_test_only) WRITE_ONCE(a->prepared,true);
    return 0;
}
static void c80_cfg_detach(struct c80_linux *c)
{
    struct c80_cfg *a=c->cfg;if(!a) return;
    wiphy_unregister(a->wdev.wiphy);wiphy_free(a->wdev.wiphy);c->cfg=NULL;
}
static void c80_cfg_peer(struct c80_linux *c,int on)
{
    struct c80_cfg *a=c->cfg;struct station_info s={};unsigned long flags;
    if(!a || !READ_ONCE(a->active)) return;
    if(on && !a->peer_present && c->peer_address) {
        spin_lock_irqsave(&c->net_lock,flags);
        a->peer_base=c->net_stats;
        ether_addr_copy(a->peer,c->peer_address);a->peer_since=jiffies;
        WRITE_ONCE(a->authorized,true);WRITE_ONCE(a->peer_present,true);++a->peer_adds;
        spin_unlock_irqrestore(&c->net_lock,flags);
        c80_cfg_station(a->wdev.wiphy,c->netdev,a->peer,&s);
        cfg80211_new_sta(c->netdev,a->peer,&s,GFP_KERNEL);
    } else if(!on && a->peer_present) {
        spin_lock_irqsave(&c->net_lock,flags);
        WRITE_ONCE(a->peer_present,false);WRITE_ONCE(a->authorized,false);++a->peer_deletes;
        spin_unlock_irqrestore(&c->net_lock,flags);
        cfg80211_del_sta(c->netdev,a->peer,GFP_KERNEL);
    }
}
#endif
