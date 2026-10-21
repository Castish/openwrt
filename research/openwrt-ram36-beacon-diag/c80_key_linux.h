/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef C80_KEY_LINUX_H
#define C80_KEY_LINUX_H
/* Included inside c80_cfg80211.h, after struct c80_cfg. No wiphy/run mutex is
 * taken by the MCU side; nl80211 may sleep here while the run thread works. */
static int c80_cfg_key_request(struct c80_cfg *a,struct c80_key_request *req)
{
    unsigned long flags;int rc;
    if(!a->owner->wpa2 || !READ_ONCE(a->prepared) || READ_ONCE(a->finished)) return -EOPNOTSUPP;
    if(a->owner->cfg_test_only) return a->owner->key_test(a->owner,req);
    if(!mutex_trylock(&a->key_mutex)) return -EBUSY;
    spin_lock_irqsave(&a->key_lock,flags);
    if(a->key_busy || a->key_serial==U32_MAX) {
        spin_unlock_irqrestore(&a->key_lock,flags);mutex_unlock(&a->key_mutex);return -EBUSY;
    }
    reinit_completion(&a->key_completed);req->serial=++a->key_serial;
    a->key_request=*req;a->key_busy=true;a->key_taken=false;a->key_rc=-EINPROGRESS;
    spin_unlock_irqrestore(&a->key_lock,flags);
    if(!wait_for_completion_timeout(&a->key_completed,msecs_to_jiffies(5000))) {
        /* Do not release/reuse the mailbox after an uncertain MCU timeout. */
        WRITE_ONCE(a->owner->net_stop_requested,true);rc=-ETIMEDOUT;
    } else {
        spin_lock_irqsave(&a->key_lock,flags);rc=a->key_rc;a->key_busy=false;
        memzero_explicit(&a->key_request,sizeof(a->key_request));
        spin_unlock_irqrestore(&a->key_lock,flags);
    }
    mutex_unlock(&a->key_mutex);return rc;
}
static __maybe_unused int c80_linux_key_fetch(void *context,struct c80_key_request *req)
{
    struct c80_linux *c=context;struct c80_cfg *a=c->cfg;unsigned long flags;int found=0;
    if(!a) return 0;
    spin_lock_irqsave(&a->key_lock,flags);
    if(a->key_busy && !a->key_taken) { *req=a->key_request;a->key_taken=true;found=1; }
    spin_unlock_irqrestore(&a->key_lock,flags);return found;
}
static __maybe_unused void c80_linux_key_done(void *context,const struct c80_key_request *req,c80_u32 result)
{
    struct c80_cfg *a=((struct c80_linux *)context)->cfg;unsigned long flags;bool done=false;
    if(!a) return;
    spin_lock_irqsave(&a->key_lock,flags);
    if(a->key_busy && a->key_taken && req->serial==a->key_request.serial) {
        a->key_rc=result?(result==C80_KEY_STATE?-EOPNOTSUPP:-EIO):0;
        memzero_explicit(a->key_request.key,16);done=true;
    }
    spin_unlock_irqrestore(&a->key_lock,flags);
    if(done) complete_all(&a->key_completed);
}
static void c80_cfg_keys_finish(struct c80_cfg *a)
{
    unsigned long flags;bool pending;
    spin_lock_irqsave(&a->key_lock,flags);pending=a->key_busy;
    a->key_rc=-ESHUTDOWN;memzero_explicit(&a->key_request,sizeof(a->key_request));
    memzero_explicit(a->gtk_key,sizeof(a->gtk_key));a->gtk_set=false;a->ptk_set=false;
    WRITE_ONCE(a->owner->net_authorized,false);
    spin_unlock_irqrestore(&a->key_lock,flags);
    if(pending) complete_all(&a->key_completed);
}
static int c80_cfg_add_key(struct wiphy *wiphy,struct net_device *dev,int link_id,
                    u8 index,bool pairwise,const u8 *mac,struct key_params *p)
{
    struct c80_cfg *a=wiphy_priv(wiphy);struct c80_key_request req={};int rc,i;
    if(link_id>0 || p->cipher!=WLAN_CIPHER_SUITE_CCMP || p->key_len!=16 || !p->key ||
       (p->seq_len && (p->seq_len!=6 || !p->seq)) ||
       (pairwise?(index || !mac || !READ_ONCE(a->peer_present) || !ether_addr_equal(mac,a->peer)):
          (index<1 || index>3 || mac))) return -EOPNOTSUPP;
    for(i=0;i<p->seq_len;++i) if(p->seq[i]) return -EOPNOTSUPP;
    req.operation=C80_KEY_ADD;req.pairwise=pairwise;req.index=index;memcpy(req.key,p->key,16);
    if(pairwise) ether_addr_copy(req.peer,mac);
    rc=c80_cfg_key_request(a,&req);memzero_explicit(&req,sizeof(req));
    if(!rc) {
        if(pairwise) WRITE_ONCE(a->ptk_set,true);
        else { a->gtk_index=index;memcpy(a->gtk_key,p->key,16);WRITE_ONCE(a->gtk_set,true); }
    }
    return rc;
}
static int c80_cfg_del_key(struct wiphy *wiphy,struct net_device *dev,int link_id,
                           u8 index,bool pairwise,const u8 *mac)
{
    struct c80_cfg *a=wiphy_priv(wiphy);struct c80_key_request req={};int rc;
    if(link_id>0 || index>3) return -EOPNOTSUPP;
    if(pairwise && (!READ_ONCE(a->ptk_set) || !mac || !ether_addr_equal(mac,a->peer))) return 0;
    if(!pairwise && (!READ_ONCE(a->gtk_set) || index!=a->gtk_index)) return 0;
    req.operation=C80_KEY_DEL;req.pairwise=pairwise;req.index=index;
    if(pairwise) { ether_addr_copy(req.peer,mac);WRITE_ONCE(a->owner->net_authorized,false); }
    rc=c80_cfg_key_request(a,&req);
    if(!rc) { if(pairwise) WRITE_ONCE(a->ptk_set,false);
        else { WRITE_ONCE(a->gtk_set,false);memzero_explicit(a->gtk_key,16); } }
    return rc;
}
static int c80_cfg_get_key(struct wiphy *wiphy,struct net_device *dev,int link_id,
            u8 index,bool pairwise,const u8 *mac,void *cookie,
            void (*callback)(void *,struct key_params *))
{
    struct c80_cfg *a=wiphy_priv(wiphy);u8 seq[6]={};struct key_params p={};
    if(link_id>0 || pairwise || !a->gtk_set || index!=a->gtk_index) return -ENOENT;
    /* All group Ethernet traffic is converted to WCID1 unicast. WCID0 GTK
     * is installed for the handshake but never transmits in this profile,
     * so its RSC is exactly zero. Do not extend this to real multicast TX. */
    p.cipher=WLAN_CIPHER_SUITE_CCMP;p.key=a->gtk_key;p.key_len=16;p.seq=seq;p.seq_len=6;
    callback(cookie,&p);return 0;
}
static int c80_cfg_default_key(struct wiphy *wiphy,struct net_device *dev,int link_id,
                               u8 index,bool unicast,bool multicast)
{
    struct c80_cfg *a=wiphy_priv(wiphy);
    /* WTBL key installation includes the selected key ID. */
    return link_id<=0 && a->gtk_set && index==a->gtk_index?0:-ENOENT;
}
#endif
