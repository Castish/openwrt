/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef C80_SECURITY_CORE_H
#define C80_SECURITY_CORE_H
/* Only the single MCU thread touches this state or sends a command. Key
 * requests arrive from cfg80211 through a bounded completion mailbox. */
static c80_u32 c80_security_exchange(struct c80_io *io,struct c80_result *r,
                                     c80_u32 ext,const c80_u8 *body,c80_u32 bytes)
{
    struct c80_security_result *s=&r->security;c80_u32 status=~0u,rc;
    if(!io->wpa2_test || !r->main_ready || (r->phase!=37 && r->phase!=38) || s->waiting)
        return C80_KEY_STATE;
    s->extension=ext;s->valid=0;s->status=~0u;s->waiting=1;
    rc=c80_exchange(io,r,0xed,body,bytes,&status);s->waiting=0;
    if(rc) return rc;
    if(!s->valid || status) return C80_KEY_REJECTED;
    return 0;
}
static void c80_security_bmc_payload(struct c80_io *io,c80_u8 *body,c80_u32 off)
{
    c80_u32 i;c80_sta_payload(io,body,off);
    body[1]=0;c80_put32(body+12,0x10020);c80_put16(body+18,0);
    for(i=0;i<6;++i) body[20+i]=255;
    if(!off) {
        body[32]=0;for(i=0;i<6;++i) body[44+i]=255;
        body[50]=14;body[56]=0;body[65]=1;body[117]=0;
    }
}
static c80_u32 c80_security_bmc(struct c80_io *io,struct c80_result *r,c80_u32 off)
{
    c80_u8 body[244];c80_u32 rc;
    c80_security_bmc_payload(io,body,off);
    rc=c80_security_exchange(io,r,0x25,body,off?28:244);
    if(!rc) r->security.bmc_live=!off;
    return rc;
}
static c80_u32 c80_security_key(struct c80_io *io,struct c80_result *r,
                              c80_u32 wcid,c80_u32 index,const c80_u8 *key,c80_u32 remove)
{
    c80_u8 body[52];c80_u32 i,k,rc=0;
    for(k=0;k<(remove?2u:1u);++k) {
        for(i=0;i<52;++i) body[i]=0;
        body[0]=wcid;body[1]=2;c80_put16(body+2,1);
        c80_put16(body+8,7);c80_put16(body+10,44);
        body[12]=!!remove;body[13]=!remove;body[15]=remove && !k?10:4;
        body[16]=remove?0:index;body[17]=remove?32:16;
        if(!remove) for(i=0;i<16;++i) body[20+i]=key[i];
        rc=c80_security_exchange(io,r,0x32,body,52);
        c80_secret_clear(body,sizeof(body));
        if(rc) return rc;
    }
    return 0;
}
static c80_u32 c80_security_authorize(struct c80_io *io,struct c80_result *r,c80_u32 on)
{
    c80_u8 body[28];c80_u32 rc;
    c80_sta_payload(io,body,1);body[16]=on?2:1;
    rc=c80_security_exchange(io,r,0x25,body,28);
    if(!rc) { r->security.authorized=on;if(on) ++r->security.authorizations; }
    return rc;
}
static int c80_security_key_equal(const c80_u8 *a,const c80_u8 *b)
{ c80_u32 i,diff=0;for(i=0;i<16;++i) diff|=a[i]^b[i];return !diff; }
static void c80_security_peer_clear(struct c80_security_result *s)
{
    s->ptk=0;s->authorized=0;c80_secret_clear(s->ptk_key,16);
    c80_secret_clear(s->rx_pn,sizeof(s->rx_pn));
}
static c80_u32 c80_security_forget_peer(struct c80_io *io,struct c80_result *r)
{
    struct c80_security_result *s=&r->security;c80_u32 rc=0;
    s->authorized=0;
    if(s->ptk) rc=c80_security_key(io,r,1,0,0,1);
    if(!rc) c80_security_peer_clear(s);
    return rc;
}
static c80_u32 c80_security_step(struct c80_io *io,struct c80_result *r)
{
    struct c80_security_result *s=&r->security;struct c80_key_request req;
    c80_u32 rc=0,refused=0,pair,i; c80_u8 *saved;
    if(!io->wpa2_test || r->net.inflight || !io->key_fetch(io->context,&req)) return 0;
    pair=req.pairwise;saved=pair?s->ptk_key:s->gtk_key;
    if(req.operation==C80_KEY_ADD) {
        if((pair && (!r->net.linked || !r->session.sta_live || req.index ||
                    !c80_mac_equal(req.peer,c80_current_peer(io)))) ||
           (!pair && (req.index<1 || req.index>3))) refused=1;
        else if(pair?s->ptk:s->gtk) {
            /* Never reinstall an identical live key: this would reset the
             * hardware TX PN and expose replay/nonce reuse. Changed live
             * keys need a checked delete first in this initial profile. */
            if((pair || req.index==s->gtk_index) && c80_security_key_equal(saved,req.key)) ++s->key_idempotent;
            else refused=1;
        } else {
            if(!pair && !s->bmc_live) rc=c80_security_bmc(io,r,0);
            if(!rc) rc=c80_security_key(io,r,pair?1:0,req.index,req.key,0);
            if(!rc) {
                for(i=0;i<16;++i) saved[i]=req.key[i];
                if(pair) { s->ptk=1;c80_secret_clear(s->rx_pn,sizeof(s->rx_pn)); }
                else { s->gtk=1;s->gtk_index=req.index; }
                ++s->key_adds;
            }
        }
    } else if(req.operation==C80_KEY_DEL) {
        if(pair) { rc=c80_security_forget_peer(io,r);if(!rc) ++s->key_deletes; }
        else if(s->gtk && req.index==s->gtk_index) {
            rc=c80_security_key(io,r,0,req.index,0,1);
            if(!rc) { s->gtk=0;c80_secret_clear(s->gtk_key,16);++s->key_deletes; }
        }
    } else if(req.operation==C80_KEY_AUTHORIZE || req.operation==C80_KEY_UNAUTHORIZE) {
        if(!r->net.linked || !c80_mac_equal(req.peer,c80_current_peer(io)) ||
           (req.operation==C80_KEY_AUTHORIZE && (!s->ptk || !s->gtk))) refused=1;
        else if(s->authorized!=(req.operation==C80_KEY_AUTHORIZE))
            rc=c80_security_authorize(io,r,req.operation==C80_KEY_AUTHORIZE);
    } else refused=1;
    if(refused) ++s->refused;
    io->key_done(io->context,&req,rc?rc:refused?C80_KEY_STATE:0);
    c80_secret_clear(&req,sizeof(req));return rc;
}
static c80_u32 c80_security_stop(struct c80_io *io,struct c80_result *r)
{
    struct c80_security_result *s=&r->security;c80_u32 rc;
    rc=c80_security_forget_peer(io,r);if(rc) return rc;
    if(s->gtk) {
        rc=c80_security_key(io,r,0,s->gtk_index,0,1);if(rc) return rc;
        s->gtk=0;c80_secret_clear(s->gtk_key,16);
    }
    if(s->bmc_live) { rc=c80_security_bmc(io,r,1);if(rc) return rc; }
    c80_secret_clear(s->assoc_rsn,sizeof(s->assoc_rsn));s->assoc_rsn_bytes=0;
    return 0;
}
#endif
