/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef C80_SESSION_CORE_H
#define C80_SESSION_CORE_H
/* One open client at a time. This state machine runs ONLY in the MCU thread.
 * RX records bounded intentions; it never sends a command recursively or
 * overwrites a DMA-owned response. The AP/beacon remains alive between peers.
 * The hardware-proven initial auth/association stays unchanged. Subsequent
 * replies use the same paired-completion ring/payload/token ledger as data. */
static void c80_session_promote(struct c80_result *r)
{
    struct c80_session_result *s=&r->session;
    if(!s->started && r->net.linked) {
        s->started=1;s->state=C80_SESSION_CONNECTED;
        s->connections=1;s->epoch_linked=1;s->authenticated=1;
    }
}
static int c80_session_assoc_valid(struct c80_io *io,struct c80_result *r,const c80_u8 *p,c80_u32 bytes)
{
    c80_u32 sub=(c80_get16(p)>>4)&15,offset=sub==2?34:28,i,count,mask=0,rate,n;
    const c80_u8 *ssid=c80_ap_ssid(io,&n);
    if((sub!=0 && sub!=2) || bytes<offset+2 || (c80_get16(p+24)&0x13)!=(io->wpa2_test?0x11u:1u) ||
       !c80_get16(p+26) || !ssid || !n || n>32 ||
       (sub==2 && !c80_mac_equal(p+28,io->pool->nvm_payload+8)) ||
       p[offset] || p[offset+1]!=n || n>bytes-offset-2) return 0;
    for(i=0;i<n;++i) if(p[offset+2+i]!=ssid[i]) return 0;
    offset+=2+n;
    if(bytes-offset<2 || p[offset]!=1 || !(count=p[offset+1]) || count>8 || count>bytes-offset-2) return 0;
    for(i=0;i<count;++i) {
        rate=p[offset+2+i]&127;
        if(rate==2) mask|=1;else if(rate==4) mask|=2;else if(rate==11) mask|=4;else if(rate==22) mask|=8;
    }
    return mask==15 && c80_security_assoc_ie(io,r,p,bytes,offset+count+2);
}
static void c80_session_receive(struct c80_io *io,struct c80_result *r,const c80_u8 *p,c80_u32 bytes)
{
    struct c80_session_result *s=&r->session;struct c80_management_counts *m=&r->management[1];
    c80_u32 sub,seq,i;const c80_u8 *peer=c80_current_peer(io);
    if(!io->session_test || r->phase!=37 || bytes<24) return;
    sub=(c80_get16(p)>>4)&15;seq=c80_get16(p+22);
    c80_session_promote(r);
    if(sub==11) {
        if(bytes<30) { ++s->bad;++m->short_header;return; }
        ++m->auth_to_us;
        if(c80_get16(p+24) || c80_get16(p+26)!=1 || c80_get16(p+28))
            { ++m->auth_other;++s->bad;return; }
        ++m->auth_open_request;++s->auth_requests;
        if(!s->started) {
            if(!r->auth_captured) s->last_auth_seq=seq;
            c80_auth_capture(io,r,p+10);return;
        }
        /* A different client cannot replace a still-associated one. Once the
         * known peer disconnects, the single vacant WCID can accept a new one. */
        if(s->state!=C80_SESSION_IDLE && !c80_mac_equal(p+10,peer)) { ++s->foreign;return; }
        if(seq==s->last_auth_seq &&
           ((s->state==C80_SESSION_CONNECTED && (c80_get16(p)&0x800)) ||
            s->state==C80_SESSION_AUTH_TX || s->state==C80_SESSION_ASSOC_WAIT || s->state==C80_SESSION_ASSOC_TX))
            { ++s->duplicates;return; }
        if(s->pending_auth) { ++s->duplicates;return; }
        for(i=0;i<6;++i) io->pool->session_pending_peer[i]=p[10+i];
        s->pending_auth_seq=seq;s->pending_auth=1;
        return;
    }
    if(sub==0 || sub==2) {
        if(sub==0) { ++m->assoc_to_us;++s->assoc_requests; }
        else { ++m->reassoc_to_us;++s->reassoc_requests; }
        if(!s->started) {
            if(sub==0) c80_assoc_capture(io,r,p,bytes);
            return;
        }
        if(!c80_mac_equal(p+10,peer)) { ++s->foreign;return; }
        if(!c80_session_assoc_valid(io,r,p,bytes)) { ++s->bad;return; }
        if((s->state==C80_SESSION_DRAIN || s->state==C80_SESSION_IDLE) && !s->authenticated) return;
        if(s->pending_assoc || s->state==C80_SESSION_ASSOC_TX) { ++s->duplicates;return; }
        s->pending_assoc=sub==2?C80_REPLY_REASSOC:C80_REPLY_ASSOC;
        r->net.session_pause=1;
        if(s->state==C80_SESSION_IDLE) s->state=C80_SESSION_ASSOC_WAIT;
        return;
    }
    if(sub==10 || sub==12) {
        if(bytes<26) { ++s->bad;++m->short_header;return; }
        if(sub==10) { ++m->disassoc_to_us;++s->disassoc_requests; }
        else { ++m->deauth_to_us;++s->deauth_requests; }
        if(!s->started) return;
        if(!c80_mac_equal(p+10,peer)) { ++s->foreign;return; }
        if(!c80_get16(p+24)) { ++s->bad;return; }
        if(sub==12) s->authenticated=0;
        s->last_reason=c80_get16(p+24);s->drop_requested=1;
    }
}
static void c80_session_clear_peer_result(struct c80_result *r,int keep_auth)
{
    c80_u32 i;
    if(!keep_auth) r->auth_captured=r->auth_submitted=r->auth_dma_done=r->auth_token_returned=0;
    r->assoc_captured=r->assoc_submitted=r->assoc_dma_done=r->assoc_token_returned=0;
    r->assoc_complete=0;
    for(i=0;i<2;++i) { r->sta_attempted[i]=r->sta_valid[i]=r->sta_status[i]=0; }
    r->net.seq_valid=0;
}
static void c80_session_begin_auth(struct c80_io *io,struct c80_result *r)
{
    struct c80_session_result *s=&r->session;c80_u32 i;
    for(i=0;i<6;++i) io->pool->session_peer[i]=io->pool->session_pending_peer[i];
    c80_session_clear_peer_result(r,0);
    s->authenticated=0;
    s->last_auth_seq=s->pending_auth_seq;s->pending_auth=0;
    s->pending_assoc=0;s->reply_done=0;s->reply_kind=C80_REPLY_AUTH;
    s->state=C80_SESSION_AUTH_TX;s->epoch_linked=0;
    r->auth_captured=1;r->net.session_pause=1;r->net.management_pending=C80_REPLY_AUTH;
}
static c80_u32 c80_session_step(struct c80_io *io,struct c80_result *r)
{
    struct c80_session_result *s=&r->session;struct c80_net_result *n=&r->net;c80_u32 rc;
    if(!io->session_test) return 0;
    if(n->token_fault) return C80_NET_TOKEN;
    c80_session_promote(r);
    if(!s->started) {
        rc=c80_auth_poll(io,r);if(rc) return rc;
        return c80_assoc_step(io,r);
    }
    if(s->drop_requested || (s->pending_auth && s->state!=C80_SESSION_DRAIN && s->state!=C80_SESSION_IDLE)) {
        s->drop_requested=0;
        if(s->pending_auth || !s->authenticated) s->pending_assoc=0;
        n->management_pending=0;n->session_pause=1;
        if(s->state!=C80_SESSION_DRAIN) {
            if(s->epoch_linked) ++s->disconnects;else ++s->aborted;
            s->state=C80_SESSION_DRAIN;
        }
        if(n->linked) { n->linked=0;io->net_link(io->context,0); }
    }
    if(s->state==C80_SESSION_DRAIN) {
        if(n->inflight) return 0;
        if(io->wpa2_test) { rc=c80_security_forget_peer(io,r);if(rc) return rc; }
        if(s->sta_live) { rc=c80_sta_exchange(io,r,1);if(rc) return rc; }
        s->reply_done=0;s->reply_kind=0;s->state=C80_SESSION_IDLE;s->epoch_linked=0;
        /* Never clear the management/data completion ledger, ring indices,
         * command generation, tokens or backing DMA packets between peers. */
        c80_session_clear_peer_result(r,s->authenticated);
        if(s->authenticated && s->pending_assoc && !s->pending_auth) s->state=C80_SESSION_ASSOC_WAIT;
    }
    if(s->state==C80_SESSION_IDLE) {
        if(s->pending_auth) c80_session_begin_auth(io,r);
        return 0;
    }
    if(s->state==C80_SESSION_AUTH_TX) {
        if(!s->reply_done) return 0;
        if(s->reply_done!=C80_REPLY_AUTH) return C80_SESSION_STATE;
        s->reply_done=0;s->state=C80_SESSION_ASSOC_WAIT;
    }
    if(s->state==C80_SESSION_ASSOC_TX) {
        if(!s->reply_done) return 0;
        if(s->reply_done!=C80_REPLY_ASSOC && s->reply_done!=C80_REPLY_REASSOC) return C80_SESSION_STATE;
        s->reply_done=0;s->state=C80_SESSION_CONNECTED;n->session_pause=0;
        if(!s->epoch_linked) {
            if(s->connections==0xffffffffu) return C80_COMMAND_COUNTER;
            ++s->connections;s->epoch_linked=1;
            n->linked=1;io->net_link(io->context,1);
        }
    }
    if((s->state==C80_SESSION_ASSOC_WAIT || s->state==C80_SESSION_CONNECTED) && s->pending_assoc) {
        if(n->inflight) return 0;
        if(!r->auth_submitted || !r->auth_dma_done || !r->auth_token_returned) return C80_SESSION_STATE;
        r->assoc_captured=1;
        if(!s->sta_live) { rc=c80_sta_exchange(io,r,0);if(rc) return rc; }
        /* Runtime duplicate/reassociation response keeps the same station.
         * Do not report NEW_STA twice or reset data/token generations. */
        s->reply_kind=s->pending_assoc;s->pending_assoc=0;s->reply_done=0;
        s->state=C80_SESSION_ASSOC_TX;n->session_pause=1;
        r->assoc_submitted=r->assoc_dma_done=r->assoc_token_returned=0;
        n->management_pending=s->reply_kind;
    }
    return 0;
}
static c80_u32 c80_session_build(struct c80_io *io,struct c80_result *r,
                                 c80_u32 index,c80_u32 token,c80_u32 sequence,c80_u32 kind)
{
    static const c80_u8 auth[32]={0x3e,0,0,0x40,0,0xcc,0,0,0,0,0,0xa0,0,0x38,0,0,
        0,0,0,0,0,0x20,0,0,4,0,0,0,0,0xc0,0x0b,0};
    static const c80_u8 assoc[32]={0x44,0,0,0x40,1,0xcc,0,0,0,0,0,0xa0,0,0x38,0,0,
        0,0,0,0,0,0x20,0,0,4,0,0,0,0,0xc0,1,0};
    struct c80_session_result *s=&r->session;struct c80_net_cell *cell;
    const c80_u8 *peer=c80_current_peer(io),*own=io->pool->nvm_payload+8;
    c80_u8 *f,*h;c80_u32 i,bytes=kind==C80_REPLY_AUTH?30u:36u;
    if(!io->session_test || !s->started || r->phase!=37 || index>=C80_NET_RECYCLE_N ||
       token<C80_NET_TOKEN_BASE || token>=4096 || sequence>=4096 ||
       kind<1 || kind>3 || kind!=s->reply_kind || !r->net.session_pause ||
       r->net.inflight || r->net.closed || !c80_mac_valid(peer) || c80_mac_equal(peer,own)) return 0;
    if(kind==C80_REPLY_AUTH) {
        if(s->state!=C80_SESSION_AUTH_TX || s->sta_live) return 0;
    } else if(s->state!=C80_SESSION_ASSOC_TX || !s->sta_live ||
              !r->sta_valid[0] || r->sta_status[0] || r->sta_attempted[1]) return 0;
    cell=&io->pool->net.tx[index];f=cell->frame;h=cell->header;
    for(i=0;i<48;++i) f[i]=0;
    c80_put16(f,kind==C80_REPLY_AUTH?0xb0:kind==C80_REPLY_REASSOC?0x30:0x10);
    c80_put16(f+2,304);c80_put16(f+22,sequence<<4);
    for(i=0;i<6;++i) { f[4+i]=peer[i];f[10+i]=f[16+i]=own[i]; }
    if(kind==C80_REPLY_AUTH) c80_put16(f+26,2);
    else {
        c80_put16(f+24,io->wpa2_test?0x11:1);c80_put16(f+28,0xc001);
        f[30]=1;f[31]=4;f[32]=0x82;f[33]=0x84;f[34]=0x8b;f[35]=0x96;
    }
    for(i=0;i<64;++i) h[i]=i<32?(kind==C80_REPLY_AUTH?auth[i]:assoc[i]):0;
    if(kind==C80_REPLY_REASSOC) h[30]=3;
    c80_put16(h,32+bytes);c80_put16(h+32,0x8000|token);
    c80_put32(h+40,c80_dma_address(io,f));c80_put16(h+44,0x8000|bytes);
    return bytes;
}
static void c80_session_tx_complete(struct c80_io *io,struct c80_result *r,c80_u32 kind)
{
    struct c80_session_result *s=&r->session;struct c80_net_result *n=&r->net;
    if(!io->session_test || !s->started || kind!=s->reply_kind ||
       n->inflight || n->token[(n->completed-1u)%C80_NET_RECYCLE_N]!=7u) {
        n->token_fault=1;return;
    }
    s->reply_done=kind;
    if(kind==C80_REPLY_AUTH) {
        r->auth_submitted=r->auth_dma_done=r->auth_token_returned=1;
        s->authenticated=1;
        r->auth_ctrl=n->last_ctrl;r->auth_cpu_readback=n->last_cpu;r->auth_dma_index=n->last_dma;
    } else {
        r->assoc_submitted=r->assoc_dma_done=r->assoc_token_returned=1;
        r->assoc_ctrl=n->last_ctrl;r->assoc_cpu_readback=n->last_cpu;r->assoc_dma_index=n->last_dma;
    }
}
#endif
