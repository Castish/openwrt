/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef C80_NET_CORE_H
#define C80_NET_CORE_H
/* Included after the shared byte/MAC/DMA helpers. This transport converts
 * validated Ethernet frames; ARP, ICMP, UDP and TCP belong to Linux. */
static void c80_net_close(struct c80_io *io,struct c80_result *r)
{
    struct c80_net_result *n=&r->net;
    if(!n->prepared || n->closed) return;
    n->closed=1;
    io->net_link(io->context,0);
}
static int c80_net_token_in_range(const struct c80_result *r,c80_u32 token)
{
    return r->net.enabled && token>=C80_NET_TOKEN_BASE &&
        token-C80_NET_TOKEN_BASE<(r->net.recycling?C80_NET_TOKEN_COUNT:C80_NET_TX_N);
}
static void c80_net_free(struct c80_result *r,c80_u32 token)
{
    struct c80_net_result *n=&r->net; c80_u32 index=token-C80_NET_TOKEN_BASE;
    if(n->recycling) {
        if(!c80_net_token_in_range(r,token)) return;
        if(!n->inflight || n->inflight>C80_NET_RECYCLE_N || token!=n->active_token) {
            ++n->stale_tokens;++n->early_tokens;++r->txfree_before_submit;
            n->token_fault=1;return;
        }
        index=n->inflight-1;
        if(!(n->token[index]&C80_NET_SUBMITTED) || (n->token[index]&C80_NET_RETURNED)) {
            ++n->duplicate_tokens;++r->txfree_duplicate;n->token_fault=1;return;
        }
        n->token[index]|=C80_NET_RETURNED;++n->returned;++r->txfree_ours;return;
    }
    if(index>=C80_NET_TX_N) return;
    if(!(n->token[index]&C80_NET_SUBMITTED)) {
        ++n->early_tokens; ++r->txfree_before_submit; ++r->txfree_foreign;
        return;
    }
    if(n->token[index]&C80_NET_RETURNED) {
        ++n->duplicate_tokens; ++r->txfree_duplicate; return;
    }
    n->token[index]|=C80_NET_RETURNED; ++n->returned; ++r->txfree_ours;
}
/* Protocol length removes any trailing DMA padding/FCS, without assuming it
 * was stripped by hardware. Do not deliver unbounded trailing bytes to Linux.
 * Checksums and IP addressing are handled by the receiving Linux stack. */
static c80_u32 c80_net_payload(c80_u32 type,const c80_u8 *p,c80_u32 bytes)
{
    c80_u32 len,ihl;
    if(type==0x806) {
        if(bytes<28 || c80_be16(p)!=1 || c80_be16(p+2)!=0x800 ||
           p[4]!=6 || p[5]!=4 || (c80_be16(p+6)!=1 && c80_be16(p+6)!=2)) return 0;
        return 28;
    }
    if(type!=0x800 || bytes<20 || (p[0]>>4)!=4) return 0;
    ihl=(p[0]&15)*4; len=c80_be16(p+2);
    if(ihl<20 || ihl>60 || len<ihl || len>bytes || len>C80_NET_MTU ||
       (c80_be16(p+6)&~0x4000u)) return 0; /* First adapter: no IP fragments. */
    return len;
}
static void c80_net_receive(struct c80_io *io,struct c80_result *r,
                            const c80_u8 *v,c80_u32 total,c80_u32 offset)
{
    struct c80_net_result *n=&r->net;
    const c80_u8 *p,*da,*sa,*payload,*peer=io->pool->auth_frame+4,*own=io->pool->nvm_payload+8;
    c80_u8 *eth=io->pool->net.ethernet;
    c80_u32 bytes,fc,seq,qos=0,sub,header,type,len,tid,i;
    if(!io->netdev_test || !n->linked || n->closed || r->phase!=37 ||
       !r->assoc_dma_done || !r->assoc_token_returned || !r->sta_valid[0] ||
       r->sta_status[0] || r->sta_attempted[1]) return;
    if(total<16 || total>C80_RX_SIZE || offset<16 || offset>total) { ++n->rx_bad_length;return; }
    bytes=total-offset; p=v+offset;
    if(v[6]&0x80) {
        ++n->rx_translated;
        if(!(v[3]&0x10) || offset<32 || bytes<14) { ++n->rx_bad_length;return; }
        fc=c80_get16(v+16);seq=c80_get16(v+24);qos=c80_get16(v+26);
        if(!c80_mac_equal(v+18,peer)) { ++n->rx_wrong_peer;return; }
        da=p;sa=p+6;type=c80_be16(p+12);payload=p+14;bytes-=14;
    } else {
        if(bytes<2) { ++n->rx_bad_length;return; }
        fc=c80_get16(p);sub=(fc>>4)&15;
        if((fc&15)!=8 || (sub!=0 && sub!=8)) return;
        ++n->rx_raw;header=sub==8?26:24;
        if(bytes<header+8) { ++n->rx_bad_length;return; }
        if(!c80_mac_equal(p+4,own)) { ++n->rx_wrong_peer;return; }
        seq=c80_get16(p+22);if(sub==8) qos=c80_get16(p+24);
        da=p+16;sa=p+10;payload=p+header;bytes-=header;
        if(payload[0]!=0xaa || payload[1]!=0xaa || payload[2]!=3 ||
           payload[3] || payload[4] || payload[5]) { ++n->rx_bad_format;return; }
        type=c80_be16(payload+6);payload+=8;bytes-=8;
    }
    sub=(fc>>4)&15;
    if((fc&15)!=8 || (sub!=0 && sub!=8) || (fc&0xc700)!=0x100 ||
       (seq&15) || (sub==8 && (qos&0x80)) || (v[7]&3)) { ++n->rx_bad_format;return; }
    ++n->rx_seen;
    if((v[10]&0x9f) || (v[11]&3) || (v[9]&0xf0)) { ++n->rx_bad_status;return; }
    if(v[8]!=1 || !c80_mac_equal(sa,peer) ||
       (!c80_mac_equal(da,own) && !c80_mac_broadcast(da))) { ++n->rx_wrong_peer;return; }
    len=c80_net_payload(type,payload,bytes);
    if(!len || (type==0x806 && !c80_mac_equal(payload+8,peer))) { ++n->rx_bad_protocol;return; }
    tid=sub==8?(qos&15):16;
    if((fc&0x800) && n->seq_valid && n->last_seq==seq && n->last_tid==tid) { ++n->rx_duplicate;return; }
    n->seq_valid=1;n->last_seq=seq;n->last_tid=tid;
    for(i=0;i<6;++i) { eth[i]=da[i];eth[6+i]=sa[i]; }
    c80_setbe16(eth+12,type);
    for(i=0;i<len;++i) eth[14+i]=payload[i];
    if(type==0x806) ++n->rx_arp;else ++n->rx_ipv4;
    if(io->net_receive(io->context,eth,14+len)) ++n->rx_dropped;
    else ++n->rx_delivered;
}
static c80_u32 c80_net_frame_fields(struct c80_io *io,c80_u32 index,c80_u32 bytes,
                                    c80_u32 token,c80_u32 sequence)
{
    static const c80_u8 txd[32]={0x5c,0x00,0x00,0x40,0x01,0xcc,0x00,0x00,0x00,0x00,0x00,0xa0,0x00,0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0xc0,0x20,0x00};
    struct c80_net_cell *cell;
    const c80_u8 *eth=io->pool->net.ethernet,*own=io->pool->nvm_payload+8,*peer=io->pool->auth_frame+4;
    c80_u8 *h,*f;c80_u32 i,len,type,raw;
    if(index>=C80_NET_TX_N || token>=4096u || sequence>=4096u || bytes<14 || bytes>C80_NET_ETH_MAX ||
       !c80_mac_equal(eth+6,own) || (!c80_mac_equal(eth,peer) && !c80_mac_broadcast(eth))) return 0;
    type=c80_be16(eth+12);len=c80_net_payload(type,eth+14,bytes-14);
    if(!len || (type==0x806 && !c80_mac_equal(eth+22,own))) return 0;
    cell=&io->pool->net.tx[index];h=cell->header;f=cell->frame;raw=32+len;
    if(raw>C80_NET_FRAME_MAX) return 0;
    for(i=0;i<64;++i) h[i]=i<32?txd[i]:0;
    c80_put16(f,0x0208);c80_put16(f+2,304);c80_put16(f+22,sequence<<4);
    /* One existing unicast STA, including a copy of a Linux broadcast.
     * This is not an independent BMC-WCID/multiclient multicast path. */
    for(i=0;i<6;++i) { f[4+i]=peer[i];f[10+i]=f[16+i]=own[i]; }
    f[24]=f[25]=0xaa;f[26]=3;f[27]=f[28]=f[29]=0;c80_setbe16(f+30,type);
    for(i=0;i<len;++i) f[32+i]=eth[14+i];
    c80_put16(h,32+raw);
    c80_put16(h+32,0x8000|token);
    c80_put32(h+40,c80_dma_address(io,f));c80_put16(h+44,0x8000|raw);
    return 14+len;
}
static c80_u32 c80_net_frame(struct c80_io *io,c80_u32 index,c80_u32 bytes)
{ return c80_net_frame_fields(io,index,bytes,C80_NET_TOKEN_BASE+index,(index+2)&4095u); }

/* OEM402e1f04 unmaps the payload and returns its token to the free-ID queue
 * on TX-free; DMA DDONE is an independent header ownership boundary.
 * One packet is outstanding. Reuse requires BOTH, with exact ring indices
 * and a CPU generation ledger; no timeout or reset fabricates completion.
 * Returned IDs circulate through all4080 non-management tokens. Firmware
 * must return exactly once and never access a payload after its TX-free. */
static c80_u32 c80_net_recycle_step(struct c80_io *io,struct c80_result *r)
{
    struct c80_net_result *n=&r->net;struct c80_desc *d;struct c80_net_cell *cell;
    c80_u32 index,slot,next,token,len,old,old_index,ctrl;c80_u64 now;
    if(n->token_fault) return C80_NET_TOKEN;
    if(r->phase!=37 || !n->prepared || !n->recycling || !r->auth_ring_programmed) return C80_NET_PREREQ;
    if(!r->assoc_submitted || !r->assoc_dma_done || !r->assoc_token_returned) return 0;
    if(!r->auth_dma_done || !r->auth_token_returned || !r->sta_valid[0] ||
       r->sta_status[0] || r->sta_attempted[1]) return C80_NET_PREREQ;
    now=io->time_us(io->context);
    if(now<r->assoc_window_start_us) return C80_BAD_TIMER;
    if(!n->linked && !n->closed) { n->linked=1;io->net_link(io->context,1); }
    if(n->inflight) {
        index=n->inflight-1;slot=n->active_slot;
        if(!n->submitted || index>=C80_NET_RECYCLE_N || slot>=C80_NET_RING_N ||
           index!=(n->submitted-1u)%C80_NET_RECYCLE_N || slot!=(n->submitted+1u)%C80_NET_RING_N ||
           n->cell_generation[index]!=n->submitted ||
           n->descriptor_generation[slot]!=n->submitted ||
           n->submitted!=n->completed+1u ||
           n->active_token!=C80_NET_TOKEN_BASE+(n->submitted-1u)%C80_NET_TOKEN_COUNT) return C80_NET_REUSE;
        next=(slot+1u)%C80_NET_RING_N;d=&io->pool->auth_tx[slot];cell=&io->pool->net.tx[index];
        ctrl=d->ctrl;if(ctrl&C80_DONE) io->dma_order(io->context,0);
        n->last_ctrl=ctrl;n->last_cpu=c80_read(io,C80_AUTH_RING+8);n->last_dma=c80_read(io,C80_AUTH_RING+12);
        if(c80_read(io,C80_AUTH_RING)!=c80_dma_address(io,io->pool->auth_tx) ||
           c80_read(io,C80_AUTH_RING+4)!=C80_NET_RING_N || n->last_cpu!=next ||
           (n->last_dma!=slot && n->last_dma!=next) ||
           (ctrl&~C80_DONE)!=(C80_LS0|(64u<<16)) || d->info ||
           d->addr!=c80_dma_address(io,cell->header) || d->addr1!=c80_dma_address(io,cell->frame)) return C80_NET_DESC;
        if(!(n->token[index]&C80_NET_HEADER_DONE) && (ctrl&C80_DONE) && n->last_dma==next) {
            n->token[index]|=C80_NET_HEADER_DONE;++n->headers;
        }
        if(now<n->submitted_us) return C80_BAD_TIMER;
        n->last_wait_us=now-n->submitted_us>0xffffffffu?0xffffffffu:(c80_u32)(now-n->submitted_us);
        if(n->token[index]==(C80_NET_SUBMITTED|C80_NET_HEADER_DONE|C80_NET_RETURNED)) {
            ++n->completed;n->inflight=0;io->net_complete(io->context,n->ethernet_bytes[index]);
        } else if(n->last_wait_us>=1000000u) return C80_NET_TIMEOUT;
    }
    if(n->closed || n->inflight) return 0;
    if(n->submitted!=n->completed) return C80_NET_REUSE;
    if(n->submitted==0xffffffffu) return C80_NET_COUNTER;
    len=io->net_dequeue(io->context,io->pool->net.ethernet,C80_NET_ETH_MAX);if(!len) return 0;
    index=n->submitted%C80_NET_RECYCLE_N;slot=(n->submitted+2u)%C80_NET_RING_N;
    token=C80_NET_TOKEN_BASE+n->submitted%C80_NET_TOKEN_COUNT;next=(slot+1u)%C80_NET_RING_N;
    d=&io->pool->auth_tx[slot];cell=&io->pool->net.tx[index];
    if(c80_read(io,C80_AUTH_RING)!=c80_dma_address(io,io->pool->auth_tx) ||
       c80_read(io,C80_AUTH_RING+4)!=C80_NET_RING_N ||
       c80_read(io,C80_AUTH_RING+8)!=slot || c80_read(io,C80_AUTH_RING+12)!=slot) return C80_NET_DESC;
    if(n->cell_generation[index]!=(n->submitted>=C80_NET_RECYCLE_N?n->submitted-C80_NET_RECYCLE_N+1u:0u)) return C80_NET_REUSE;
    if(n->cell_generation[index] &&
       (n->cell_generation[index]>n->completed || n->token[index]!=7u)) return C80_NET_REUSE;
    if(!n->cell_generation[index] && n->token[index]) return C80_NET_REUSE;
    old=n->descriptor_generation[slot];
    if(old!=(n->submitted>=C80_NET_RING_N?n->submitted-C80_NET_RING_N+1u:0u)) return C80_NET_REUSE;
    if(old) {
        old_index=(old-1u)%C80_NET_RECYCLE_N;
        if(old>n->completed || d->ctrl!=(C80_DONE|C80_LS0|(64u<<16)) || d->info ||
           d->addr!=c80_dma_address(io,io->pool->net.tx[old_index].header) ||
           d->addr1!=c80_dma_address(io,io->pool->net.tx[old_index].frame)) return C80_NET_REUSE;
    } else if(slot<2u) {
        if(d->ctrl!=(C80_DONE|C80_LS0|(64u<<16)) || d->info ||
           d->addr!=c80_dma_address(io,slot?io->pool->assoc_header:io->pool->auth_header) ||
           d->addr1!=c80_dma_address(io,slot?io->pool->assoc_frame:io->pool->auth_frame)) return C80_NET_REUSE;
    } else if(d->ctrl!=C80_DONE || d->addr || d->addr1 || d->info) return C80_NET_DESC;
    len=c80_net_frame_fields(io,index,len,token,(n->submitted+2u)&4095u);
    if(!len) { ++n->tx_rejected;return 0; }
    if(n->cell_generation[index]) ++n->payload_reuses;
    if(n->submitted && token==C80_NET_TOKEN_BASE) ++n->token_wraps;
    if(!next) ++n->ring_wraps;
    n->ethernet_bytes[index]=len;
    d->addr=c80_dma_address(io,cell->header);d->addr1=c80_dma_address(io,cell->frame);d->info=0;
    d->ctrl=C80_LS0|(64u<<16);io->dma_order(io->context,1);
    n->token[index]=C80_NET_SUBMITTED;n->inflight=index+1;n->submitted_us=now;
    n->active_slot=slot;n->active_token=token;++n->submitted;
    n->cell_generation[index]=n->descriptor_generation[slot]=n->submitted;n->last_slot=slot;
    c80_write(io,C80_AUTH_RING+8,next);n->last_cpu=c80_read(io,C80_AUTH_RING+8);
    if(n->last_cpu!=next) return C80_NET_PUBLISH;
    return 0;
}
static c80_u32 c80_net_step(struct c80_io *io,struct c80_result *r)
{
    struct c80_net_result *n=&r->net;struct c80_desc *d;struct c80_net_cell *cell;
    c80_u32 index,slot,len; c80_u64 now,elapsed;
    if(!io->netdev_test) return 0;
    if(io->net_recycle_test) return c80_net_recycle_step(io,r);
    if(r->phase!=37 || !n->prepared || !r->auth_ring_programmed) return C80_NET_PREREQ;
    if(!r->assoc_submitted || !r->assoc_dma_done || !r->assoc_token_returned) return 0;
    if(!r->sta_valid[0] || r->sta_status[0] || r->sta_attempted[1]) return C80_NET_PREREQ;
    now=io->time_us(io->context);
    if(now<r->assoc_window_start_us) return C80_BAD_TIMER;
    elapsed=now-r->assoc_window_start_us;
    if(!n->linked && !n->closed) { n->linked=1;io->net_link(io->context,1); }
    if(n->inflight) {
        if(n->inflight>C80_NET_TX_N) return C80_NET_DESC;
        index=n->inflight-1;slot=index+2;d=&io->pool->auth_tx[slot];cell=&io->pool->net.tx[index];
        n->last_ctrl=d->ctrl;n->last_cpu=c80_read(io,C80_AUTH_RING+8);n->last_dma=c80_read(io,C80_AUTH_RING+12);
        if(n->last_cpu!=slot+1 || (n->last_dma!=slot && n->last_dma!=slot+1) ||
           (d->ctrl&~C80_DONE)!=(C80_LS0|(64u<<16)) || d->info ||
           d->addr!=c80_dma_address(io,cell->header) || d->addr1!=c80_dma_address(io,cell->frame)) return C80_NET_DESC;
        if(!(n->token[index]&C80_NET_HEADER_DONE) && (d->ctrl&C80_DONE) && n->last_dma==slot+1) {
            io->dma_order(io->context,0);n->token[index]|=C80_NET_HEADER_DONE;++n->headers;
        }
        if(now<n->submitted_us) return C80_BAD_TIMER;
        n->last_wait_us=now-n->submitted_us>0xffffffffu?0xffffffffu:(c80_u32)(now-n->submitted_us);
        if(n->token[index]==(C80_NET_SUBMITTED|C80_NET_HEADER_DONE|C80_NET_RETURNED)) {
            ++n->completed;n->inflight=0;io->net_complete(io->context,n->ethernet_bytes[index]);
        } else if(n->last_wait_us>=1000000u) return C80_NET_TIMEOUT;
    }
    if(n->submitted==C80_NET_TX_N) { n->exhausted=1;c80_net_close(io,r); }
    if(elapsed>=c80_beacon_target(io)-2000000u) c80_net_close(io,r);
    if(n->closed || n->inflight) return 0;
    len=io->net_dequeue(io->context,io->pool->net.ethernet,C80_NET_ETH_MAX);
    if(!len) return 0;
    index=n->submitted;slot=index+2;
    if(index>=C80_NET_TX_N || slot>=c80_auth_ring_size(io)) return C80_NET_DESC;
    d=&io->pool->auth_tx[slot];cell=&io->pool->net.tx[index];
    if(n->token[index] ||
       c80_read(io,C80_AUTH_RING)!=c80_dma_address(io,io->pool->auth_tx) ||
       c80_read(io,C80_AUTH_RING+4)!=c80_auth_ring_size(io) ||
       c80_read(io,C80_AUTH_RING+8)!=slot || c80_read(io,C80_AUTH_RING+12)!=slot ||
       d->addr || d->addr1 || d->info || d->ctrl!=C80_DONE) return C80_NET_DESC;
    len=c80_net_frame(io,index,len);
    if(!len) { ++n->tx_rejected;return 0; }
    n->ethernet_bytes[index]=len;
    d->addr=c80_dma_address(io,cell->header);d->addr1=c80_dma_address(io,cell->frame);
    d->info=0;d->ctrl=C80_LS0|(64u<<16);
    io->dma_order(io->context,1);
    n->token[index]=C80_NET_SUBMITTED;n->inflight=index+1;n->submitted_us=now;
    ++n->submitted;n->last_slot=slot;
    c80_write(io,C80_AUTH_RING+8,slot+1);n->last_cpu=c80_read(io,C80_AUTH_RING+8);
    if(n->last_cpu!=slot+1) return C80_NET_PUBLISH;
    return 0;
}
#endif
