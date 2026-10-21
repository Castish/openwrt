/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef C80_SECURITY_PARSE_H
#define C80_SECURITY_PARSE_H
#include "c80_rsn.h"
static int c80_security_assoc_ie(struct c80_io *io,struct c80_result *r,
                                  const c80_u8 *p,c80_u32 n,c80_u32 offset)
{
    c80_u32 size,rsn=0,pos=0,i;
    if(!io->wpa2_test) return 1;
    if(n>=offset+4 && c80_crc(p,n-4)==c80_get32(p+n-4)) n-=4; /* independently verified trailing FCS */
    while(offset<n) {
        if(n-offset<2 || (size=p[offset+1])>n-offset-2) return 0;
        if(p[offset]==48) {
            if(rsn || !c80_rsn_valid(p+offset+2,size)) return 0;
            rsn=size+2;pos=offset;
        }
        offset+=size+2;
    }
    if(!rsn) return 0;
    for(i=0;i<rsn;++i) r->security.assoc_rsn[i]=p[pos+i];
    r->security.assoc_rsn_bytes=rsn;return 1;
}
static c80_u32 c80_eapol_bytes(const c80_u8 *p,c80_u32 n)
{
    c80_u32 bytes;
    if(n<4 || p[0]<1 || p[0]>3 || p[1]>4) return 0;
    bytes=4+c80_be16(p+2);
    return bytes<=n && bytes<=C80_NET_MTU?bytes:0;
}
/* A protected frame is accepted only after hardware decryption/MIC checks
 * and a strictly increasing per-TID CCMP PN from RXD group1. */
static int c80_security_receive(struct c80_io *io,struct c80_result *r,
               const c80_u8 *v,c80_u32 total,c80_u32 offset,c80_u32 fc,c80_u32 tid,c80_u32 type)
{
    struct c80_security_result *s=&r->security;c80_u32 group,pos,i,mode; c80_u64 pn=0;
    if(!io->wpa2_test) return 1;
    mode=v[9]>>4;
    if((v[10]&0xff) || (v[11]&3)) { ++s->rx_bad_crypto;return 0; }
    if(!(fc&0x4000)) {
        if(mode || type!=0x888e) { ++s->rx_blocked;return 0; }
        ++s->rx_eapol;return 1;
    }
    if(!s->ptk || (type!=0x888e && !s->authorized) || mode!=4 ||
       (v[10]&0xff) || (v[11]&3) || tid>=17) { ++s->rx_bad_crypto;return 0; }
    group=(v[3]>>1)&15;pos=16+16*!!(group&8);
    if(!(group&1) || pos>total || total-pos<16 || pos+16>offset) { ++s->rx_bad_crypto;return 0; }
    for(i=0;i<6;++i) pn|=(c80_u64)v[pos+i]<<(8*i);
    if(!pn || pn<=s->rx_pn[tid]) { ++s->rx_replay;return 0; }
    s->rx_pn[tid]=pn;++s->rx_encrypted;
    if(type==0x888e) ++s->rx_eapol;
    return 1;
}
static int c80_security_transmit(struct c80_io *io,struct c80_result *r,c80_u32 bytes)
{
    struct c80_security_result *s=&r->security;
    if(!io->wpa2_test) return 1;
    if(bytes>=18 && c80_be16(io->pool->net.ethernet+12)==0x888e) { ++s->tx_eapol;return 1; }
    if(!s->authorized || !s->ptk) { ++s->tx_blocked;return 0; }
    ++s->tx_encrypted;return 1;
}
static c80_u32 c80_security_step(struct c80_io *,struct c80_result *);
static c80_u32 c80_security_forget_peer(struct c80_io *,struct c80_result *);
static c80_u32 c80_security_stop(struct c80_io *,struct c80_result *);
#endif
