/* SPDX-License-Identifier: GPL-2.0-only */
/* Actual frame builder/recycler; independent synthetic completion/MCU model. */
#define main c80_previous_session_main
#include "verify-session.c"
#undef main
static unsigned rate_cases;
static c80_u8 rate_oracle[40][44];
static const c80_u8 *golden(unsigned rate,unsigned protected,unsigned bytes)
{
    for(unsigned i=0;i<40;++i)if(c80_get32(rate_oracle[i])==rate &&
        c80_get32(rate_oracle[i]+4)==protected && c80_get32(rate_oracle[i]+8)==bytes)
        return rate_oracle[i]+12;
    assert(!"Missing actual OEM vector");return NULL;
}
static unsigned ethernet(c80_u8 *e,unsigned kind)
{
    unsigned type=kind==0?0x806:kind==4?0x888e:0x800;
    unsigned len=kind==0?28:kind==4?99:kind==3?1400:kind==2?60:20;
    memset(e,0,14+len);memcpy(e,client_mac,6);memcpy(e+6,own_mac,6);c80_setbe16(e+12,type);
    c80_u8 *p=e+14;
    if(type==0x806) { c80_setbe16(p,1);c80_setbe16(p+2,0x800);p[4]=6;p[5]=4;c80_setbe16(p+6,2);memcpy(p+8,own_mac,6); }
    else if(type==0x888e) { p[0]=2;p[1]=3;c80_setbe16(p+2,95); }
    else { p[0]=0x45;c80_setbe16(p+2,len);p[8]=64; }
    return 14+len;
}
static void pass(const char *name) { ++rate_cases;printf("PASS DATA RATE %s\n",name); }
static void matrix(void)
{
    struct session_model *m=fixture();memcpy(m->pool.session_peer,client_mac,6);m->r.session.started=1;
    const unsigned cells[]={0,15,255},tokens[]={16,4095},seqs[]={0,4095};
    for(unsigned enabled=0;enabled<2;++enabled)for(unsigned secure=0;secure<2;++secure)
    for(unsigned kind=0;kind<5;++kind)for(unsigned i=0;i<3;++i)
    for(unsigned t=0;t<2;++t)for(unsigned q=0;q<2;++q) {
        unsigned bytes=ethernet(m->pool.net.ethernet,kind),raw=bytes+18;
        unsigned rate=enabled && secure && kind!=4?3:0,protected=secure && kind!=4;
        m->io.data_cck11_test=enabled;m->io.wpa2_test=secure;
        unsigned len=c80_net_frame_fields(&m->io,cells[i],bytes,tokens[t],seqs[q]);
        if(!secure && kind==4) { assert(!len);pass("open-profile-EAPOL-still-refused");continue; }
        assert(len==bytes);const struct c80_net_cell *cell=&m->pool.net.tx[cells[i]];
        c80_u8 h[64]={0};memcpy(h,golden(rate,protected,raw),32);
        c80_put16(h+32,0x8000|tokens[t]);c80_put32(h+40,c80_dma_address(&m->io,cell->frame));c80_put16(h+44,0x8000|raw);
        assert(!memcmp(h,cell->header,64) && c80_get16(cell->frame)==(0x208|(protected?0x4000:0)));
        assert(c80_get16(cell->frame+2)==304 && c80_get16(cell->frame+22)==seqs[q]<<4);
        assert(!memcmp(cell->frame+32,m->pool.net.ethernet+14,bytes-14));
        assert(!m->writes && !m->r.net.submitted && !m->r.net.data_cck1_submitted && !m->r.net.data_cck11_submitted);
        pass("whole-OEM-TXD-TXP-CCMP-EAPOL-payload-and-boundary-vector");
    }
    free(m);
}
static c80_u32 rate_dequeue(void *o,c80_u8 *e,c80_u32 capacity)
{
    struct session_model *m=o;owned(m);if(!m->requests)return 0;--m->requests;assert(capacity>=1414);
    unsigned kind=(m->r.net.submitted+1)%3;
    return ethernet(e,kind==0?4:kind==1?0:3);
}
static void rate_complete(void *o,c80_u32 bytes)
{ struct session_model *m=o;assert(!m->net_busy && (bytes==42 || bytes==1414 || bytes==113));++m->data_done; }
static void rate_write(void *o,c80_u32 a,c80_u32 value)
{
    struct session_model *m=o;struct c80_result *r=&m->r;
    if(a!=C80_AUTH_RING+8) { wr(o,a,value);return; }
    owned(m);++m->writes;unsigned slot=(value+127)%128;struct c80_desc *d=&m->pool.auth_tx[slot];
    const c80_u8 *h=dma_pointer(m,d->addr,64),*p=dma_pointer(m,d->addr1,32);
    unsigned bytes=c80_get16(h+44)&0x7fff,token=c80_get16(h+32)&0x7fff,type=c80_be16(p+30),rate=type==0x888e?0:3;
    assert(!m->net_busy && !m->command_busy && r->session.sta_live);
    assert(type==0x888e || r->security.authorized);
    assert(d->ctrl==0x40400000 && !d->info && value==(*reg(m,a)+1)%128);
    c80_u8 expected[64]={0};memcpy(expected,golden(rate,type!=0x888e,bytes),32);
    c80_put16(expected+32,0x8000|token);c80_put32(expected+40,d->addr1);c80_put16(expected+44,0x8000|bytes);
    assert(!memcmp(h,expected,64));
    assert(c80_get16(p)==(0x208|(type==0x888e?0:0x4000)) && c80_get16(p+2)==304);
    assert(token==16+(r->net.submitted-1)%4080 && slot==(r->net.submitted+1)%128);
    assert(r->net.data_cck1_submitted+r->net.data_cck11_submitted==r->net.data_submitted);
    m->tx_pointer=(const c80_u8 *)&m->pool.net.tx[r->net.inflight-1];m->tx_bytes=sizeof(struct c80_net_cell);
    memcpy(m->tx_snapshot,m->tx_pointer,m->tx_bytes);m->net_busy=1;
    m->tx_slot=slot;m->tx_next=value;m->tx_token=token;m->kind=0;
    m->tx_header_done=m->tx_token_done=0;m->tx_at=m->us;
    *reg(m,a)=value;
    if(m->net_fault!=2 && m->net_fault!=4)device_header(m);
    if(m->net_fault!=1 && m->net_fault!=5)device_token(m);
}
static void exercise(unsigned count,unsigned fault,unsigned expected)
{
    struct session_model *m=fixture();initial_connection(m);
    m->io.data_cck11_test=m->io.wpa2_test=1;m->io.net_dequeue=rate_dequeue;m->io.net_complete=rate_complete;m->io.write=rate_write;
    m->r.security.ptk=m->r.security.gtk=m->r.security.authorized=1;m->net_fault=fault;m->requests=count;
    unsigned rc=0;
    for(unsigned i=0;i<5*count+2100;++i) {
        rc=tick(m);if(rc || (m->r.net.completed==count && !m->r.net.inflight))break;
    }
    assert(rc==expected);
    if(!expected) {
        assert(m->r.net.submitted==count && m->r.net.headers==count && m->r.net.returned==count && m->r.net.completed==count && m->data_done==count);
        assert(m->r.net.data_cck11_submitted && m->r.net.data_cck1_submitted && m->r.net.token_wraps==1 && m->r.net.ring_wraps>30);
        assert(!m->r.net.inflight && !m->r.net.stale_tokens && !m->r.net.token_fault);
    } else assert(m->r.net.inflight && !m->r.net.completed && m->r.net.submitted==1);
    pass(expected?"CCK11-missing-or-bad-completion-not-fabricated":"mixed-CCK11-data-CCK1-EAPOL-5000-posts-and-buffer-ring-token-wraps");
    free(m);
}
static unsigned port_kind;
static c80_u32 port_dequeue(void *o,c80_u8 *e,c80_u32 capacity)
{
    struct session_model *m=o;assert(capacity>=1414);if(!m->requests)return 0;
    --m->requests;return ethernet(e,port_kind);
}
static void controlled_port(void)
{
    const unsigned kinds[]={0,3,4};
    for(unsigned i=0;i<3;++i) {
        struct session_model *m=fixture();initial_connection(m);
        m->io.data_cck11_test=m->io.wpa2_test=1;m->io.net_dequeue=port_dequeue;
        m->io.net_complete=rate_complete;m->io.write=rate_write;m->requests=1;port_kind=kinds[i];
        unsigned before=m->writes;assert(!tick(m));assert(!tick(m));
        assert(!m->r.security.ptk && !m->r.security.authorized);
        if(port_kind==4) {
            assert(m->r.net.completed==1 && m->r.net.data_cck1_submitted==1 && !m->r.net.data_cck11_submitted);
            assert(m->r.security.tx_eapol==1);pass("EAPOL-before-keys-uses-real-recycler-at-CCK1");
        } else {
            assert(m->writes==before && !m->r.net.submitted && !m->r.net.data_cck11_submitted);
            assert(m->r.security.tx_blocked==1);pass("unauthorized-CCK11-ARP-or-IP-never-published");
        }
        free(m);
    }
}
int main(int argc,char **argv)
{
    assert(argc==7);load(argv[1],auth_oracle,32);load(argv[2],assoc_oracle,32);load(argv[3],data_oracle,32);load(argv[5],reassoc_oracle,32);
    FILE *f=fopen(argv[4],"rb");assert(f);
    for(unsigned i=0;i<2;++i){assert(fread(&sta_bytes[i],4,1,f)==1 && sta_bytes[i]<=308);assert(fread(sta_oracle[i],1,sta_bytes[i],f)==sta_bytes[i]);}assert(fgetc(f)==EOF);fclose(f);
    load(argv[6],(c80_u8 *)rate_oracle,sizeof(rate_oracle));matrix();
    exercise(5000,0,0);exercise(5000,4,0);exercise(5000,5,0);
    exercise(1,1,C80_NET_TIMEOUT);exercise(1,2,C80_NET_TIMEOUT);exercise(1,6,C80_NET_TOKEN);exercise(1,7,C80_NET_TOKEN);
    controlled_port();
    printf("PASS: %u actual data-rate cases; 15000 mixed posts; synthetic MCU/DMA/CCMP/RF.\n",rate_cases);
    return 0;
}
