/* SPDX-License-Identifier: GPL-2.0-only */
/* Execute the actual session, TX, RX and MCU command cores. MMIO, firmware,
 * DMA completion and Linux callbacks are independent synthetic device effects.
 * This cannot prove MT7626 RF/timing or its exactly-once completion contract. */
#define _GNU_SOURCE
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "c80_mcu_core.h"
static const c80_u8 own_mac[6]={2,0xc0,0x80,0x33,0,1};
static const c80_u8 client_mac[6]={2,0xc0,0x80,0x33,0,2};
static c80_u8 auth_oracle[32],assoc_oracle[32],reassoc_oracle[32],data_oracle[32],sta_oracle[2][308];
static unsigned sta_bytes[2],cases;
struct session_model {
    struct c80_io io;struct c80_result r;struct c80_dma_pool pool;
    c80_u32 reg[48][2];unsigned regs,rx_head,writes,links,unlinks,requests,data_done,received;
    unsigned sta_live,creates,deletes,command_posts,command_busy,net_busy,kind;
    unsigned net_fault,command_fault,barriers,stopped,notified;
    c80_u32 tx_slot,tx_next,tx_token,command_slot,command_next,last_sequence;
    unsigned tx_bytes,command_bytes,tx_header_done,tx_token_done;
    c80_u64 us,tx_at;
    c80_u8 tx_snapshot[sizeof(struct c80_net_cell)],cmd_snapshot[C80_COMMAND_BYTES];
    const c80_u8 *tx_pointer,*command_pointer;
};
static c80_u32 *reg(struct session_model *m,c80_u32 a)
{
    for(unsigned i=0;i<m->regs;++i)if(m->reg[i][0]==a)return &m->reg[i][1];
    assert(m->regs<48);m->reg[m->regs][0]=a;return &m->reg[m->regs++][1];
}
static void owned(struct session_model *m)
{
    if(m->net_busy)assert(!memcmp(m->tx_snapshot,m->tx_pointer,m->tx_bytes));
    if(m->command_busy)assert(!memcmp(m->cmd_snapshot,m->command_pointer,m->command_bytes));
}
static c80_u8 *dma_pointer(struct session_model *m,c80_u32 a,unsigned bytes)
{
    assert(a>=m->io.dma_base && a-m->io.dma_base<=sizeof(m->pool)-bytes);
    return (c80_u8 *)&m->pool+(a-m->io.dma_base);
}
static c80_u32 rd(void *o,c80_u32 a)
{ struct session_model *m=o;owned(m);return *reg(m,a); }
static void event(struct session_model *m,const c80_u8 *p,unsigned bytes)
{
    unsigned i=m->rx_head%C80_RX_N;struct c80_desc *d=&m->pool.rx[1][i];
    assert(!(d->ctrl&C80_DONE) && bytes<=C80_RX_SIZE);
    memcpy(m->pool.data[1][i],p,bytes);d->ctrl=C80_DONE|C80_LS0|(bytes<<16);++m->rx_head;
}
static void token_event(struct session_model *m,unsigned token,unsigned count)
{
    c80_u8 p[16]={0};assert(count==1 || count==2);
    c80_put32(p,(6u<<29)|(count<<16)|(8+4*count));c80_put32(p+4,1u<<16);
    c80_put16(p+8,token);if(count==2)c80_put16(p+12,token);
    event(m,p,8+4*count);
}
static void device_header(struct session_model *m)
{
    m->pool.auth_tx[m->tx_slot].ctrl|=C80_DONE;
    *reg(m,C80_AUTH_RING+12)=m->tx_next;m->tx_header_done=1;
    if(m->tx_token_done)m->net_busy=0;
}
static void device_token(struct session_model *m)
{
    token_event(m,m->net_fault==7?m->tx_token+1:m->tx_token,m->net_fault==6?2:1);
    m->tx_token_done=1;if(m->tx_header_done)m->net_busy=0;
}
static void wr(void *o,c80_u32 a,c80_u32 value)
{
    struct session_model *m=o;struct c80_result *r=&m->r;owned(m);++m->writes;
    if(a==0x180043f8) {
        unsigned slot=(value+127)%128;struct c80_desc *d=&m->pool.tx[slot];
        unsigned bytes=(d->ctrl>>16)&0x3fff;const c80_u8 *p=dma_pointer(m,d->addr,bytes);
        c80_u8 expected[308],reply[44]={0};unsigned off=r->sta_waiting-1;
        assert(!m->command_busy && !m->net_busy && r->sta_waiting && off<2);
        assert(value==(*reg(m,a)+1)%128 && bytes==sta_bytes[off]);
        assert(!d->addr1 && !d->info && d->ctrl==(C80_LS0|(bytes<<16)));
        assert(p[39]==(m->last_sequence==15?1:m->last_sequence+1));m->last_sequence=p[39];
        memcpy(expected,sta_oracle[off],bytes);expected[39]=p[39];
        memcpy(expected+84,client_mac,6);if(!off)memcpy(expected+108,client_mac,6);
        assert(!memcmp(p,expected,bytes));
        assert(off?m->sta_live:!m->sta_live);m->sta_live=!off;
        if(off)++m->deletes;else ++m->creates;
        memcpy(m->cmd_snapshot,p,bytes);m->command_pointer=p;m->command_bytes=bytes;m->command_busy=1;
        m->command_slot=slot;m->command_next=value;++m->command_posts;
        *reg(m,a)=value;
        if(m->command_fault!=2) { d->ctrl|=C80_DONE;*reg(m,0x180043fc)=value; }
        if(m->command_fault==4)d->addr^=16;
        if(m->command_fault==5)*reg(m,0x180043fc)=(value+1)%128;
        if(m->command_fault==1)return;
        c80_put32(reply,(7u<<29)|44);c80_put16(reply+16,28);c80_put16(reply+18,0xe000);
        reply[20]=0xed;reply[21]=p[39];reply[24]=reply[28]=0x25;
        reply[37]=1;c80_put16(reply+38,off?1:2);
        if(m->command_fault==3)reply[21]^=1;
        if(m->command_fault==6)c80_put32(reply+32,1);
        event(m,reply,sizeof(reply));if(!m->command_fault || m->command_fault==6)m->command_busy=0;
        return;
    }
    if(a==C80_AUTH_RING+8) {
        unsigned slot=(value+127)%128;struct c80_desc *d=&m->pool.auth_tx[slot];
        const c80_u8 *h=dma_pointer(m,d->addr,64),*p=dma_pointer(m,d->addr1,48);
        unsigned token=c80_get16(h+32)&0x7fff,bytes=c80_get16(h+44)&0x7fff,kind;
        c80_u8 expected[64]={0};
        assert(!m->net_busy && !m->command_busy && d->ctrl==0x40400000 && !d->info);
        assert(value==(*reg(m,a)+1)%128 && token<4096);
        kind=token<2?(token?C80_REPLY_ASSOC:C80_REPLY_AUTH):r->net.active_kind;
        memcpy(expected,kind==C80_REPLY_AUTH?auth_oracle:kind==C80_REPLY_REASSOC?reassoc_oracle:kind?assoc_oracle:data_oracle,32);
        c80_put16(expected,32+bytes);c80_put16(expected+32,0x8000|token);
        c80_put32(expected+40,d->addr1);c80_put16(expected+44,0x8000|bytes);
        assert(!memcmp(h,expected,64));
        assert(c80_get16(p+2)==304 && !memcmp(p+4,client_mac,6) && !memcmp(p+10,own_mac,6) && !memcmp(p+16,own_mac,6));
        if(kind) {
            assert(bytes==(kind==C80_REPLY_AUTH?30:36));
            assert(c80_get16(p)==(kind==C80_REPLY_AUTH?0xb0:kind==C80_REPLY_REASSOC?0x30:0x10));
            assert(!c80_get16(p+24+(kind==C80_REPLY_AUTH?0:2)));
            if(kind==C80_REPLY_AUTH)assert(!m->sta_live && c80_get16(p+26)==2 && !c80_get16(p+28));
            else assert(m->sta_live && c80_get16(p+24)==1 && c80_get16(p+28)==0xc001 && !memcmp(p+30,(c80_u8[]){1,4,0x82,0x84,0x8b,0x96},6));
        } else assert(m->sta_live && c80_get16(p)==0x208 && bytes==52);
        if(token>=16) {
            assert(token==16+(r->net.submitted-1)%4080);
            assert(slot==(r->net.submitted+1)%128);
            assert(c80_get16(p+22)==(((r->net.submitted+1)&4095)<<4));
            m->tx_pointer=(const c80_u8 *)&m->pool.net.tx[r->net.inflight-1];m->tx_bytes=sizeof(struct c80_net_cell);
        } else { m->tx_pointer=p;m->tx_bytes=kind==C80_REPLY_AUTH?30:36; }
        memcpy(m->tx_snapshot,m->tx_pointer,m->tx_bytes);m->net_busy=1;
        m->tx_slot=slot;m->tx_next=value;m->tx_token=token;m->kind=kind;
        m->tx_header_done=m->tx_token_done=0;m->tx_at=m->us;
        if(m->net_fault!=8)*reg(m,a)=value;
        if(m->net_fault!=2 && m->net_fault!=4)device_header(m);
        if(m->net_fault!=1 && m->net_fault!=5)device_token(m);
        if(m->net_fault==3)d->addr^=16;
        return;
    }
    *reg(m,a)=value;
}
static c80_u64 now(void *o) { return ((struct session_model *)o)->us; }
static void delay(void *o,c80_u32 us)
{
    struct session_model *m=o;owned(m);m->us+=us;
    if(m->net_busy && m->us-m->tx_at>=4000) {
        if(m->net_fault==4 && !m->tx_header_done)device_header(m);
        if(m->net_fault==5 && !m->tx_token_done)device_token(m);
    }
}
static void barrier(void *o,int publish)
{ struct session_model *m=o;owned(m);if(publish)++m->barriers; }
static void link_changed(void *o,int on)
{ struct session_model *m=o;owned(m);if(on){assert(m->sta_live);++m->links;}else ++m->unlinks; }
static c80_u32 dequeue(void *o,c80_u8 *out,c80_u32 capacity)
{
    struct session_model *m=o;owned(m);if(!m->requests)return 0;--m->requests;
    assert(capacity>=34);memcpy(out,client_mac,6);memcpy(out+6,own_mac,6);c80_setbe16(out+12,0x800);
    memset(out+14,0,20);out[14]=0x45;c80_setbe16(out+16,20);out[22]=64;return 34;
}
static void complete(void *o,c80_u32 bytes)
{ struct session_model *m=o;owned(m);assert(bytes==34 && !m->net_busy);++m->data_done; }
static int receive(void *o,const c80_u8 *p,c80_u32 bytes)
{ struct session_model *m=o;assert(bytes==34 && !memcmp(p+6,client_mac,6));++m->received;return 0; }
static struct session_model *fixture(void)
{
    struct session_model *m=calloc(1,sizeof(*m));assert(m);struct c80_result *r=&m->r;
    m->us=1000000;m->last_sequence=r->sequence=8;
    m->io=(struct c80_io){.context=m,.pool=&m->pool,.dma_base=0x41000000,.read=rd,.write=wr,
        .time_us=now,.delay_us=delay,.dma_order=barrier,.net_link=link_changed,.net_dequeue=dequeue,
        .net_complete=complete,.net_receive=receive,.session_test=1,.cfg80211_test=1,.net_recycle_test=1,
        .netdev_test=1,.auth_reply_test=1,.assoc_reply_test=1,.management_rx_test=1,.rx1_rearm_test=1,
        .rx1_packet_test=1,.rx0_rearm_test=1,.radio_test=1,.ap_ssid=(const c80_u8 *)"C80-RAM34",.ap_ssid_bytes=9};
    r->phase=37;r->main_ready=r->nvm_equal=r->devinfo_mac_valid=r->auth_ring_programmed=1;
    r->bss_valid[0]=r->radio_valid[3]=r->beacon_valid[1]=1;
    r->net.enabled=r->net.prepared=r->net.recycling=1;r->assoc_window_start_us=m->us;
    memcpy(m->pool.nvm_payload+8,own_mac,6);
    *reg(m,C80_AUTH_RING)=c80_dma_address(&m->io,m->pool.auth_tx);*reg(m,C80_AUTH_RING+4)=128;
    *reg(m,0x180043f0)=c80_dma_address(&m->io,m->pool.tx);*reg(m,0x180043f4)=128;
    *reg(m,0x180043f8)=*reg(m,0x180043fc)=r->command_submitted=r->command_completed=22;
    *reg(m,C80_GLO)=0x10001c75;*reg(m,C80_OWN)=0x30000;*reg(m,C80_SYNC)=6;
    for(unsigned i=0;i<128;++i) { m->pool.auth_tx[i].ctrl=C80_DONE;m->pool.tx[i].ctrl=C80_DONE; }
    for(unsigned i=0;i<22;++i) {
        c80_put32(m->pool.command[i],0x80000040);m->pool.tx[i].addr=c80_dma_address(&m->io,m->pool.command[i]);
        m->pool.tx[i].ctrl=C80_DONE|C80_LS0|(64u<<16);
    }
    for(unsigned q=0;q<2;++q)for(unsigned i=0;i<64;++i) {
        m->pool.rx[q][i].addr=c80_dma_address(&m->io,m->pool.data[q][i]);m->pool.rx[q][i].ctrl=1536u<<16;
    }
    return m;
}
static unsigned tick(struct session_model *m)
{
    unsigned status=0,rc;owned(m);rc=c80_receive(&m->io,&m->r,0,0,&status);
    if(rc!=C80_RX_TIMEOUT)return rc?rc:C80_SESSION_STATE;
    rc=c80_session_step(&m->io,&m->r);if(rc)return rc;
    rc=c80_net_step(&m->io,&m->r);delay(m,1000);return rc;
}
static void packet(struct session_model *m,unsigned sub,unsigned seq,unsigned flags)
{
    c80_u8 p[96]={0};unsigned bytes=sub==11?30:sub==0?45:sub==2?51:26;
    c80_put16(p,sub<<4|flags);c80_put16(p+22,(seq&4095)<<4);
    memcpy(p+4,own_mac,6);memcpy(p+10,client_mac,6);memcpy(p+16,own_mac,6);
    if(sub==11)c80_put16(p+26,1);
    else if(sub==0 || sub==2) {
        c80_put16(p+24,1);c80_put16(p+26,1);unsigned off=sub==2?34:28;
        if(sub==2)memcpy(p+28,own_mac,6);
        p[off+1]=9;memcpy(p+off+2,"C80-RAM34",9);memcpy(p+off+11,(c80_u8[]){1,4,0x82,0x84,0x8b,0x96},6);
    } else c80_put16(p+24,3);
    c80_management_receive(&m->io,&m->r,p,bytes);
}
static void until_state(struct session_model *m,unsigned state)
{
    for(unsigned i=0;i<2100;++i) {
        unsigned rc=tick(m);if(rc)fprintf(stderr,"session rc%u state%u posts%u cmd%u\n",rc,m->r.session.state,m->r.net.submitted,m->r.command_submitted);
        assert(!rc);
        if(m->r.session.started && m->r.session.state==state && !m->r.net.inflight)return;
    }
    assert(!"session state deadline");
}
static void initial_connection(struct session_model *m)
{
    packet(m,11,1,0);
    for(unsigned i=0;i<20 && !m->r.auth_token_returned;++i)assert(!tick(m));
    assert(m->r.auth_token_returned);packet(m,0,2,0);
    until_state(m,C80_SESSION_CONNECTED);assert(m->r.session.connections==1 && m->links==1 && m->creates==1);
}
static void data_once(struct session_model *m)
{
    unsigned old=m->data_done;++m->requests;
    for(unsigned i=0;i<20 && m->data_done==old;++i)assert(!tick(m));
    assert(m->data_done==old+1 && m->r.net.data_completed==m->data_done);
}
static void cycle(struct session_model *m,unsigned mode,unsigned seq)
{
    unsigned old=m->r.session.connections;
    if(mode==1 || mode==2) { packet(m,mode==1?12:10,seq,0);until_state(m,C80_SESSION_IDLE); }
    if(mode!=2) { packet(m,11,seq+1,0);until_state(m,C80_SESSION_ASSOC_WAIT); }
    packet(m,mode==2?2:0,seq+2,0);until_state(m,C80_SESSION_CONNECTED);
    assert(m->r.session.connections==old+1 && m->r.session.creates==m->creates && m->r.session.deletes==m->deletes);
}
static void stress(unsigned count,unsigned mode,unsigned completion_order)
{
    struct session_model *m=fixture();initial_connection(m);data_once(m);
    m->net_fault=completion_order;
    for(unsigned i=1;i<count;++i) { cycle(m,mode==3?i%3:mode,3*i);data_once(m); }
    assert(m->r.session.connections==count && m->links==count && m->unlinks==count-1);
    assert(m->creates==count && m->deletes==count-1 && m->sta_live);
    assert(m->r.net.completed==m->r.net.submitted && m->r.net.headers==m->r.net.submitted && m->r.net.returned==m->r.net.submitted);
    assert(m->r.command_cycle.acked==m->r.command_submitted && !m->r.command_cycle.fault);
    assert(m->r.command_submitted==22+m->command_posts && !m->net_busy && !m->command_busy && !m->r.net.token_fault);
    printf("PASS SESSION stress count=%u mode=%u completion_order=%u management=%u data=%u cmd=%u data_ring_wraps=%u token_wraps=%u command_ring_wraps=%u\n",
        count,mode,completion_order,m->r.net.management_completed,m->data_done,m->command_posts,m->r.net.ring_wraps,m->r.net.token_wraps,m->r.command_cycle.ring_wraps);
    ++cases;free(m);
}
static void inflight_disconnect(unsigned sub,unsigned order)
{
    struct session_model *m=fixture();initial_connection(m);m->net_fault=order;
    ++m->requests;assert(!tick(m) && m->net_busy && m->r.net.inflight);
    packet(m,sub,81,0);assert(!tick(m));
    assert(m->r.session.state==C80_SESSION_DRAIN && m->deletes==0 && m->net_busy);
    until_state(m,C80_SESSION_IDLE);assert(m->deletes==1 && !m->sta_live && !m->net_busy);
    assert(m->r.net.data_completed==1 && m->r.net.submitted==m->r.net.completed);
    assert(!memcmp(m->pool.auth_frame+4,client_mac,6));
    printf("PASS SESSION disconnect subtype%u while TX completion order%u waits before STA delete\n",sub,order);
    ++cases;free(m);
}
static void duplicate_association(unsigned sub)
{
    struct session_model *m=fixture();initial_connection(m);data_once(m);
    unsigned posts=m->command_posts,links=m->links,completed=m->r.net.management_completed;
    packet(m,sub,21,0);until_state(m,C80_SESSION_CONNECTED);
    assert(m->command_posts==posts && m->links==links && m->r.session.connections==1);
    assert(m->r.net.management_completed==completed+1);data_once(m);
    printf("PASS SESSION duplicate subtype%u response without extra MCU STA or cfg80211 NEW_STA\n",sub);
    ++cases;free(m);
}
static void unauthenticated_reassociation(void)
{
    struct session_model *m=fixture();initial_connection(m);packet(m,12,10,0);until_state(m,C80_SESSION_IDLE);
    unsigned posts=m->command_posts;packet(m,2,11,0);
    for(unsigned i=0;i<10;++i)assert(!tick(m));
    assert(m->r.session.state==C80_SESSION_IDLE && !m->r.session.pending_assoc && m->command_posts==posts);
    cycle(m,0,20);printf("PASS SESSION DEAUTH invalidates authentication; bare reassociation refused\n");
    ++cases;free(m);
}
static void retry_during_auth(unsigned order)
{
    struct session_model *m=fixture();initial_connection(m);m->net_fault=order;
    packet(m,11,50,0);assert(!tick(m) && m->r.session.state==C80_SESSION_AUTH_TX && m->net_busy);
    packet(m,11,50,0x800);assert(!tick(m) && m->r.session.state==C80_SESSION_AUTH_TX);
    assert(!m->r.session.pending_auth && !m->r.session.aborted);
    until_state(m,C80_SESSION_ASSOC_WAIT);packet(m,11,50,0x800);assert(!tick(m));
    assert(m->r.session.state==C80_SESSION_ASSOC_WAIT && !m->r.session.pending_auth);
    packet(m,0,51,0);until_state(m,C80_SESSION_CONNECTED);
    assert(m->r.session.connections==2 && m->creates==2 && m->deletes==1);
    printf("PASS SESSION AUTH retry during pending completion order%u and association wait is idempotent\n",order);
    ++cases;free(m);
}
static void receive_history(unsigned mode)
{
    struct session_model *m=fixture();initial_connection(m);c80_u8 v[68]={0};
    c80_put16(v,sizeof(v));v[3]=0x50;v[6]=0x80;v[8]=1;
    c80_put16(v+16,0x908);memcpy(v+18,client_mac,6);c80_put16(v+24,0x120);
    memcpy(v+32,own_mac,6);memcpy(v+38,client_mac,6);c80_setbe16(v+44,0x800);
    v[46]=0x45;c80_setbe16(v+48,20);
    c80_net_receive(&m->io,&m->r,v,sizeof(v),32);assert(m->received==1);
    c80_net_receive(&m->io,&m->r,v,sizeof(v),32);assert(m->received==1 && m->r.net.rx_duplicate==1);
    cycle(m,mode,20);c80_net_receive(&m->io,&m->r,v,sizeof(v),32);
    assert(m->received==2 && m->r.net.rx_delivered==2);
    printf("PASS SESSION reconnect mode%u resets peer RX duplicate history\n",mode);++cases;free(m);
}
static void management_status(unsigned variant)
{
    struct session_model *m=fixture();initial_connection(m);c80_u8 *v=m->pool.data[0][0],*p=v+16;
    c80_put16(v,46);v[3]=0x40;c80_put16(p,0xb0);memcpy(p+4,own_mac,6);
    memcpy(p+10,client_mac,6);memcpy(p+16,own_mac,6);c80_put16(p+26,1);c80_put16(p+22,88<<4);
    if(variant<8)v[10]=1u<<variant;else if(variant<10)v[11]=1u<<(variant-8);else v[9]=1u<<(variant-6);
    m->pool.rx[0][0].ctrl=C80_DONE|C80_LS0|(46u<<16);assert(!c80_radio_receive(&m->io,&m->r));
    unsigned bad=variant<5 || variant==7 || variant>=8;
    assert(m->r.session.pending_auth==!bad && m->r.session.bad==bad && m->r.rx0_rearmed==1);
    printf("PASS SESSION raw management RXD status bit%u %s before state mutation\n",variant,bad?"rejected":"allowed");
    ++cases;free(m);
}
static void bad_request(unsigned variant)
{
    struct session_model *m=fixture();initial_connection(m);c80_u8 p[64]={0};unsigned bytes=30;
    c80_put16(p,0xb0);memcpy(p+4,own_mac,6);memcpy(p+10,client_mac,6);memcpy(p+16,own_mac,6);c80_put16(p+26,1);
    switch(variant) {
    case 0:p[4]^=4;break;case 1:p[16]^=4;break;case 2:p[10]^=4;break;
    case 3:c80_put16(p,0xb1);break;case 4:c80_put16(p,0x40b0);break;
    case 5:c80_put16(p,0x4b0);break;case 6:c80_put16(p+22,1);break;
    case 7:c80_put16(p+24,1);break;case 8:c80_put16(p+26,2);break;
    case 9:c80_put16(p+28,1);break;case 10:bytes=29;break;
    default:assert(0);
    }
    unsigned posts=m->command_posts,submitted=m->r.net.submitted;
    c80_management_receive(&m->io,&m->r,p,bytes);assert(!tick(m));
    assert(m->command_posts==posts && m->r.net.submitted==submitted && m->r.session.state==C80_SESSION_CONNECTED);
    printf("PASS SESSION invalid/foreign AUTH variant%u leaves connected peer and DMA untouched\n",variant);
    ++cases;free(m);
}
static void fault_case(unsigned fault,unsigned command_fault,unsigned expected)
{
    struct session_model *m=fixture();initial_connection(m);m->net_fault=fault;m->command_fault=command_fault;
    packet(m,11,40,0);unsigned rc=0;
    for(unsigned i=0;i<2200 && !rc;++i)rc=tick(m);
    if(rc!=expected)fprintf(stderr,"FAULT net%u cmd%u got%u wanted%u state%u\n",fault,command_fault,rc,expected,m->r.session.state);
    assert(rc==expected);owned(m);
    if(command_fault==1 || command_fault==2 || command_fault==3) {
        c80_u8 *p;unsigned slot;unsigned writes=m->writes;
        assert(c80_command_reuse(&m->io,&m->r,92,&p,&slot)==C80_COMMAND_REUSE && writes==m->writes);
    }
    printf("PASS SESSION fault net%u command%u rc%u preserves_owned_memory\n",fault,command_fault,rc);++cases;free(m);
}
static void parser_guard(unsigned n)
{
    long page=sysconf(_SC_PAGESIZE);c80_u8 *v=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(v!=MAP_FAILED && !mprotect(v+page,page,PROT_NONE));
    struct session_model *m=fixture();c80_u8 *p=v+page-n;memset(p,0,n);
    if(n>=24) { c80_put16(p,0xb0);memcpy(p+4,own_mac,6);memcpy(p+10,client_mac,6);memcpy(p+16,own_mac,6); }
    if(n>=28)c80_put16(p+26,1);
    unsigned writes=m->writes;c80_management_receive(&m->io,&m->r,p,n);assert(m->writes==writes);
    assert(m->r.auth_captured==(n>=30));
    printf("PASS SESSION guard bytes%u\n",n);++cases;free(m);assert(!munmap(v,2*page));
}
static void load(const char *name,c80_u8 *out,unsigned n)
{ FILE *f=fopen(name,"rb");assert(f && fread(out,1,n,f)==n && fgetc(f)==EOF);fclose(f); }
int main(int argc,char **argv)
{
    (void)c80_run;(void)c80_irq_prepare;(void)c80_irq_unmask;(void)c80_irq_event;(void)c80_irq_stop;
    setvbuf(stdout,NULL,_IOLBF,0);assert(argc==6);
    load(argv[1],auth_oracle,32);load(argv[2],assoc_oracle,32);load(argv[3],data_oracle,32);
    load(argv[5],reassoc_oracle,32);
    FILE *f=fopen(argv[4],"rb");assert(f);
    for(unsigned i=0;i<2;++i) { assert(fread(&sta_bytes[i],4,1,f)==1 && sta_bytes[i]<=308);assert(fread(sta_oracle[i],1,sta_bytes[i],f)==sta_bytes[i]); }
    assert(fgetc(f)==EOF);fclose(f);
    const unsigned counts[]={1,2,3,17,129,2049,5000};
    for(unsigned i=0;i<sizeof(counts)/sizeof(counts[0]);++i)for(unsigned mode=0;mode<4;++mode)stress(counts[i],mode,0);
    for(unsigned order=4;order<=5;++order)for(unsigned mode=0;mode<4;++mode)stress(17,mode,order);
    for(unsigned order=4;order<=5;++order)for(unsigned sub=10;sub<=12;sub+=2)inflight_disconnect(sub,order);
    duplicate_association(0);duplicate_association(2);unauthenticated_reassociation();
    retry_during_auth(4);retry_during_auth(5);
    for(unsigned mode=0;mode<3;++mode)receive_history(mode);
    for(unsigned variant=0;variant<14;++variant)management_status(variant);
    for(unsigned variant=0;variant<11;++variant)bad_request(variant);
    for(unsigned n=0;n<=128;++n)parser_guard(n);
    fault_case(1,0,C80_NET_TIMEOUT);fault_case(2,0,C80_NET_TIMEOUT);fault_case(3,0,C80_NET_DESC);
    fault_case(6,0,C80_NET_TOKEN);fault_case(7,0,C80_NET_TOKEN);fault_case(8,0,C80_NET_PUBLISH);
    fault_case(0,1,C80_RX_TIMEOUT);fault_case(0,2,C80_TX_TIMEOUT);fault_case(0,3,C80_RX_TIMEOUT);
    fault_case(0,4,C80_COMMAND_REUSE);fault_case(0,5,C80_COMMAND_REUSE);fault_case(0,6,C80_STA_REJECTED);
    printf("PASS: %u actual session/management/command-recycle scenarios; ASan/UBSan; hardware effects synthetic.\n",cases);return 0;
}
