/* SPDX-License-Identifier: GPL-2.0-only */
/* Real RX0/parser/session/key code, synthetic descriptor and MCU producer.
 * This cannot establish which RXD flags the owner's failed frames carried. */
#ifndef C80_RX_FIXTURE
#define C80_RX_FIXTURE "private/rx-status-fixture.h"
#endif
#include C80_RX_FIXTURE
static unsigned rcases;
static void rpass(const char *s) { ++rcases;printf("PASS RX STATUS %s\n",s); }
static struct secure_model *connected(void)
{
    struct secure_model *s=secure_fixture();struct c80_result *r=&s->m.r;
    r->session.started=r->session.authenticated=r->session.epoch_linked=1;
    r->session.state=C80_SESSION_CONNECTED;r->session.connections=1;
    r->security.gtk=r->security.ptk=r->security.authorized=1;
    memcpy(r->security.ptk_key,synthetic_key,16);r->security.rx_pn[16]=91;
    return s;
}
static void raw(struct secure_model *s,unsigned sub,unsigned status,unsigned variant)
{
    struct session_model *m=&s->m;unsigned index=m->r.rx_next[0];
    c80_u8 *v=m->pool.data[0][index],*p=v+16;unsigned bytes=sub==11?30:26;
    memset(v,0,100);c80_put32(v,(2u<<29)|(bytes+16));c80_put32(v+8,status|1);
    c80_put16(p,sub<<4);c80_put16(p+22,50<<4);
    memcpy(p+4,own_mac,6);memcpy(p+10,client_mac,6);memcpy(p+16,own_mac,6);
    if(sub==11)c80_put16(p+26,1);else c80_put16(p+24,3);
    switch(variant) {
    case 1:p[10]^=2;break;case 2:p[4]^=2;break;case 3:p[16]^=2;break;
    case 4:p[1]|=0x40;break;case 5:p[1]|=0x80;break;
    case 6:p[1]|=4;break;case 7:p[22]|=1;break;
    case 8:p[1]|=1;break;case 9:p[0]|=4;break;case 10:p[0]|=1;break;
    case 11:p[24]=1;break;case 12:p[24]=0;break;
    default:assert(variant==0);
    }
    m->pool.rx[0][index].ctrl=C80_DONE|C80_LS0|((bytes+16)<<16);
    assert(!c80_radio_receive(&m->io,&m->r));
    assert(m->r.rx0_rearmed && !(m->pool.rx[0][index].ctrl&C80_DONE));
}
#ifndef C80_RX_OLD_BASELINE
static void lifecycle_write(void *o,c80_u32 a,c80_u32 value)
{
    struct secure_model *s=o;
    if(a==0x180043f8 && s->m.r.sta_waiting)wr(o,a,value);
    else {
        secure_write(o,a,value);
        if(a==0x180043f8)s->m.last_sequence=s->m.r.sequence;
    }
}
#endif
int main(int argc,char **argv)
{
    assert(argc==3);load_security(argv[1]);
    for(unsigned i=0;i<16;++i)synthetic_key[i]=i*13+3;
    struct secure_model *s=connected();
    raw(s,11,0x44000,0);
#ifdef C80_RX_OLD_BASELINE
    assert(!s->m.r.session.pending_auth && !s->m.r.session.auth_requests &&
           s->m.r.session.bad==1 && s->m.r.security.ptk);
    puts("PASS: RAM39 actual RX0 gate discards unprotected peer auth with CCMP WCID/CipherMis before parser.");
    free(s);return 0;
#else
    assert(s->m.r.session.pending_auth && s->m.r.session.auth_requests==1 &&
           s->m.r.management_filter.peer_plaintext==1 && s->m.r.security.ptk);
    rpass("actual-RX0-CCMP-WCID-CipherMis-plain-auth-queues-intention-only");free(s);
    for(unsigned mode=0;mode<16;++mode)for(unsigned cm=0;cm<2;++cm) {
        s=connected();raw(s,11,(mode<<12)|(cm<<18),0);
        unsigned allowed=mode==0 || mode==4;
        assert(!!s->m.r.session.pending_auth==allowed);
        assert(s->m.r.security.rx_pn[16]==91 && s->m.r.security.ptk && !s->posts);
        rpass("all-mode-and-CM-combinations-require-plain-current-peer-CCMP-or-none");free(s);
    }
    for(unsigned bit=16;bit<26;++bit) {
        if(bit==18)continue;
        s=connected();raw(s,11,0x44000|(1u<<bit),0);
        assert(!s->m.r.session.pending_auth && s->m.r.management_filter.rejected==1 &&
               s->m.r.management_filter.status_bits[bit-16]==1 && s->m.r.security.ptk);
        rpass("CM-exception-never-waives-FCS-ICV-MIC-length-translation-or-other-status");free(s);
    }
    for(unsigned variant=1;variant<=10;++variant) {
        s=connected();raw(s,11,0x44000,variant);
        assert(!s->m.r.session.pending_auth && s->m.r.security.ptk && !s->posts);
        rpass("foreign-peer-DA-BSSID-Protected-Order-fragment-DS-type-version-refused");free(s);
    }
    for(unsigned variant=0;variant<5;++variant) {
        s=connected();struct c80_result *r=&s->m.r;
        if(variant==0)r->security.ptk=0;
        if(variant==1)r->session.sta_live=0;
        if(variant==2)r->session.started=0;
        if(variant==3)r->phase=38;
        if(variant==4)s->m.io.wpa2_test=0;
        raw(s,11,0x44000,0);assert(!r->session.pending_auth);
        rpass("relaxation-requires-existing-WPA2-PTK-live-STA-runtime-session");free(s);
    }
    for(unsigned sub=0;sub<16;++sub) {
        s=connected();raw(s,sub,0x44000,0);
        unsigned lifecycle=sub==0 || sub==2 || sub==10 || sub==11 || sub==12;
        assert(s->m.r.management_filter.peer_plaintext==lifecycle);
        if(sub==10 || sub==12)assert(s->m.r.session.drop_requested);
        if(sub==0 || sub==2)assert(!s->m.r.session.pending_assoc); /* no valid RSN/body */
        rpass("only-five-lifecycle-subtypes-and-original-body-RSN-parser");free(s);
    }
    s=connected();raw(s,11,0x44000,11);
    assert(!s->m.r.session.pending_auth && s->m.r.session.bad==1 && s->m.r.security.ptk);
    rpass("accepted-metadata-cannot-bypass-open-auth-algorithm-validation");free(s);
    s=connected();raw(s,12,0x44000,12);
    assert(!s->m.r.session.drop_requested && s->m.r.session.bad==1 && s->m.r.security.ptk);
    rpass("zero-reason-disconnect-cannot-clear-peer-key");free(s);
    long page=sysconf(_SC_PAGESIZE);
    c80_u8 *guard=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(guard!=MAP_FAILED && !mprotect(guard+page,page,PROT_NONE));
    for(unsigned len=0;len<=40;++len) {
        c80_u8 frame[40]={},metadata[16]={};c80_u8 *p=guard+page-len;
        s=connected();c80_put16(frame,0xb0);c80_put16(frame+26,1);
        memcpy(frame+4,own_mac,6);memcpy(frame+10,client_mac,6);memcpy(frame+16,own_mac,6);
        memcpy(p,frame,len);c80_put32(metadata+8,0x44001);
        if(c80_management_status(&s->m.io,&s->m.r,metadata,p,len))
            c80_management_receive(&s->m.io,&s->m.r,p,len);
        assert(!!s->m.r.session.pending_auth==(len>=30));
        rpass("guard-page-truncated-metadata-accepted-auth-body-bounds");free(s);
    }
    assert(!munmap(guard,page*2));
    /* Exercise teardown through the actual worker, with independently traced
     * OEM key bodies and STA delete. No synthetic hostapd station=0 shortcut. */
    s=connected();s->m.io.write=lifecycle_write;
    FILE *f=fopen(argv[2],"rb");assert(f);
    for(unsigned i=0;i<2;++i) {
        assert(fread(&sta_bytes[i],4,1,f)==1 && sta_bytes[i]<=308);
        assert(fread(sta_oracle[i],1,sta_bytes[i],f)==sta_bytes[i]);
    }
    assert(fgetc(f)==EOF);fclose(f);assert(sta_bytes[1]==92);
    raw(s,11,0x44000,0);s->m.r.net.inflight=1;
    assert(!c80_session_step(&s->m.io,&s->m.r) && !s->posts &&
           s->m.r.session.state==C80_SESSION_DRAIN && s->m.r.security.ptk);
    rpass("new-plain-auth-waits-for-inflight-TX-before-key-or-STA-delete");
    s->m.r.net.inflight=0;
    assert(!c80_session_step(&s->m.io,&s->m.r));
    assert(!s->m.r.security.ptk && !s->m.r.security.authorized &&
           !s->m.r.security.rx_pn[16] && s->m.r.security.gtk &&
           s->m.r.session.state==C80_SESSION_AUTH_TX && !s->m.r.session.sta_live &&
           s->posts==2 && s->m.deletes==1 && s->m.r.session.pending_auth==0 &&
           s->m.r.net.management_pending==C80_REPLY_AUTH);
    for(unsigned i=0;i<16;++i)assert(!s->m.r.security.ptk_key[i]);
    rpass("same-worker-removes-old-PTK-and-STA-before-queuing-new-auth-reply");free(s);
    printf("PASS: %u RX status cases; actual shared core, synthetic hardware effects.\n",rcases);
    return 0;
#endif
}
