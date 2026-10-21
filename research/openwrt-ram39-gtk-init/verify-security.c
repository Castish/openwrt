/* SPDX-License-Identifier: GPL-2.0-only */
/* Actual shared core; independent synthetic MCU/RXD and real ARM-produced
 * byte oracles. This does not emulate CCMP crypto, RF or a physical MCU. */
#define main c80_legacy_session_main
#include "verify-session.c"
#undef main
struct secure_model {
    struct session_model m;struct c80_key_request request;
    unsigned pending,done,result,posts,delivered,fault;
};
static unsigned scases;
static c80_u8 key_oracle[6][52],sta_security[5][252],tx_security[2][32],bss_security[2][52];
static c80_u8 synthetic_key[16];
static void spass(const char *name) { ++scases;printf("PASS SECURITY %s\n",name); }
static void secure_write(void *o,c80_u32 a,c80_u32 value)
{
    struct secure_model *s=o;struct session_model *m=&s->m;owned(m);
    if(a!=0x180043f8) { wr(o,a,value);return; }
    unsigned slot=(value+127)%128;struct c80_desc *d=&m->pool.tx[slot];
    unsigned bytes=(d->ctrl>>16)&0x3fff;const c80_u8 *p=dma_pointer(m,d->addr,bytes);
    c80_u8 reply[44]={},expect[252];unsigned n=bytes-64,k,body;
    if(p[41]==0x26) {
        unsigned off=m->r.phase-25;assert(off<2 && n==(off?36u:52u));
        memcpy(expect,bss_security[off],n);memcpy(expect+(off?20:36),own_mac,6);assert(!memcmp(expect,p+64,n));
        *reg(m,a)=value;d->ctrl|=C80_DONE;*reg(m,0x180043fc)=value;++s->posts;
        c80_put32(reply,(7u<<29)|44);c80_put16(reply+16,28);c80_put16(reply+18,0xe000);reply[20]=0xed;reply[21]=p[39];reply[24]=reply[28]=0x26;c80_put16(reply+38,off?1:2);event(m,reply,44);return;
    }
    assert(!m->net_busy && !m->command_busy && (n==52 || n==28 || n==244 || n==252));
    assert(p[36]==0xed && p[43]==1 && p[39] && p[39]<=15);
    assert(value==(*reg(m,a)+1)%128 && !d->addr1 && !d->info);
    if(p[41]==0x32) {
        assert(n==52 && p[38]==1);
        k=p[76]?2+(p[64]?0:2)+(p[79]==4):p[64]?0:1;
        memcpy(expect,key_oracle[k],52);
    } else {
        assert(p[41]==0x25 && !p[38]);
        k=p[65]?(n==244?2:p[80]==2?3:4):n==252?0:1;
        memcpy(expect,sta_security[k],n);
        if(p[65]) { memcpy(expect+20,client_mac,6);if(n==244)memcpy(expect+44,client_mac,6); }
    }
    assert(!memcmp(p+64,expect,n));++s->posts;
    memcpy(m->cmd_snapshot,p,bytes);m->command_pointer=p;m->command_bytes=bytes;m->command_busy=1;
    *reg(m,a)=value;
    if(s->fault!=3) { d->ctrl|=C80_DONE;*reg(m,0x180043fc)=value; }
    if(s->fault==9)d->addr^=16;
    if(s->fault==2 || s->fault==10)return;
    body=p[41]==0x32?8:16;
    c80_put32(reply,(7u<<29)|(28+body));c80_put16(reply+16,12+body);c80_put16(reply+18,0xe000);
    reply[20]=0xed;reply[21]=s->fault==4?(p[39]%15)+1:p[39];reply[24]=p[41];reply[28]=p[41];
    if(s->fault==1)c80_put32(reply+32,1);
    if(s->fault==5)reply[24]^=1;
    if(s->fault==6)c80_put16(reply+16,19);
    if(s->fault==7)reply[28]^=1;
    event(m,reply,28+body);
    if(!s->fault || s->fault==1 || s->fault==5 || s->fault==6 || s->fault==7)m->command_busy=0;
}
static int fetch(void *o,struct c80_key_request *r)
{ struct secure_model *s=o;if(!s->pending)return 0;*r=s->request;s->pending=0;return 1; }
static void done(void *o,const struct c80_key_request *r,c80_u32 status)
{ struct secure_model *s=o;assert(r->serial==s->request.serial);++s->done;s->result=status; }
static int deliver(void *o,const c80_u8 *p,c80_u32 n)
{ struct secure_model *s=o;assert(n>=18 && n<=C80_NET_ETH_MAX && !memcmp(p+6,client_mac,6));++s->delivered;return 0; }
static struct secure_model *secure_fixture(void)
{
    struct session_model *m=fixture();struct secure_model *s=calloc(1,sizeof(*s));assert(s);
    memcpy(&s->m,m,sizeof(*m));free(m);m=&s->m;m->io.context=s;m->io.pool=&m->pool;m->io.write=secure_write;
    m->io.wpa2_test=1;m->io.key_fetch=fetch;m->io.key_done=done;m->io.net_receive=deliver;
    memcpy(m->pool.session_peer,client_mac,6);m->r.net.linked=m->r.session.sta_live=m->sta_live=1;
    m->r.sta_valid[0]=m->r.auth_captured=m->r.auth_submitted=m->r.auth_dma_done=m->r.auth_token_returned=1;
    m->r.assoc_captured=m->r.assoc_submitted=m->r.assoc_dma_done=m->r.assoc_token_returned=1;
    return s;
}
static unsigned request(struct secure_model *s,unsigned op,unsigned pair)
{
    memset(&s->request,0,sizeof(s->request));s->request.serial=s->done+1;
    s->request.operation=op;s->request.pairwise=pair;s->request.index=pair?0:1;
    memcpy(s->request.peer,client_mac,6);memcpy(s->request.key,synthetic_key,16);
    s->pending=1;return c80_security_step(&s->m.io,&s->m.r);
}
static void feed(struct secure_model *s,unsigned protected,unsigned mode,unsigned type,unsigned pn,unsigned tid)
{
    c80_u8 v[96]={};unsigned off=48,len=type==0x888e?4:20;
    v[3]=(9u<<1)|(2u<<5);v[6]=0x80;v[8]=1;v[9]=mode<<4;
    c80_put16(v+16,0x0108|(protected?0x4000:0)|(tid<16?0x80:0));memcpy(v+18,client_mac,6);
    c80_put16(v+24,(s->delivered+1)<<4);c80_put16(v+26,tid&15);
    c80_put32(v+32,pn);memcpy(v+off,own_mac,6);memcpy(v+off+6,client_mac,6);c80_setbe16(v+off+12,type);
    if(type==0x888e) { v[off+14]=2;v[off+15]=1; }
    else { v[off+14]=0x45;c80_setbe16(v+off+16,20); }
    c80_net_receive(&s->m.io,&s->m.r,v,off+14+len,off);
}
static void load_security(const char *path)
{
    FILE *f=fopen(path,"rb");assert(f);unsigned n=0;
    for(unsigned i=0;i<6;++i)assert(fread(key_oracle[i],1,52,f)==52);
    for(unsigned i=0;i<5;++i) { assert(fread(&n,4,1,f)==1 && n==(i==0?252u:i==2?244u:28u));assert(fread(sta_security[i],1,n,f)==n); }
    assert(fread(tx_security,1,64,f)==64);
    for(unsigned i=0;i<2;++i) { assert(fread(&n,4,1,f)==1 && n==(i?36u:52u));assert(fread(bss_security[i],1,n,f)==n); }
    assert(fgetc(f)==EOF);fclose(f);
}
int main(int argc,char **argv)
{
    assert(argc==2);load_security(argv[1]);for(unsigned i=0;i<16;++i)synthetic_key[i]=i*13+3;
    struct secure_model *s=secure_fixture();struct c80_result *r=&s->m.r;
    s->m.io.radio_test=0;s->m.io.bss_period_test=1;r->devinfo_valid[0]=1;
    assert(!c80_bss_roundtrip(&s->m.io,r) && s->posts==2 && r->bss_complete);spass("actual-WPA2-BSS-cipher4-and-period100-DTIM1-on-off-OEM-oracle");
    free(s);s=secure_fixture();r=&s->m.r;
    assert(!request(s,C80_KEY_AUTHORIZE,1) && s->result==C80_KEY_STATE && !s->posts);spass("authorization-without-keys-refused-before-MMIO");
    assert(!request(s,C80_KEY_ADD,0) && !s->result && r->security.gtk && r->security.bmc_live && s->posts==2);spass("actual-OEM-BMC-STA-and-GTK-commands");
    assert(!request(s,C80_KEY_ADD,1) && !s->result && r->security.ptk && s->posts==3);spass("actual-OEM-CCMP-PTK-command");
    r->security.rx_pn[16]=19;assert(!request(s,C80_KEY_ADD,1) && !s->result && s->posts==3 && r->security.rx_pn[16]==19 && r->security.key_idempotent==1);spass("identical-PTK-reinstall-preserves-PN-and-sends-no-command");
    s->request.serial=++s->done;s->request.key[0]^=1;s->pending=1;assert(!c80_security_step(&s->m.io,r) && s->result==C80_KEY_STATE && s->posts==3);spass("changed-live-key-refused-without-resetting-PN");
    assert(!request(s,C80_KEY_AUTHORIZE,1) && !s->result && r->security.authorized && s->posts==4);spass("port-secure-BASIC-update-after-both-keys");
    assert(!request(s,C80_KEY_UNAUTHORIZE,1) && !s->result && !r->security.authorized && s->posts==5);spass("port-unauthorize-BASIC-update");
    assert(!request(s,C80_KEY_DEL,1) && !s->result && !r->security.ptk && !r->security.rx_pn[16] && s->posts==7);spass("actual-two-step-OEM-PTK-removal-and-PN-clear");
    assert(!c80_security_stop(&s->m.io,r) && !r->security.gtk && !r->security.bmc_live && s->posts==10);spass("GTK-removal-and-BMC-delete-clean-stop");
    for(unsigned i=0;i<16;++i) { assert(!r->security.ptk_key[i] && !r->security.gtk_key[i]); }
    spass("CPU-key-cache-wiped-after-ACKed-removal");free(s);
    for(unsigned fault=1;fault<=10;++fault) {
        if(fault==8)continue;
        s=secure_fixture();s->fault=fault;s->m.r.security.bmc_live=1;
        unsigned rc=request(s,C80_KEY_ADD,1);assert(rc && s->done==1 && s->result==rc && !s->m.r.security.ptk && !s->m.r.security.authorized);
        if(fault==2 || fault==3 || fault==4 || fault==9 || fault==10)assert(s->m.us<4000000 && s->m.r.command_cycle.acked<s->m.r.command_submitted);
        spass("MCU-reject-timeout-DDONE-sequence-extension-length-echo-descriptor-fail-closed");free(s);
    }
    s=secure_fixture();r=&s->m.r;
    feed(s,0,0,0x800,1,16);assert(!s->delivered);spass("unencrypted-IP-blocked-before-PTK");
    feed(s,0,0,0x888e,1,16);assert(s->delivered==1);spass("EAPOL-delivered-before-authorization");
    feed(s,1,4,0x800,1,16);assert(s->delivered==1);spass("protected-IP-blocked-without-PTK");
    r->security.ptk=1;feed(s,1,4,0x800,1,16);assert(s->delivered==1);spass("protected-IP-blocked-before-hostapd-authorization");
    r->security.authorized=1;feed(s,1,4,0x800,1,16);assert(s->delivered==2 && r->security.rx_pn[16]==1);spass("CCMP-decrypted-authorized-IP-delivered");
    feed(s,1,4,0x800,1,16);assert(s->delivered==2 && r->security.rx_replay==1);spass("repeated-PN-rejected");
    feed(s,1,4,0x800,0,16);assert(s->delivered==2 && r->security.rx_replay==2);spass("zero-or-lower-PN-rejected");
    feed(s,1,3,0x800,2,16);assert(s->delivered==2 && r->security.rx_pn[16]==1);spass("cipher-mismatch-blocked-without-consuming-PN");
    feed(s,1,4,0x800,2,16);assert(s->delivered==3);spass("increasing-PN-accepted");
    feed(s,1,4,0x800,1,3);assert(s->delivered==4 && r->security.rx_pn[3]==1);spass("independent-QoS-TID-replay-counters");
    for(unsigned bit=0;bit<8;++bit) {
        c80_u8 v[48]={};v[3]=18;v[8]=1;v[9]=0x40;v[10]=1u<<bit;c80_put32(v+32,3);
        assert(!c80_security_receive(&s->m.io,r,v,48,48,0x4108,16,0x800) && r->security.rx_pn[16]==2);spass("hardware-crypto-or-FCS-error-refused-without-PN-update");
    }
    c80_u8 v[48]={};v[9]=0x40;v[3]=16;assert(!c80_security_receive(&s->m.io,r,v,48,32,0x4108,16,0x800));spass("missing-group1-PN-refused");
    v[3]=18;assert(!c80_security_receive(&s->m.io,r,v,47,32,0x4108,16,0x800));spass("truncated-or-overlapping-PN-refused");
    for(unsigned p=0;p<2;++p) {
        c80_u8 *e=s->m.pool.net.ethernet;memcpy(e,client_mac,6);memcpy(e+6,own_mac,6);c80_setbe16(e+12,p?0x800:0x888e);
        memset(e+14,0,20);if(p){e[14]=0x45;c80_setbe16(e+16,20);}else e[14]=2;
        assert(c80_net_frame_fields(&s->m.io,0,p?34:18,16,1));
        c80_u8 expected[32];memcpy(expected,tx_security[p],32);c80_put16(expected,32+(p?52:36));
        assert(!memcmp(s->m.pool.net.tx[0].header,expected,32));
        assert(c80_get16(s->m.pool.net.tx[0].frame)==(p?0x4208:0x208));spass("TXD-protection-bit-compared-to-actual-OEM-ARM");
    }
    r->security.authorized=0;assert(!c80_security_transmit(&s->m.io,r,34));spass("TX-IP-blocked-before-authorization");free(s);
    c80_u8 good[]={48,20,1,0,0,0x0f,0xac,4,1,0,0,0x0f,0xac,4,1,0,0,0x0f,0xac,2,0,0};
    assert(c80_rsn_valid(good+2,20));spass("RSN-WPA2-CCMP-PSK-accepted");
    for(unsigned b=0;b<20;++b) {
        c80_u8 bad[22];memcpy(bad,good,22);bad[b+2]^=0x80;
        assert(!c80_rsn_valid(bad+2,20));spass("unsupported-suite-version-count-or-capability-refused");
    }
    s=secure_fixture();r=&s->m.r;
    c80_u8 assoc[96]={};memcpy(assoc+4,own_mac,6);memcpy(assoc+10,client_mac,6);memcpy(assoc+16,own_mac,6);
    c80_put16(assoc+22,32);c80_put16(assoc+24,0x11);c80_put16(assoc+26,1);
    assoc[29]=9;memcpy(assoc+30,"C80-RAM34",9);memcpy(assoc+39,(c80_u8[]){1,4,0x82,0x84,0x8b,0x96},6);memcpy(assoc+45,good,22);
    r->assoc_captured=0;c80_assoc_capture(&s->m.io,r,assoc,67);
    assert(r->assoc_captured && r->security.assoc_rsn_bytes==22 && c80_get16(s->m.pool.assoc_frame+24)==0x11);spass("RSN-association-validated-and-privacy-response-built");
    assert(c80_session_assoc_valid(&s->m.io,r,assoc,67));spass("runtime-RSN-association-validation");
    r->assoc_captured=0;c80_put32(assoc+67,c80_crc(assoc,67));c80_assoc_capture(&s->m.io,r,assoc,71);
    assert(r->assoc_captured);spass("association-trailing-FCS-accepted-only-after-independent-CRC");
    r->assoc_captured=0;assoc[68]^=1;c80_assoc_capture(&s->m.io,r,assoc,71);assert(!r->assoc_captured);spass("invalid-trailing-FCS-refused");
    assoc[24]=1;c80_assoc_capture(&s->m.io,r,assoc,67);assert(!r->assoc_captured);spass("open-association-cannot-downgrade-WPA2-AP");
    assoc[24]=0x11;memcpy(assoc+67,good,22);c80_assoc_capture(&s->m.io,r,assoc,89);assert(!r->assoc_captured);spass("duplicate-RSN-IE-refused");free(s);
    long page=sysconf(_SC_PAGESIZE);c80_u8 *guard=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(guard!=MAP_FAILED && !mprotect(guard+page,page,PROT_NONE));
    for(unsigned len=0;len<=30;++len) {
        c80_u8 *p=guard+page-len;if(len)memset(p,0,len);
        assert(!c80_rsn_valid(p,len));spass("RSN-length-guard-page-bounds");
    }
    munmap(guard,page*2);
    printf("PASS: %u WPA2 security cases; actual shared core, ASan/UBSan; all MCU/DMA/crypto/RF effects synthetic.\n",scases);return 0;
}
