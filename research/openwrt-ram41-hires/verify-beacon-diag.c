/* SPDX-License-Identifier: GPL-2.0-only */
/* Run actual key/core callbacks with synthetic MMIO and the OEM byte oracle. */
#include "private/beacon-diag-fixture.h"
static struct c80_beacon_diag published[8];
static unsigned publications,mac_reads,dcases;
static c80_u32 diag_read(void *opaque,c80_u32 a)
{
    for(unsigned i=0;i<12;++i) if(a==c80_state_regs[i]) {
        ++mac_reads;return 0x12000000u|(publications<<8)|i;
    }
    return rd(opaque,a);
}
static void publish(void *opaque,const struct c80_beacon_diag *d)
{
    struct secure_model *s=opaque;assert(publications<8);
    assert(d==&s->m.r.beacon_diag);published[publications++]=*d;
}
static void dpass(const char *name) { ++dcases;printf("PASS BEACON DIAG %s\n",name); }
static struct secure_model *diag_fixture(void)
{
    struct secure_model *s=secure_fixture();static c80_u8 frame[96];
    frame[34]=0x11;s->m.io.ap_beacon=frame;s->m.io.ap_beacon_bytes=96;
    s->m.io.ap_tim_offset=56;s->m.io.read=diag_read;s->m.io.beacon_diag=publish;
    memset(published,0,sizeof(published));publications=mac_reads=0;return s;
}
int main(int argc,char **argv)
{
    assert(argc==2);load_security(argv[1]);for(unsigned i=0;i<16;++i)synthetic_key[i]=i*13+3;
    struct secure_model *s=diag_fixture();struct c80_result *r=&s->m.r;
    assert(!request(s,C80_KEY_ADD,0) && !s->result && s->posts==2);
    assert(publications==3 && mac_reads==36 && r->beacon_diag.saved==7);
    dpass("actual-OEM-BMC-GTK-command-bytes-and-three-ordered-snapshots");
    for(unsigned k=0;k<3;++k) {
        const struct c80_beacon_diag_sample *v=&published[k].sample[k];
        assert(published[k].saved==((1u<<(k+1))-1) && !v->guard_fault && v->phase==37);
        assert(v->gtk==(k==2) && v->bmc==(k>0) && v->commands==22+k);
        assert(v->frame_bytes==96 && v->tim_offset==56 && v->capability==0x11);
        dpass("phase-key-state-command-count-real-template-length-and-capability");
        for(unsigned i=0;i<12;++i) {
            assert(v->regs[i]==(0x12000000u|(k<<8)|i));
            dpass("capture-preserves-raw-register-value-without-packet-or-key-data");
        }
    }
    unsigned writes=s->m.writes,posts=s->posts;
    c80_beacon_diag_capture(&s->m.io,r,3);
    assert(publications==4 && mac_reads==48 && published[3].saved==15);
    assert(published[3].sample[3].gtk==1 && published[3].sample[3].bmc==1);
    assert(s->m.writes==writes && s->posts==posts);
    dpass("precleanup-snapshot-keeps-live-key-state-and-sends-no-command");
    assert(!c80_security_stop(&s->m.io,r) && !r->security.gtk && !r->security.bmc_live);
    assert(published[3].sample[3].gtk==1 && published[3].sample[3].bmc==1);
    dpass("published-precleanup-observation-survives-key-and-BMC-deletion");
    free(s);
    for(unsigned kind=0;kind<3;++kind) {
        s=diag_fixture();r=&s->m.r;
        if(kind==0) *reg(&s->m,C80_GLO)=0;
        if(kind==1) *reg(&s->m,C80_OWN)|=1;
        if(kind==2) *reg(&s->m,C80_SYNC)=2;
        c80_beacon_diag_capture(&s->m.io,r,0);
        assert(publications==1 && !mac_reads && published[0].sample[0].guard_fault && !s->posts && !s->m.writes);
        dpass("bad-DMA-ownership-ready-guard-skips-MAC-register-reads-and-all-writes");free(s);
    }
    s=diag_fixture();r=&s->m.r;
    c80_beacon_diag_capture(&s->m.io,r,4);
    assert(!publications && !mac_reads && !r->beacon_diag.saved);
    dpass("out-of-range-index-does-not-access-hardware-or-publish");
    s->m.io.beacon_diag=NULL;c80_beacon_diag_capture(&s->m.io,r,0);
    assert(!publications && !mac_reads && !r->beacon_diag.saved);
    dpass("disabled-diagnostics-do-not-access-hardware-or-change-results");
    assert(!request(s,C80_KEY_ADD,0) && !publications && !mac_reads && s->posts==2);
    dpass("disabled-diagnostics-preserve-key-exchange-and-command-count");free(s);
    printf("PASS: %u actual-core beacon/key diagnostic cases; synthetic MMIO, no MCU/RF emulation.\n",dcases);
    return 0;
}
