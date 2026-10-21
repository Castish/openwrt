/* SPDX-License-Identifier: GPL-2.0-only */
/* Execute real MCU-worker key code; device effects are synthetic. */
#ifndef C80_GTK_FIXTURE
#define C80_GTK_FIXTURE "private/gtk-refresh-fixture.h"
#endif
#include C80_GTK_FIXTURE
static unsigned cases,inject_post,inject_fault,published;
static struct c80_beacon_diag first_diag;
static void gpass(const char *name) { ++cases;printf("PASS GTK REFRESH %s\n",name); }
static void gtk_write(void *o,c80_u32 a,c80_u32 value)
{
    struct secure_model *s=o;
    if(a==0x180043f8) {
        struct c80_desc *d=&s->m.pool.tx[(value+127)%128];
        const c80_u8 *p=dma_pointer(&s->m,d->addr,(d->ctrl>>16)&0x3fff);
        if(p[41]==0x32 && !p[76]) {
            /* Oracle header/delete bytes stay independently OEM-produced;
             * insertion bytes are the caller's explicit synthetic input. */
            unsigned k=p[64]?0:1;memcpy(key_oracle[k]+20,s->request.key,16);
            key_oracle[k][16]=s->request.index;
        }
        if(inject_post && s->posts+1==inject_post) s->fault=inject_fault;
    }
    secure_write(o,a,value);
}
static c80_u32 gtk_read(void *o,c80_u32 a)
{ for(unsigned i=0;i<12;++i)if(a==c80_state_regs[i])return 0x12000000u+i;return rd(o,a); }
static void gtk_diag(void *o,const struct c80_beacon_diag *d)
{ (void)o;++published;if(published==3)first_diag=*d; }
static struct secure_model *start(void)
{
    struct secure_model *s=secure_fixture();inject_post=inject_fault=published=0;
    s->m.io.write=gtk_write;s->m.io.read=gtk_read;s->m.io.beacon_diag=gtk_diag;
    return s;
}
static unsigned key_request(struct secure_model *s,unsigned pair,unsigned index,unsigned variant)
{
    memset(&s->request,0,sizeof(s->request));s->request.serial=s->done+1;
    s->request.operation=C80_KEY_ADD;s->request.pairwise=pair;s->request.index=index;
    memcpy(s->request.peer,client_mac,6);memcpy(s->request.key,synthetic_key,16);
    s->request.key[0]^=variant;s->pending=1;
    return c80_security_step(&s->m.io,&s->m.r);
}
static struct secure_model *with_gtk(void)
{ struct secure_model *s=start();assert(!key_request(s,0,1,0) && s->posts==2 && s->m.r.security.gtk);return s; }
int main(int argc,char **argv)
{
    assert(argc==2);load_security(argv[1]);for(unsigned i=0;i<16;++i)synthetic_key[i]=i*13+3;
    struct secure_model *s=with_gtk();
#ifdef C80_GTK_OLD_BASELINE
    assert(!key_request(s,0,1,1) && s->result==C80_KEY_STATE && s->m.r.security.refused==1 && s->posts==2);
    assert(!s->m.r.security.ptk && !s->m.r.security.authorized);
    puts("PASS: RAM38 actual core reproduces first-station changed-GTK refusal before MCU/PTK/authorization.");free(s);return 0;
#else
    struct c80_security_result *k=&s->m.r.security;
    assert(k->bmc_live && k->key_adds==1 && published==3);gpass("initial-GTK-BMC-keeps-normal-profile");
    k->rx_pn[16]=23;
    assert(!key_request(s,0,1,1) && !s->result && s->posts==5 && k->gtk && !k->ptk && !k->authorized);
    assert(k->gtk_key[0]==(synthetic_key[0]^1) && k->gtk_refreshes==1 && k->key_adds==2 && k->key_deletes==1 && k->rx_pn[16]==23);
    gpass("first-station-GTK-two-ACKed-deletes-then-install-without-PTK-PN-change");
    assert(published==3 && !memcmp(&first_diag,&s->m.r.beacon_diag,sizeof(first_diag)));
    c80_beacon_diag_capture(&s->m.io,&s->m.r,3);assert(published==4 && s->m.r.beacon_diag.sample[3].gtk);
    gpass("initial-three-beacon-snapshots-preserved-through-refresh-and-precleanup");
    assert(!key_request(s,0,1,1) && !s->result && s->posts==5 && k->key_idempotent==1 && k->gtk_refreshes==1);
    gpass("identical-refreshed-GTK-skips-MCU-and-counter-reset");
    assert(!key_request(s,1,0,0) && !s->result && k->ptk);unsigned posts=s->posts;
    assert(!key_request(s,0,1,2) && s->result==C80_KEY_STATE && s->posts==posts && k->gtk_key[0]==(synthetic_key[0]^1));
    gpass("changed-GTK-with-live-PTK-refused-before-MCU");
    assert(!key_request(s,1,0,1) && s->result==C80_KEY_STATE && s->posts==posts && !memcmp(k->ptk_key,synthetic_key,16));
    gpass("changed-PTK-remains-refused");
    k->rx_pn[16]=91;
    assert(!key_request(s,1,0,0) && !s->result && s->posts==posts && k->rx_pn[16]==91);
    gpass("identical-PTK-preserves-replay-counter-and-sends-no-command");
    assert(!key_request(s,0,1,1) && !s->result && s->posts==posts);
    gpass("identical-GTK-with-live-PTK-is-idempotent");
    k->authorized=1;
    assert(!key_request(s,0,1,2) && s->result==C80_KEY_STATE && s->posts==posts && k->authorized);
    gpass("authorized-peer-GTK-rekey-remains-refused");
    k->ptk=0;
    assert(!key_request(s,0,1,2) && s->result==C80_KEY_STATE && s->posts==posts);
    gpass("inconsistent-authorized-without-PTK-refuses-refresh");free(s);
    s=with_gtk();assert(!key_request(s,0,2,1) && !s->result && s->m.r.security.gtk_index==2 && s->posts==5);
    gpass("pre-PTK-GTK-key-ID-change-deletes-before-install");free(s);
    s=with_gtk();s->m.r.net.inflight=1;unsigned done_before=s->done;
    assert(!key_request(s,0,1,1) && s->pending && s->done==done_before && s->posts==2);
    s->m.r.net.inflight=0;assert(!c80_security_step(&s->m.io,&s->m.r) && !s->pending && s->posts==5);
    gpass("refresh-waits-for-inflight-runtime-TX");free(s);
    s=with_gtk();s->m.r.phase=38;
    assert(!key_request(s,0,1,1) && !s->result && s->m.r.security.gtk_refreshes==1);
    gpass("first-client-startup-phase38-refresh-supported");free(s);
    s=with_gtk();assert(!key_request(s,1,0,0));
    assert(!c80_security_forget_peer(&s->m.io,&s->m.r));
    assert(!key_request(s,0,1,1) && !s->result && !s->m.r.security.ptk);
    gpass("GTK-refresh-after-confirmed-peer-key-removal");free(s);
    for(unsigned command=1;command<=3;++command)for(unsigned fault=1;fault<=10;++fault) {
        if(fault==8)continue;
        s=with_gtk();inject_post=2+command;inject_fault=fault;
        assert(key_request(s,0,1,1) && s->result && s->posts==2+command);
        k=&s->m.r.security;
        assert(!k->ptk && !k->authorized && !k->gtk_refreshes && k->key_adds==1 && k->bmc_live);
        assert(k->gtk==(command<3));
        if(command==3)for(unsigned i=0;i<16;++i)assert(!k->gtk_key[i]);
        else assert(!memcmp(k->gtk_key,synthetic_key,16));
        gpass("delete1-delete2-install-reject-timeout-DDONE-sequence-extension-length-echo-descriptor-fail-closed");free(s);
    }
    assert(cases==41);printf("PASS: %u actual-core first-station GTK refresh cases; ASan/UBSan; synthetic MCU/DMA/RF.\n",cases);return 0;
#endif
}
