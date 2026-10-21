/* SPDX-License-Identifier: GPL-2.0-only */
/* Exercise the actual shared core. All HIF, clock and client effects synthetic. */
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "c80_mcu_core.h"
struct fixture {
    struct c80_dma_pool pool;
    struct c80_io io;
    struct c80_result result;
    c80_u64 us,request_at,stop_at;
    unsigned timer_fault,hif_fault,requests,delays;
};
static unsigned cases;
static c80_u32 rd(void *context,c80_u32 address)
{
    struct fixture *f=context;
    if(address==C80_GLO) return f->hif_fault && f->delays?0:0x10001c75;
    if(address==C80_OWN) return 0x30000;
    if(address==C80_SYNC) return 6;
    return 0;
}
static void wr(void *context,c80_u32 address,c80_u32 value)
{ (void)context;(void)address;(void)value;assert(!"Unexpected MMIO write"); }
static void barrier(void *context,int publish)
{ (void)context;assert(!publish); }
static c80_u64 now(void *context)
{ struct fixture *f=context;return f->timer_fault==1?1000000:f->us; }
static void delay(void *context,c80_u32 amount)
{
    struct fixture *f=context;++f->delays;
    if(f->timer_fault==2) --f->us;else f->us+=amount;
}
static int requested(void *context)
{ struct fixture *f=context;++f->requests;return f->us>=1000000 && f->us-1000000>=f->request_at; }
static int stopped(void *context)
{ struct fixture *f=context;return f->us>=1000000 && f->us-1000000>=f->stop_at; }
static struct fixture *new_fixture(void)
{
    struct fixture *f=calloc(1,sizeof(*f));assert(f);f->us=1000000;
    f->request_at=f->stop_at=ULLONG_MAX;
    f->io=(struct c80_io){.context=f,.pool=&f->pool,.read=rd,.write=wr,
        .time_us=now,.delay_us=delay,.dma_order=barrier,.cfg80211_test=1,.ap_requested=requested,
        .netdev_test=1,.net_stop_requested=stopped};
    f->result.phase=38;return f;
}
static void control(unsigned mode,c80_u64 at,unsigned expected)
{
    struct fixture *f=new_fixture();
    if(!mode) f->request_at=at;
    if(mode==1) f->stop_at=at;
    if(mode==2) f->io.ap_requested=NULL;
    if(mode==3) f->hif_fault=1;
    if(mode==4 || mode==5) f->timer_fault=mode-3;
    if(mode==6) f->io.cfg80211_test=0;
    unsigned rc=c80_watch_window(&f->io,&f->result,0);
    if(rc!=expected)fprintf(stderr,"control mode%u got%u wanted%u\n",mode,rc,expected);
    assert(rc==expected);
    assert(!f->result.beacon_attempted[0] && !f->result.beacon_attempted[1]);
    if(!mode) assert(f->result.watch[0].complete && f->result.watch[0].elapsed_us>=at);
    if(mode==6) assert(!f->requests && f->result.watch[0].elapsed_us==30000000);
    if(mode==7) assert(f->result.net.stop_requested && !f->result.watch[0].complete);
    printf("PASS CFG-control-%u-at%llu-rc%u\n",mode,at,expected);++cases;free(f);
}
static void prerequisite(unsigned which)
{
    struct fixture *f=new_fixture();f->io.net_recycle_test=f->io.watch_test=1;
    f->io.bss_period_test=f->io.bss_test=f->io.beacon_test=1;
    if(!which)f->io.ap_requested=NULL;
    if(which==1)f->io.net_recycle_test=0;
    if(which==2)f->io.watch_test=0;
    if(which==3)f->io.bss_period_test=0;
    if(which==4)f->io.bss_test=0;
    if(which==5)f->io.beacon_test=0;
    assert(c80_run(&f->io,NULL,&f->result)==C80_CFG_BAD_STATE);
    printf("PASS CFG-prerequisite-%u-before-MMIO\n",which);++cases;free(f);
}
static void template_cases(const char *path)
{
    c80_u8 oracle[528],out[528],frame[480];FILE *p=fopen(path,"rb");assert(p);
    assert(fread(oracle,1,528,p)==528 && fgetc(p)==EOF);fclose(p);
    struct fixture *f=new_fixture();memcpy(f->pool.nvm_payload+8,oracle+54,6);
    f->io.cfg80211_test=0;
    assert(!c80_beacon_payload(&f->io,out,1) && !memcmp(oracle,out,528));
    puts("PASS CFG-legacy-template-identical-to-OEM-offload-mode-oracle");++cases;
    for(unsigned n=62;n<=480;n+=19) for(unsigned on=0;on<2;++on) {
        memset(frame,0,sizeof(frame));memcpy(frame,oracle+44,62);
        for(unsigned i=62;i<n;++i)frame[i]=(i*7)&255;
        f->io.cfg80211_test=1;f->io.ap_beacon=frame;f->io.ap_beacon_bytes=n;f->io.ap_tim_offset=56;
        assert(!c80_beacon_payload(&f->io,out,on));
        assert(out[1]==on && c80_get16(out+8)==n+32 && c80_get16(out+10)==88 && c80_get16(out+12)==n+32);
        assert(!memcmp(out+44,frame,n));
        for(unsigned i=44+n;i<528;++i)assert(!out[i]);
        ++cases;
    }
    /* Buffer ends at a protected page: validate all lengths before any read. */
    long page=sysconf(_SC_PAGESIZE);assert(page>=4096);
    c80_u8 *mapping=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(mapping!=MAP_FAILED);
    assert(!mprotect(mapping+page,page,PROT_NONE));
    for(unsigned n=0;n<=480;++n) {
        c80_u8 *b=mapping+page-n;
        memset(b,0,n);if(n>=62)memcpy(b,oracle+44,62);
        f->io.ap_beacon=b;f->io.ap_beacon_bytes=n;f->io.ap_tim_offset=56;
        memset(out,0xa5,sizeof(out));unsigned rc=c80_beacon_payload(&f->io,out,1);
        assert(rc==(n<62?C80_CFG_BAD_STATE:0));
        if(rc)for(unsigned i=0;i<528;++i)assert(out[i]==0xa5);
        ++cases;
    }
    assert(!munmap(mapping,page*2));
    for(unsigned bad=0;bad<9;++bad) {
        memcpy(frame,oracle+44,62);f->io.ap_beacon=frame;f->io.ap_beacon_bytes=62;f->io.ap_tim_offset=56;
        if(bad==0)f->io.ap_beacon=NULL;
        if(bad==1)f->io.ap_beacon_bytes=481;
        if(bad==2)f->io.ap_tim_offset=57;
        if(bad==3)f->io.ap_tim_offset=35;
        if(bad==4)frame[56]=0;
        if(bad==5)frame[57]=255;
        if(bad==6)frame[59]=0;
        if(bad==7)frame[10]^=2;
        if(bad==8)frame[16]^=2;
        assert(c80_beacon_payload(&f->io,out,1)==C80_CFG_BAD_STATE);++cases;
    }
    free(f);
}
static void ssid_case(unsigned length,unsigned corrupt)
{
    struct fixture *f=new_fixture();c80_u8 ssid[32],request[128]={},probe[128]={};
    static const c80_u8 own[6]={2,0xc0,0x80,0x32,0,1},peer[6]={2,0xc0,0x80,0x32,0,2};
    for(unsigned i=0;i<length;++i)ssid[i]='A'+i%26;
    memcpy(f->pool.nvm_payload+8,own,6);memcpy(f->pool.auth_frame+4,peer,6);
    f->io.ap_ssid=ssid;f->io.ap_ssid_bytes=length;f->io.assoc_reply_test=1;
    f->io.net_recycle_test=1;f->io.management_rx_test=1;
    struct c80_result *r=&f->result;r->phase=37;r->auth_submitted=r->auth_dma_done=1;
    r->auth_ring_programmed=r->nvm_equal=r->devinfo_mac_valid=1;
    r->bss_valid[0]=r->radio_valid[3]=r->beacon_valid[1]=1;
    memcpy(request+4,own,6);memcpy(request+10,peer,6);memcpy(request+16,own,6);
    c80_put16(request+24,1);c80_put16(request+26,1);request[29]=length;
    memcpy(request+30,ssid,length);memcpy(request+30+length,(c80_u8[]){1,4,0x82,0x84,0x8b,0x96},6);
    if(corrupt==1)request[30]^=1;
    unsigned size=36+length;if(corrupt==2)--size;
    c80_assoc_capture(&f->io,r,request,size);
    assert(r->assoc_captured==!corrupt);
    c80_put16(probe,0x40);memset(probe+4,255,6);memcpy(probe+10,peer,6);memset(probe+16,255,6);
    probe[25]=length;memcpy(probe+26,ssid,length);
    c80_management_receive(&f->io,r,probe,26+length);
    assert(r->management[1].probe_test_ssid==1);
    ++cases;free(f);
}
int main(int argc,char **argv)
{
    (void)c80_irq_prepare;(void)c80_irq_unmask;(void)c80_irq_event;(void)c80_irq_stop;
    setvbuf(stdout,NULL,_IOLBF,0);
    assert(argc==2);template_cases(argv[1]);
    for(unsigned n=1;n<=32;++n)for(unsigned bad=0;bad<3;++bad)ssid_case(n,bad);
    const c80_u64 at[]={0,1,1000,150000,29999000};
    for(unsigned i=0;i<5;++i)control(0,at[i],0);
    control(1,0,C80_NET_STOPPED);control(1,5000,C80_NET_STOPPED);
    control(2,0,C80_CFG_BAD_STATE);control(3,0,C80_HIF_CHANGED);
    control(4,0,C80_BAD_TIMER);control(5,0,C80_BAD_TIMER);
    control(6,0,0);control(7,0,C80_NET_STOPPED);
    for(unsigned i=0;i<6;++i)prerequisite(i);
    printf("PASS: %u cfg80211 control/template/variable-SSID core cases; ASan/UBSan; synthetic HIF only.\n",cases);
    return 0;
}
