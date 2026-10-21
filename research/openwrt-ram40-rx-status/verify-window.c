/* SPDX-License-Identifier: GPL-2.0-only */
#define C80_DATA_LIBRARY
#include "verify-data.c"
struct window_model { struct data_model base; c80_u64 auth_at;unsigned injected,drop,shifted; };
static unsigned window_cases;
static void window_stage(void *opaque,c80_u32 phase)
{
    struct window_model *x=opaque;unsigned old=x->base.parent.base.auth.fault;
    /* Synthetic client stays absent until the requested arrival time. */
    if(phase==37) x->base.parent.base.auth.fault=20;
    auth_stage(opaque,phase);x->base.parent.base.auth.fault=old;
}
static void window_delay(void *opaque,c80_u32 us)
{
    struct window_model *x=opaque;struct model *m=data_model_base(&x->base);data_delay(opaque,us);
    if(m->phase!=37) return;
    if(x->drop==1 && m->us-m->watch_start>=60000000) *regptr(m,C80_GLO)&=~5u;
    if(!x->injected && m->us-m->watch_start>=x->auth_at) { auth_frame_inject(&x->base.parent.base.auth,11);x->injected=1; }
}
static void window_barrier(void *opaque,int publish)
{
    struct window_model *x=opaque;struct model *m=data_model_base(&x->base);data_barrier(opaque,publish);
    if(x->drop==2 && !x->shifted && m->result.sta_valid[0] && !m->result.assoc_submitted) { m->us+=1500000;x->shifted=1; }
}
static struct window_model *window_new(unsigned long_window,c80_u64 arrival,unsigned data_fault,unsigned sta_fault,unsigned drop)
{
    struct data_model *old=data_new(data_fault);struct window_model *x=calloc(1,sizeof(*x));assert(x);memcpy(&x->base,old,sizeof(*old));free(old);
    struct model *m=data_model_base(&x->base);x->auth_at=arrival;x->drop=drop;x->base.parent.fault=sta_fault;
    m->io.context=x;m->io.pool=&m->pool;m->io.long_beacon_test=long_window;m->io.stage=window_stage;m->io.delay_us=window_delay;m->io.dma_order=window_barrier;return x;
}
static void window_full(unsigned long_window,c80_u64 arrival,unsigned data_fault,unsigned sta_fault,unsigned drop,unsigned expected,unsigned auth,unsigned assoc,unsigned data)
{
    struct window_model *x=window_new(long_window,arrival,data_fault,sta_fault,drop);struct model *m=data_model_base(&x->base);struct c80_result *r=&m->result;
    unsigned rc=c80_run(&m->io,firmware,r);
    if(rc!=expected || r->auth_submitted!=auth || r->assoc_submitted!=assoc || r->diag_submissions!=data)
        fprintf(stderr,"WINDOW long%u at%llu drop%u datafault%u stafault%u rc%u/%u auth%u/%u assoc%u/%u data%u/%u elapsed%u\n",long_window,arrival,drop,data_fault,sta_fault,rc,expected,r->auth_submitted,auth,r->assoc_submitted,assoc,r->diag_submissions,data,r->watch[1].elapsed_us);
    assert(rc==expected && r->auth_submitted==auth && r->assoc_submitted==assoc && r->diag_submissions==data);data_pinned(&x->base);
    assert(r->watch[0].complete && r->watch[0].elapsed_us>=30000000 && r->watch[0].elapsed_us<30100000);
    assert(!r->cleanup && !r->critical && r->mcu_stopped && r->dma_idle && !r->auth_ring_restore_bad);
    if(!expected) {
        unsigned target=long_window?180000000:30000000;
        assert(r->watch[1].complete && r->beacon_complete && r->watch[1].elapsed_us>=target && r->watch[1].elapsed_us<target+100000);
        if(data==2) assert(r->diag_dma_done[0] && r->diag_dma_done[1] && r->diag_token_returned[0] && r->diag_token_returned[1] && r->sta_valid[1] && r->command_submitted==29 && r->sequence==15);
    }
    if(expected==44) assert(r->watch_fault_phase==37 && r->watch[1].elapsed_us>=60000000);
    if(expected==63) assert(x->shifted && r->sta_valid[0] && !r->assoc_submitted);
    if(long_window && arrival==178500000) assert(r->assoc_late==1);
    if(long_window && arrival==179500000) assert(r->auth_late==1);
    printf("PASS WINDOW-full long%u auth_at%llu fault%u/%u/%u rc%u auth%u assoc%u data%u elapsed%u\n",long_window,arrival,data_fault,sta_fault,drop,rc,auth,assoc,data,r->watch[1].elapsed_us);++window_cases;free(x);
}
static c80_u64 frozen_time(void *opaque) { (void)opaque;return 1000000; }
static void frozen_delay(void *opaque,c80_u32 us) { struct window_model *x=opaque;assert(us==1000);++x->injected; }
static c80_u64 rollback_time(void *opaque) { struct window_model *x=opaque;return x->injected?999999:1000000; }
static void window_clock(unsigned long_window,unsigned rollback)
{
    struct window_model *x=window_new(long_window,60000000,0,0,0);struct model *m=data_model_base(&x->base);struct c80_result *r=&m->result;
    m->phase=r->phase=37;*regptr(m,C80_GLO)=0x10001c75;*regptr(m,C80_OWN)=0x30000;*regptr(m,C80_SYNC)=6;
    m->io.time_us=rollback?rollback_time:frozen_time;m->io.delay_us=frozen_delay;
    assert(c80_watch_window(&m->io,r,1)==C80_BAD_TIMER && !r->watch[1].complete && !r->diag_submissions);
    unsigned maximum=long_window?180000:30000;
    if(rollback) assert(x->injected==1 && r->watch[1].samples==1);
    else assert(x->injected==maximum && r->watch[1].samples==maximum+1);
    printf("PASS WINDOW-clock long%u rollback%u samples%u delay_calls%u\n",long_window,rollback,r->watch[1].samples,x->injected);++window_cases;free(x);
}
static void window_guard(unsigned which)
{
    struct window_model *x=window_new(1,60000000,0,0,0);struct model *m=data_model_base(&x->base);
    if(which) m->io.beacon_test=0;else m->io.watch_test=0;
    assert(c80_run(&m->io,firmware,&m->result)==47 && !m->writes);
    printf("PASS WINDOW-prerequisite %u noMMIO\n",which);++window_cases;free(x);
}
static void window_load(int argc,char **argv)
{
    assert(argc==9);FILE *f;
    f=fopen(argv[4],"rb");assert(f && fread(auth_oracle,1,32,f)==32 && fgetc(f)==EOF);fclose(f);
    f=fopen(argv[3],"rb");assert(f && fread(synthetic_nvm,1,1024,f)==1024 && fgetc(f)==EOF);fclose(f);
    f=fopen(argv[2],"rb");assert(f);for(unsigned i=0;i<59;++i) { c80_u8 b[4];assert(fread(b,1,4,f)==4);stock_sizes[i]=c80_get32(b);assert(stock_sizes[i]<=1152 && fread(stock_packets[i],1,stock_sizes[i],f)==stock_sizes[i]); }assert(fgetc(f)==EOF);fclose(f);
    f=fopen(argv[5],"rb");assert(f);for(unsigned i=0;i<2;++i) { c80_u8 b[4];assert(fread(b,1,4,f)==4);sta_size[i]=c80_get32(b);assert(sta_size[i]<=308 && fread(sta_oracle[i],1,sta_size[i],f)==sta_size[i]); }assert(fgetc(f)==EOF);fclose(f);
    f=fopen(argv[6],"rb");assert(f && fread(assoc_txd,1,32,f)==32 && fgetc(f)==EOF);fclose(f);
    f=fopen(argv[7],"rb");assert(f && fread(data_txd,1,32,f)==32 && fgetc(f)==EOF);fclose(f);
    f=fopen(argv[8],"rb");assert(f);for(unsigned i=0;i<10;++i) { c80_u8 b[4];assert(fread(b,1,4,f)==4);wire_size[i]=c80_get32(b);assert(wire_size[i]<=200 && fread(wire[i],1,wire_size[i],f)==wire_size[i]); }assert(fgetc(f)==EOF);fclose(f);
    const char *names[]={"test_mcu.bin","test_wifi.bin","WIFI_RAM_CODE_iemi.bin","WIFI_RAM_CODE_demi.bin","mt7626_patch_e1_hdr.bin","WIFI_RAM_CODE_7626.bin"};for(unsigned i=0;i<6;++i) { char path[4096];snprintf(path,sizeof(path),"%s/%s",argv[1],names[i]);f=fopen(path,"rb");assert(f);firmware[i].bytes=c80_blob_sizes[i];firmware[i].data=malloc(firmware[i].bytes);assert(fread((void *)firmware[i].data,1,firmware[i].bytes,f)==firmware[i].bytes && fgetc(f)==EOF);fclose(f); }
}
int main(int argc,char **argv)
{
    window_load(argc,argv);
    window_full(0,20000000,0,0,0,0,1,1,2);
    window_full(0,60000000,0,0,0,0,0,0,0);
    window_full(1,60000000,0,0,0,0,1,1,2);
    window_full(1,120000000,0,0,0,0,1,1,2);
    window_full(1,170000000,0,0,0,0,1,1,2);
    window_full(1,177000000,0,0,0,0,1,1,2);
    window_full(1,178500000,0,0,0,0,1,0,0);
    window_full(1,179500000,0,0,0,0,0,0,0);
    window_full(1,170000000,10,0,0,68,1,1,1);
    window_full(1,170000000,0,1,0,61,1,0,0);
    window_full(1,170000000,0,0,1,44,0,0,0);
    window_full(1,177750000,0,0,2,63,1,0,0);
    window_clock(0,0);window_clock(1,0);window_clock(1,1);window_guard(0);window_guard(1);
    for(unsigned i=0;i<6;++i) free((void *)firmware[i].data);
    printf("PASS: %u actual-core extended-window cases; ASan/UBSan; simulated clock/client/DMA only.\n",window_cases);return 0;
}
