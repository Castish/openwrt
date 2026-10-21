/* SPDX-License-Identifier: GPL-2.0-only */
/* Actual shared core with real OEM ARM-produced configuration oracle.
 * MMIO/firmware/DMA/time/OS effects remain synthetic, not hardware proof. */
#define C80_SCHED_LIBRARY
#include "verify-recycle.c"
struct sched_model {
    struct cycle_model cycle;
    c80_u32 regs[C80_SCHED_N],initial[C80_SCHED_N];
    c80_u32 written_reg[64],written_value[64],writes,reads;
    int fault_program,fault_restore,fault_read,alter_live,altered;
};
static c80_u32 oracle_reg[15],oracle_value[15];
static unsigned sched_cases;
static struct model *sm(struct sched_model *x) { return cm(&x->cycle); }
static int si(c80_u32 address)
{ for(unsigned i=0;i<15;++i)if(oracle_reg[i]==address)return i;return -1; }
static c80_u32 sr(void *o,c80_u32 address)
{
    struct sched_model *x=o;int i=si(address);
    if(i<0)return cycle_read(o,address);
    ++x->reads;
    if(x->fault_read==i && !sm(x)->result.scheduler.saved)return 0xffffffffu;
    return x->regs[i];
}
static void sw(void *o,c80_u32 address,c80_u32 value)
{
    struct sched_model *x=o;struct model *m=sm(x);int i=si(address);
    if(i<0) {
        if(address==C80_GLO && (value&5u))assert(m->result.scheduler.applied);
        cycle_write(o,address,value);return;
    }
    assert(x->writes<64 && !(association_read(o,C80_GLO)&15u));
    x->written_reg[x->writes]=address;x->written_value[x->writes++]=value;
    if((!m->result.mcu_stopped && x->fault_program==i) ||
       (m->result.mcu_stopped && x->fault_restore==i))return;
    x->regs[i]=value;
}
static void sd(void *o,c80_u32 us)
{
    struct sched_model *x=o;cycle_delay(o,us);
    if(x->alter_live>=0 && !x->altered && sm(x)->result.net.submitted) {
        x->regs[x->alter_live]^=1;x->altered=1;
    }
}
static struct sched_model *sn(unsigned count,unsigned mode)
{
    struct cycle_model *b=cycle_new(count,mode);struct sched_model *x=calloc(1,sizeof(*x));assert(x);
    memcpy(&x->cycle,b,sizeof(*b));free(b);struct model *m=sm(x);
    m->io.pool=&m->pool;m->io.context=x;m->io.read=sr;m->io.write=sw;m->io.delay_us=sd;m->io.scheduler_test=1;
    x->fault_program=x->fault_restore=x->fault_read=x->alter_live=-1;
    for(unsigned i=0;i<15;++i)x->initial[i]=x->regs[i]=i?0x1000u+i:0;
    return x;
}
static void unit_ready(struct sched_model *x)
{
    struct model *m=sm(x);m->result.phase=m->phase=6;m->result.ready=1;
    *regptr(m,C80_GLO)=0x10001870;*regptr(m,C80_MASK)=0;*regptr(m,C80_OWN)=0x30000;
}
static void restore(struct sched_model *x)
{ sm(x)->result.mcu_stopped=1;c80_scheduler_restore(&sm(x)->io,&sm(x)->result); }
static void same(struct sched_model *x)
{ assert(!memcmp(x->regs,x->initial,sizeof(x->regs))); }
static void result(const char *name,unsigned detail)
{ printf("PASS SCHED-%s%u\n",name,detail);++sched_cases; }
static void unit_vectors(FILE *f)
{
    for(unsigned n=0;n<10;++n) {
        c80_u32 h[3],pairs[30];assert(fread(h,4,3,f)==3 && h[2]==15 && fread(pairs,4,30,f)==30);
        struct sched_model *x=sn(0,0);unit_ready(x);x->initial[0]=x->regs[0]=h[1];
        unsigned rc=c80_scheduler_init(&sm(x)->io,&sm(x)->result);
        if(h[1]==0xffffffffu)assert(rc==78 && !x->writes && !sm(x)->result.scheduler.saved);
        else {
            assert(!rc && x->writes==15 && sm(x)->result.scheduler.applied);
            for(unsigned i=0;i<15;++i)assert(x->written_reg[i]==pairs[i*2] && x->written_value[i]==pairs[i*2+1]);
            assert(!c80_scheduler_guard(&sm(x)->io,&sm(x)->result));restore(x);same(x);
            assert(sm(x)->result.scheduler.restored && !sm(x)->result.scheduler.restore_bad);
        }
        result("OEM-vector-",n);free(x);
    }
    assert(fgetc(f)==EOF);
}
static void unit_fault(unsigned mode,unsigned reg)
{
    struct sched_model *x=sn(0,0);unit_ready(x);struct model *m=sm(x);unsigned rc;
    if(!mode)x->fault_read=reg;
    if(mode==1)x->fault_program=reg;
    rc=c80_scheduler_init(&m->io,&m->result);
    if(!mode)assert(rc==78 && !x->writes && m->result.scheduler.read_bad==(1u<<reg) && !m->result.scheduler.saved);
    else if(mode==1) {
        assert(rc==78 && x->writes==reg+1 && m->result.scheduler.program_bad==(1u<<reg));
        assert(m->result.scheduler.touched==((1u<<(reg+1))-1));restore(x);same(x);
    } else {
        assert(!rc && x->writes==15);
        if(mode==2) {
            x->regs[reg]^=1;assert(c80_scheduler_guard(&m->io,&m->result)==78 && m->result.scheduler.guard_bad==(1u<<reg));
            c80_scheduler_capture(&m->io,&m->result,1);assert(m->result.scheduler.failure_valid && m->result.scheduler.failure[reg]==x->regs[reg]);
            restore(x);same(x);
        } else {
            x->fault_restore=reg;restore(x);
            assert(m->result.scheduler.restore_bad==(1u<<reg) && !m->result.scheduler.restored);
            assert(m->result.cleanup_flags&C80_CLEANUP_SCHED);
            for(unsigned i=0;i<15;++i)assert(x->regs[i]==(i==reg?m->result.scheduler.wanted[i]:x->initial[i]));
        }
    }
    result(mode==0?"read-refusal-":mode==1?"partial-program-":mode==2?"live-guard-":"restore-fault-",reg);free(x);
}
static void unit_prereq(unsigned mode)
{
    struct sched_model *x=sn(0,0);unit_ready(x);struct model *m=sm(x);
    switch(mode) {
        case 0:m->result.phase=5;break;case 1:m->result.ready=0;break;
        case 2:m->result.dma_started=1;break;case 3:*regptr(m,C80_GLO)|=1;break;
        case 4:*regptr(m,C80_MASK)=1;break;case 5:*regptr(m,C80_OWN)=1;break;
        case 6:m->result.scheduler.saved=1;break;default:assert(0);
    }
    assert(c80_scheduler_init(&m->io,&m->result)==78 && !x->writes && !x->reads);
    result("init-prereq-",mode);free(x);
}
static void unit_busy(unsigned mode)
{
    struct sched_model *x=sn(0,0);unit_ready(x);struct model *m=sm(x);
    assert(!c80_scheduler_init(&m->io,&m->result));unsigned old=x->writes;
    if(mode){m->result.mcu_stopped=1;*regptr(m,C80_GLO)|=4;}
    c80_scheduler_restore(&m->io,&m->result);
    assert(x->writes==old && m->result.scheduler.restore_refused && m->result.critical==(mode?81:80));
    result("refuse-running-",mode);free(x);
}
static void scheduler_full(unsigned count,unsigned mode)
{
    struct sched_model *x=sn(count,mode==1?1:0);struct model *m=sm(x);
    if(mode==2)x->alter_live=2;
    if(mode==3)x->fault_program=7;
    if(mode==4)x->fault_restore=7;
    if(mode==5)m->io.net_recycle_test=0;
    if(mode==6)m->io.watch_test=0;
    unsigned rc=c80_run(&m->io,firmware,&m->result),expected=mode==1?73:mode==2 || mode==3 || mode==5 || mode==6?78:mode==4?16:0;
    if(rc!=expected)fprintf(stderr,"SCHED full%u mode%u rc%u expected%u\n",count,mode,rc,expected);
    assert(rc==expected);struct c80_scheduler_result *s=&m->result.scheduler;
    if(mode<5) {
        assert(m->result.mcu_stopped && !m->result.critical);
        if(mode!=4)assert(s->restored && !s->restore_bad);
        if(mode!=3)assert(s->applied && m->result.dma_idle);
        if(!mode || mode==4) {
            assert(m->result.net.completed==count && !m->result.net.inflight && s->active_valid);
            assert(m->result.sta_valid[1] && m->result.devinfo_valid[1] && m->result.bss_valid[1]);
        }
        if(mode==1 || mode==2)assert(s->failure_valid && m->result.failure_snapshot && m->result.failure_ring==5);
        if(mode==2)assert(s->guard_bad==4 && s->failure[2]==(s->wanted[2]^1));
        if(mode!=4)same(x);
    } else assert(!x->writes && !x->reads && !m->result.dma_started);
    result("full-",count*10+mode);free(x);
}
int main(int argc,char **argv)
{
    assert(argc==9);
    c80_netdev_test_entry(argc,argv);
    FILE *o=fopen("stock-scheduler-oracle.bin","rb");assert(o);
    for(unsigned i=0;i<15;++i){assert(fread(&oracle_reg[i],4,1,o)==1 && fread(&oracle_value[i],4,1,o)==1);assert(oracle_reg[i]==c80_sched_regs[i] && oracle_value[i]==c80_sched_values[i]);}assert(fgetc(o)==EOF);fclose(o);
    o=fopen("stock-scheduler-vectors.bin","rb");assert(o);unit_vectors(o);fclose(o);
    for(unsigned mode=0;mode<4;++mode)for(unsigned i=0;i<15;++i)unit_fault(mode,i);
    for(unsigned i=0;i<7;++i)unit_prereq(i);
    unit_busy(0);unit_busy(1);
    const char *names[]={"test_mcu.bin","test_wifi.bin","WIFI_RAM_CODE_iemi.bin","WIFI_RAM_CODE_demi.bin","mt7626_patch_e1_hdr.bin","WIFI_RAM_CODE_7626.bin"};
    /* Load the same independent firmware/packet fixtures as the regression model. */
    for(unsigned i=0;i<6;++i){char path[4096];snprintf(path,sizeof(path),"%s/%s",argv[1],names[i]);FILE *f=fopen(path,"rb");assert(f);firmware[i].data=malloc(firmware[i].bytes);assert(fread((void *)firmware[i].data,1,firmware[i].bytes,f)==firmware[i].bytes);fclose(f);}
    unsigned counts[]={0,125,126,127,129,4081};
    for(unsigned i=0;i<sizeof(counts)/sizeof(counts[0]);++i)scheduler_full(counts[i],0);
    for(unsigned mode=1;mode<=6;++mode)scheduler_full(2,mode);
    for(unsigned i=0;i<6;++i)free((void *)firmware[i].data);
    printf("PASS: %u actual-core scheduler cases; OEM ARM config oracle; ASan/UBSan; synthetic hardware effects.\n",sched_cases);
    return 0;
}
