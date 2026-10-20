/* SPDX-License-Identifier: MIT
 * First vendor EMI bootstrap, not a Wi-Fi host driver or an AP test.
 * No U-Boot calls, flash writes or MMU mapping/control changes. PAR is
 * temporarily used for privileged translation probes and then restored.
 */
typedef unsigned int u32;
typedef unsigned char u8;
typedef unsigned long long u64;
#define NOINLINE __attribute__((noinline,noclone))
#define EMI 0x40000000u
#define EMI_SIZE 0x200000u
#define IMAGE 0x41000000u
#define IMAGE_SIZE 0x250000u
#define BACKUP 0x41050000u
#define MCU_SOURCE 0x41004000u
#define MCU_SIZE 72096u
#define WIFI_SOURCE 0x41018000u
#define WIFI_SIZE 169240u
#define WIFI_DEST 0x40043000u
#define RESET 0x10212018u
#define RESET_BIT 0x1000u
#define RESET_KEY 0x88000000u
#define COMPLETE 0x18002600u
#define HARD_POLLS 1000000u

enum { MIDR,SCTLR,CTR,TTBR0,TTBR1,TTBCR,VBAR,PAR,CNTFRQ,MPIDR };
struct test {
    u32 cpu[10], original_sp, original_gd, caller, cpsr, line, stage, error_stage;
    u32 primary, cleanup_errors, critical, uart_failed, have_cpu, have_aon;
    u32 aon[10], after[10], aon_changed, pdma_before[2], pdma_after[2];
    u32 last_read, translations, bad_va, bad_par, bad_table_entry;
    u32 ids[4], ids_valid, complete_before, complete_last, ready, polls;
    u32 original_crc, backup_crc, restored_crc, restored_crc2;
    u32 source_mcu_crc, source_wifi_crc, backup_valid, emi_dirty, emi_restored;
    u32 old_controls[3], control_readback[3], touched, release_attempted, mcu_stopped, controls_saved;
    u32 reset_release_readback, reset_hold_readback;
    u32 power_cycle, outcome, par_used;
};
extern u32 c80_midr(void);
extern void c80_snapshot(u32 *);
extern u64 c80_counter(void);
extern u32 c80_translate(u32,u32);
extern void c80_restore_par(u32);
extern void c80_clean(u32,u32,u32);
extern void c80_invalidate(u32,u32,u32);

static const u32 aon_addresses[10] = {
    0x10000220,0x10000228,0x10000230,0x10000238,0x10000370,
    0x10006000,0x10006608,0x1000660c,0x10006610,RESET
};
static const u32 controls[3] = { 0x18002150,0x18001130,0x10210000 };
static const u32 control_masks[3] = { 0x00208001,1,0xc };
static const u32 id_addresses[4] = { 0x180b1010,0x180b101c,0x18002000,0x18002004 };

static u32 rd(u32 a) { return *(volatile u32 *)a; }
static void wr(u32 a,u32 v) { *(volatile u32 *)a=v; __asm__ volatile("dsb sy":::"memory"); }
static void out(struct test *t,const char *s)
{
    while (*s && !t->uart_failed) {
        u32 i;
        for (i=0;i<1000000;++i) if (rd(0x11002014)&0x20) break;
        if (i==1000000) { t->uart_failed=1; return; }
        wr(0x11002000,(u8)*s++);
    }
}
static void hex(struct test *t,u32 v)
{
    char b[9]; u32 i;
    for (i=0;i<8;++i) { b[i]="0123456789abcdef"[v>>28]; v<<=4; }
    b[8]=0; out(t,b);
}
static void field(struct test *t,const char *label,u32 value)
{ out(t,label); out(t,"="); hex(t,value); out(t,"\r\n"); }
static void words(struct test *t,const char *label,const u32 *v,u32 count)
{ u32 i; out(t,label); out(t,"="); for(i=0;i<count;++i) { if(i) out(t," "); hex(t,v[i]); } out(t,"\r\n"); }
static void error(struct test *t,u32 rc)
{ if (!t->primary) { t->primary=rc; t->error_stage=t->stage; } }
static int phase(struct test *t,u32 stage)
{
    t->stage=stage; field(t,"STAGE",stage);
    if (t->uart_failed) { error(t,40); return 0; }
    return 1;
}
static int checkpoint(struct test *t,u32 address)
{
    t->last_read=address; field(t,"READ",address);
    if (t->uart_failed) { error(t,40); return 0; }
    return 1;
}
static int overlap(u32 a,u32 n,u32 b,u32 m)
{ return a<b+m && b<a+n; }
static int mutation_overlap(u32 a,u32 n)
{ return overlap(a,n,EMI,EMI_SIZE) || overlap(a,n,IMAGE,IMAGE_SIZE); }

NOINLINE u32 c80_crc32(u32 address,u32 size)
{
    static const u32 tab[16] = {0,0x1db71064,0x3b6e20c8,0x26d930ac,
        0x76dc4190,0x6b6b51f4,0x4db26158,0x5005713c,0xedb88320,0xf00f9344,
        0xd6d6a3e8,0xcb61b38c,0x9b64c2b0,0x86d3d2d4,0xa00ae278,0xbdbdf21c};
    const volatile u8 *p=(const volatile u8 *)address;
    u32 crc=~0u;
    while (size--) {
        crc^=*p++;
        crc=(crc>>4)^tab[crc&15]; crc=(crc>>4)^tab[crc&15];
    }
    return ~crc;
}
NOINLINE void c80_copy(u32 dest,u32 source,u32 size)
{
    volatile u32 *d=(volatile u32 *)dest;
    const volatile u32 *s=(const volatile u32 *)source;
    for (;size;size-=4) *d++=*s++;
}
NOINLINE int c80_wait(u32 ticks)
{
    u64 start=c80_counter(), now; u32 i;
    for (i=0;i<HARD_POLLS;++i) {
        now=c80_counter();
        if(now<start) return 0;
        if(now-start>=ticks) return 1;
    }
    return 0;
}
static void flush(struct test *t,u32 address,u32 size)
{ c80_clean(address,size,t->line); c80_invalidate(address,size,t->line); }

static int mapping(struct test *t,u32 va,u32 write,int identity)
{
    u32 p;
    t->par_used=1; p=c80_translate(va,write); ++t->translations;
    if ((p&1) || (identity && ((p^va)&0xfffff000u))) {
        t->bad_va=va; t->bad_par=p; return 0;
    }
    return 1;
}
static int region_mapping(struct test *t,u32 address,u32 size,u32 write)
{
    u32 end=address+size, a=address&~0xfffu;
    for (;a<end;a+=4096)
        if (!mapping(t,a,0,1) || (write && !mapping(t,a,1,1))) return 0;
    return 1;
}
static int table_guard(struct test *t)
{
    u32 table=t->cpu[TTBR0]&0xffffc000u, i, vector_pa, p;
    if (t->cpu[TTBCR]!=0 || t->cpu[SCTLR]!=0x00c5187f ||
        table<0x40200000 || table>0x41ffc000 || mutation_overlap(table,0x4000)) return 0;
    if (!region_mapping(t,table,0x4000,0)) return 0;
    for (i=0;i<4096;++i) {
        u32 d=rd(table+i*4), coarse=d&0xfffffc00u;
        if ((d&3)==1 && mutation_overlap(coarse,0x400)) {
            t->bad_table_entry=table+i*4; return 0;
        }
    }
    if (t->cpu[VBAR]&31) return 0;
    t->par_used=1; p=c80_translate(t->cpu[VBAR],0); ++t->translations;
    vector_pa=(p&0xfffff000u)|(t->cpu[VBAR]&0xfff);
    if ((p&1) || mutation_overlap(vector_pa,32)) {
        t->bad_va=t->cpu[VBAR]; t->bad_par=p; return 0;
    }
    return 1;
}
static void snapshot_aon(u32 *values)
{ u32 i; for(i=0;i<10;++i) values[i]=rd(aon_addresses[i]); }
static int aon_guard(const u32 *a)
{
    return !(a[0]&0x8104) && !(a[1]&0x8104) && !(a[2]&7) && !(a[3]&7) &&
        (a[4]&0xfff)==0x40 && (a[5]&1) && (a[6]&0x20800000)==0x20800000 &&
        a[7]==a[8] && (a[7]&0x07000000)==0x07000000 && (a[9]&0x1200)==0x1000;
}
static int set_control(struct test *t,u32 i,u32 bits)
{
    u32 v=rd(controls[i]);
    t->touched|=1u<<i; t->power_cycle=1;
    wr(controls[i],(v&~control_masks[i])|(bits&control_masks[i]));
    t->control_readback[i]=rd(controls[i]);
    return (t->control_readback[i]&control_masks[i])==(bits&control_masks[i]);
}
static int hold_mcu(struct test *t)
{
    u32 v=rd(RESET), i; u64 start;
    wr(RESET,(v&0x00ffffffu)|RESET_KEY|RESET_BIT);
    start=c80_counter();
    for(i=0;i<HARD_POLLS;++i) {
        t->reset_hold_readback=rd(RESET);
        if(t->reset_hold_readback&RESET_BIT) { t->mcu_stopped=1; return 1; }
        if(c80_counter()-start>=400000u) break; /* 20ms at observed20MHz */
    }
    return 0;
}

static void cleanup(struct test *t)
{
    u32 i;
    if (t->release_attempted) {
        t->stage=110; field(t,"STAGE",t->stage);
        if (!hold_mcu(t)) { t->cleanup_errors|=1; t->critical=80; goto final; }
        if (!c80_wait(40000)) { t->cleanup_errors|=2; t->critical=81; goto final; }
    }
    if (t->emi_dirty) {
        if (!(rd(RESET)&RESET_BIT)) { t->cleanup_errors|=1; t->critical=80; goto final; }
        t->mcu_stopped=1;
        t->stage=120; field(t,"STAGE",t->stage);
        c80_invalidate(BACKUP,EMI_SIZE,t->line);
        t->backup_crc=c80_crc32(BACKUP,EMI_SIZE);
        if (!t->backup_valid || t->backup_crc!=t->original_crc) {
            t->cleanup_errors|=4; t->critical=82; goto final;
        }
        t->stage=130; field(t,"STAGE",t->stage);
        c80_invalidate(EMI,EMI_SIZE,t->line);
        c80_copy(EMI,BACKUP,EMI_SIZE); flush(t,EMI,EMI_SIZE);
        t->restored_crc=c80_crc32(EMI,EMI_SIZE);
        if (!c80_wait(40000)) { t->cleanup_errors|=2; t->critical=81; goto final; }
        c80_invalidate(EMI,EMI_SIZE,t->line);
        t->restored_crc2=c80_crc32(EMI,EMI_SIZE);
        if(t->restored_crc!=t->original_crc || t->restored_crc2!=t->original_crc) {
            t->cleanup_errors|=8; t->critical=83; goto final;
        }
        t->emi_restored=1;
    }
    if (t->touched) {
        t->stage=140; field(t,"STAGE",t->stage);
        for(i=3;i;i--) if(t->touched&(1u<<(i-1)))
            if(!set_control(t,i-1,t->old_controls[i-1])) t->cleanup_errors|=16;
    }
final:
    if (t->have_aon) {
        snapshot_aon(t->after);
        for(i=0;i<10;++i) if(t->after[i]!=t->aon[i]) t->aon_changed|=1u<<i;
        if(t->aon_changed) t->cleanup_errors|=32;
        t->pdma_after[0]=rd(0x1b100a04); t->pdma_after[1]=rd(0x1b100a28);
        if(t->pdma_after[0]!=t->pdma_before[0] || t->pdma_after[1]!=t->pdma_before[1])
            t->cleanup_errors|=64;
    }
    if(t->par_used) c80_restore_par(t->cpu[PAR]);
}

static void report(struct test *t)
{
    u32 i;
    static const char *const names[10]={"MIDR","SCTLR","CTR","TTBR0","TTBR1",
        "TTBCR","VBAR","PAR_BEFORE","CNTFRQ","MPIDR"};
    field(t,"RESULT_RC",t->outcome); field(t,"PRIMARY_RC",t->primary);
    field(t,"ERROR_STAGE",t->error_stage); field(t,"CLEANUP_ERRORS",t->cleanup_errors);
    field(t,"CRITICAL_STOP",t->critical); field(t,"CPSR_BEFORE",t->cpsr);
    field(t,"ORIGINAL_SP",t->original_sp); field(t,"ORIGINAL_GD",t->original_gd);
    field(t,"CALLER",t->caller);
    for(i=0;i<10;++i) field(t,names[i],t->cpu[i]);
    field(t,"TRANSLATIONS",t->translations); field(t,"BAD_VA",t->bad_va);
    field(t,"BAD_PAR",t->bad_par); field(t,"BAD_TABLE_ENTRY",t->bad_table_entry);
    field(t,"LAST_READ",t->last_read); field(t,"AON_CHANGED_BITS",t->aon_changed);
    field(t,"AON_SNAPSHOT_VALID",t->have_aon);
    words(t,"AON_BEFORE",t->aon,10); words(t,"AON_AFTER",t->after,10);
    words(t,"CONTROLS_BEFORE_2150_1130_RTC",t->old_controls,3);
    words(t,"CONTROLS_LAST_READBACK",t->control_readback,3);
    field(t,"RGU_RELEASE_READBACK",t->reset_release_readback);
    field(t,"RGU_HOLD_READBACK",t->reset_hold_readback);
    field(t,"IDS_VALID",t->ids_valid); field(t,"CONNSYS_VERSION",t->ids[0]);
    field(t,"CONNSYS_CONFIG",t->ids[1]); field(t,"CONNSYS_HW",t->ids[2]);
    field(t,"CONNSYS_FW",t->ids[3]);
    field(t,"COMPLETE_BEFORE",t->complete_before); field(t,"COMPLETE_LAST",t->complete_last);
    field(t,"READY_OBSERVED",t->ready); field(t,"READY_POLLS",t->polls);
    field(t,"MCU_SOURCE_CRC",t->source_mcu_crc); field(t,"WIFI_SOURCE_CRC",t->source_wifi_crc);
    field(t,"DDR_ORIGINAL_CRC",t->original_crc); field(t,"DDR_BACKUP_CRC",t->backup_crc);
    field(t,"DDR_RESTORED_CRC",t->restored_crc); field(t,"DDR_RESTORED_CRC2",t->restored_crc2);
    field(t,"DDR_BACKUP_VALID",t->backup_valid); field(t,"DDR_RESTORED",t->emi_restored);
    field(t,"MCU_RELEASE_ATTEMPTED",t->release_attempted); field(t,"MCU_STOPPED",t->mcu_stopped);
    field(t,"CONTROLS_TOUCHED",t->touched); field(t,"POWER_CYCLE_REQUIRED",t->power_cycle);
    out(t,"DONE\r\n");
}

int bootstrap_main(u32 sp,u32 caller,u32 cpsr,u32 gd)
{
    struct test t; u32 i; u64 start;
    u32 *zero=(u32 *)&t;
    for(i=0;i<sizeof(t)/4;++i) zero[i]=0;
    t.original_sp=sp; t.original_gd=gd; t.caller=caller; t.cpsr=cpsr;
    out(&t,"\r\nC80 CONNSYS bootstrap test v1\r\n");
    if(!phase(&t,10)) goto done;
    if((cpsr&0x3ff)!=0x1d3 || c80_midr()!=0x410fc073) { error(&t,3); goto done; }
    if((sp&7) || sp<0x41c10000 || sp>=0x42000000 ||
       (caller&3) || caller<0x41c00000 || caller>=0x42000000 ||
       (gd&3) || gd<0x41c00000 || gd>0x41ffff00) { error(&t,4); goto done; }
    c80_snapshot(t.cpu); t.have_cpu=1;
    t.line=4u<<((t.cpu[CTR]>>16)&15);
    if(t.line<32 || t.line>256 || t.cpu[MPIDR]!=0x80000000 || t.cpu[CNTFRQ]!=20000000)
        { error(&t,5); goto done; }
    if(!phase(&t,20)) goto done;
    if(!table_guard(&t)) { error(&t,6); goto done; }
    if(!phase(&t,30)) goto done;
    if(!region_mapping(&t,EMI,EMI_SIZE,1) || !region_mapping(&t,IMAGE,IMAGE_SIZE,1) ||
       !region_mapping(&t,0x41c00000,0x400000,0) ||
       !region_mapping(&t,sp-0x4000,0x4000,1) || !region_mapping(&t,gd,256,1))
        { error(&t,7); goto done; }
    start=c80_counter();
    for(i=0;i<1024;++i) if(c80_counter()>start) break;
    if(i==1024) { error(&t,8); goto done; }
    if(!phase(&t,40)) goto done;
    snapshot_aon(t.aon); t.have_aon=1;
    t.pdma_before[0]=rd(0x1b100a04); t.pdma_before[1]=rd(0x1b100a28);
    if(t.pdma_before[0]!=0x1410 || t.pdma_before[1] || !aon_guard(t.aon))
        { error(&t,9); goto done; }
    for(i=0;i<4;++i) {
        if(!checkpoint(&t,id_addresses[i])) goto done;
        t.ids[i]=i<2?rd(id_addresses[i]):*(volatile unsigned short *)id_addresses[i];
        t.ids_valid|=1u<<i;
        if((i==0 && t.ids[0]!=0x10040101) || (i==1 && (t.ids[1]&15)) ||
           (i>=2 && t.ids[i]!=0x8a00)) { error(&t,10); goto done; }
    }
    if(!checkpoint(&t,COMPLETE)) goto done;
    t.complete_before=rd(COMPLETE);
    if(t.complete_before==0x1d1e) { error(&t,11); t.power_cycle=1; goto done; }
    for(i=0;i<3;++i) {
        if(!checkpoint(&t,controls[i])) goto done;
        t.old_controls[i]=rd(controls[i]);
    }
    t.controls_saved=1;
    if(!phase(&t,50)) goto done;
    t.source_mcu_crc=c80_crc32(MCU_SOURCE,MCU_SIZE);
    t.source_wifi_crc=c80_crc32(WIFI_SOURCE,WIFI_SIZE);
    if(t.source_mcu_crc!=0x2ede9294 || t.source_wifi_crc!=0x4e2c264c)
        { error(&t,20); goto done; }
    if(!phase(&t,60)) goto done;
    flush(&t,EMI,EMI_SIZE);
    t.original_crc=c80_crc32(EMI,EMI_SIZE);
    c80_copy(BACKUP,EMI,EMI_SIZE); flush(&t,BACKUP,EMI_SIZE);
    t.backup_crc=c80_crc32(BACKUP,EMI_SIZE);
    if(t.backup_crc!=t.original_crc) { error(&t,21); goto done; }
    t.backup_valid=1;
    field(&t,"DDR_BACKUP_CRC",t.backup_crc);
    if(!phase(&t,70)) goto done;
    t.emi_dirty=1;
    c80_copy(EMI,MCU_SOURCE,MCU_SIZE); c80_copy(WIFI_DEST,WIFI_SOURCE,WIFI_SIZE);
    flush(&t,EMI,EMI_SIZE);
    if(c80_crc32(EMI,MCU_SIZE)!=0x2ede9294 || c80_crc32(WIFI_DEST,WIFI_SIZE)!=0x4e2c264c)
        { error(&t,22); goto done; }
    if(!phase(&t,80)) goto done;
    for(i=0;i<3;++i) if(!set_control(&t,i,t.old_controls[i]|control_masks[i]))
        { error(&t,30); goto done; }
    if(!phase(&t,90)) goto done;
    t.release_attempted=1; t.power_cycle=1;
    wr(RESET,((rd(RESET)&0x00ffffffu)&~RESET_BIT)|RESET_KEY);
    t.reset_release_readback=rd(RESET);
    if(t.reset_release_readback&RESET_BIT) { error(&t,31); goto done; }
    if(!phase(&t,100)) goto done;
    start=c80_counter();
    for(i=0;i<HARD_POLLS;++i) {
        t.complete_last=rd(COMPLETE); t.polls=i+1;
        if(t.complete_last==0x1d1e) { t.ready=1; break; }
        if(c80_counter()-start>=40000000u) break; /* 2s at observed20MHz */
    }
    if(!t.ready) error(&t,32);
done:
    cleanup(&t);
    t.outcome=t.critical?t.critical:t.cleanup_errors?48:t.primary?t.primary:t.uart_failed?40:t.ready?0:99;
    report(&t);
    return t.uart_failed && !t.outcome?40:(int)t.outcome;
}
