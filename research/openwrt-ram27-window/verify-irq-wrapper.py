#!/usr/bin/env python3
"""Compile actual Linux IRQ callbacks with synthetic IRQ/MMIO/lock services.
Exercise NO_AUTOEN depth, one-shot IRQ disable, delayed/wrong routes and stop
interleavings. This does not execute a Linux IRQ domain or hardware.
"""
from pathlib import Path
import hashlib,json,subprocess,os
r=Path(__file__).resolve().parent
source=(r/'c80_mcu_transport.c').read_text()
callbacks=source[source.index('static irqreturn_t c80_mcu_irq'):source.index('static ssize_t status_show')]
prefix=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "c80_mcu_core.h"
typedef int irqreturn_t;
#define IRQ_HANDLED 1
#define READ_ONCE(x) (x)
struct c80_linux { struct c80_io io; struct c80_result result; int irq,irq_lock; bool irq_cpu_on; };
struct fake { struct c80_linux c; unsigned mode,depth,locked,in_irq,forced,sleeps,starts,stops,syncs,writes; c80_u32 mask,source; };
static struct fake f;
static irqreturn_t c80_mcu_irq(int,void *);
static void deliver(void)
{
    unsigned count=0;
    while(!f.locked && !f.in_irq && !f.depth && (f.forced || (f.source&f.mask))) {
        assert(++count==1); /* Any enabled level storm fails immediately. */
        if(f.mode==2) return;
        f.forced=0; f.in_irq=1;
        assert(c80_mcu_irq(f.c.irq,&f.c)==IRQ_HANDLED);
        f.in_irq=0;
    }
}
static void lock(void) { assert(!f.locked); f.locked=1; }
static void unlock(void) { assert(f.locked); f.locked=0; deliver(); }
#define raw_spin_lock_irqsave(p,flags) do { (void)(p); (flags)=0; lock(); } while(0)
#define raw_spin_unlock_irqrestore(p,flags) do { (void)(p); (void)(flags); unlock(); } while(0)
static void enable_irq(int irq)
{
    assert(irq==f.c.irq && !f.locked && !f.in_irq && f.depth==1);
    --f.depth; ++f.starts;
    if(f.mode==3) f.forced=1;
    deliver();
}
static void disable_irq_nosync(int irq)
{
    assert(irq==f.c.irq && f.locked && !f.depth);
    ++f.depth; ++f.stops;
}
static void synchronize_irq(int irq)
{
    assert(irq==f.c.irq && !f.locked && !f.in_irq && f.depth==1);
    ++f.syncs;
}
static void usleep_range(unsigned lo,unsigned hi)
{
    assert(!f.locked && !f.in_irq && lo==1000 && hi==1200);
    assert(++f.sleeps<=100);
    if(f.mode==1 && f.sleeps==5) { f.source|=2; deliver(); }
}
static c80_u32 read_reg(void *ctx,c80_u32 reg)
{
    assert(ctx==&f.c && f.locked);
    assert(reg==C80_MASK || reg==C80_SOURCE);
    if(f.mode==7 && reg==C80_SOURCE) return ~0u;
    if(f.mode==8 && f.in_irq && reg==C80_SOURCE) return ~0u;
    return reg==C80_MASK?f.mask:f.source;
}
static void write_reg(void *ctx,c80_u32 reg,c80_u32 value)
{
    assert(ctx==&f.c && f.locked && ++f.writes<24);
    assert(reg==C80_MASK || reg==C80_SOURCE);
    if(reg==C80_MASK) {
        assert(value==0 || value==2);
        if((f.mode==4 && !value) || (f.mode==6 && value)) return;
        f.mask=value;
        /* Force a candidate CPU edge during the stop lock. The real
         * callbacks must disable the CPU before unlocking, not afterwards. */
        if(f.mode==10 && !value && f.c.result.counter_query_valid) f.forced=1;
    } else {
        assert(value==2);
        if(f.mode!=5) f.source&=~value;
    }
}
'''
suffix=r'''
int main(void)
{
    unsigned mode; (void)c80_run;
    for(mode=0;mode<12;++mode) {
        c80_u32 arm,stop,expected;
        memset(&f,0,sizeof(f)); f.mode=mode; f.depth=1; f.mask=0x20000000; f.source=0x80082;
        f.c.irq=23; f.c.io=(struct c80_io){.context=&f.c,.read=read_reg,.write=write_reg};
        f.c.result.phase=20; f.c.result.main_ready=1; f.c.result.dma_started=1;
        arm=c80_linux_irq_arm(&f.c,&f.c.result);
        if(!arm) {
            f.c.result.counter_query_attempted=1;
            f.c.result.counter_query_valid=mode!=11;
            if(mode!=1 && mode!=2) {
                f.source=mode==9?0x80080:0x80082;
                if(mode==9) f.forced=1;
                deliver();
            }
        }
        stop=c80_linux_irq_disarm(&f.c,&f.c.result);
        expected=mode==2?25:mode>=3 && mode<=9?26:0;
        assert((arm?arm:stop)==expected);
        assert(f.depth==1 && !f.c.irq_cpu_on && !f.c.result.irq_armed);
        assert(f.starts==f.stops && f.syncs==1 && !f.locked && !f.in_irq);
        if(!expected) assert(f.c.result.irq_events==1 && f.c.result.irq_entries==1 && !f.c.result.irq_faults);
        if(mode==1) assert(f.sleeps==5);
        if(mode==2) assert(f.sleeps==100 && !f.c.result.irq_entries);
        if(mode==10) { assert(f.forced==1 && f.c.result.irq_entries==1); deliver(); assert(f.c.result.irq_entries==1); }
        printf("PASS Linux callback case%u rc%u depth%u starts%u stops%u sleeps%u\n",mode,expected,f.depth,f.starts,f.stops,f.sleeps);
    }
    return 0;
}
'''
p=r/'irq-wrapper-generated.c';p.write_text(prefix+callbacks+suffix)
subprocess.run(['gcc','-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
                '-fsanitize=address,undefined','-fno-omit-frame-pointer',str(p),'-o',str(r/'verify-irq-wrapper')],check=True)
result=subprocess.run([str(r/'verify-irq-wrapper')],check=True,capture_output=True,text=True,
                      env={**os.environ,'ASAN_OPTIONS':'detect_leaks=1'})
assert result.stdout.count('PASS Linux callback')==12 and not result.stderr
(r/'irq-wrapper-verification.log').write_text(result.stdout)
(r/'evidence/irq-wrapper-result.json').write_text(json.dumps({
    'passed':True,'cases_passed':12,'actual_callback_source_sha256':hashlib.sha256(callbacks.encode()).hexdigest(),
    'scope':__doc__,'Linux_irq_domain_and_physical_hardware_emulated':False},indent=2)+'\n')
print('PASS:12 actual Linux callback cases; synthetic IRQ/lock/MMIO/time services; ASan/UBSan.')
