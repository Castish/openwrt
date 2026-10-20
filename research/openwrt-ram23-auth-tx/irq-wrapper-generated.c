
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
static irqreturn_t c80_mcu_irq(int irq,void *context)
{
    struct c80_linux *c=context; unsigned long flags;
    raw_spin_lock_irqsave(&c->irq_lock,flags);
    /* Bound a mistaken route too: never return into an enabled level storm.
     * The IRQ domain owns polarity/GIC state; no direct GIC register writes. */
    if(c->irq_cpu_on) { c->irq_cpu_on=false; disable_irq_nosync(irq); }
    c80_irq_event(&c->io,&c->result);
    raw_spin_unlock_irqrestore(&c->irq_lock,flags);
    return IRQ_HANDLED;
}
static c80_u32 c80_linux_irq_arm(void *context,struct c80_result *r)
{
    struct c80_linux *c=context; unsigned long flags; c80_u32 rc;
    if(r->phase!=20 || !r->main_ready || !r->dma_started) return C80_IRQ_BAD;
    raw_spin_lock_irqsave(&c->irq_lock,flags);
    rc=c80_irq_prepare(&c->io,r);
    if(!rc) { c->irq_cpu_on=true; r->irq_cpu_started=1; }
    raw_spin_unlock_irqrestore(&c->irq_lock,flags);
    if(rc) return rc;
    enable_irq(c->irq);
    raw_spin_lock_irqsave(&c->irq_lock,flags);
    rc=c80_irq_unmask(&c->io,r);
    raw_spin_unlock_irqrestore(&c->irq_lock,flags);
    return rc;
}
static c80_u32 c80_linux_irq_disarm(void *context,struct c80_result *r)
{
    struct c80_linux *c=context; unsigned long flags; unsigned int i;
    if(!r->irq_attempted) return 0;
    /* A valid DMA reply alone is insufficient. Give a delayed CPU IRQ a
     * bounded opportunity, without extending failed transport timeouts. */
    for(i=0;r->counter_query_valid && !READ_ONCE(r->irq_entries) && i<100;++i)
        usleep_range(1000,1200);
    raw_spin_lock_irqsave(&c->irq_lock,flags);
    c80_irq_stop(&c->io,r);
    if(c->irq_cpu_on) { c->irq_cpu_on=false; disable_irq_nosync(c->irq); }
    raw_spin_unlock_irqrestore(&c->irq_lock,flags);
    synchronize_irq(c->irq);
    if(r->irq_cpu_started) r->irq_cpu_stopped=1;
    return r->irq_faults?C80_IRQ_BAD:r->irq_events?0:C80_IRQ_NOT_SEEN;
}

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
