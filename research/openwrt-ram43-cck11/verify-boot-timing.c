/* SPDX-License-Identifier: GPL-2.0-only */
/* Actual ownership routine; synthetic MCU readiness, clock and MMIO only. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "c80_mcu_core.h"
struct model {
    struct c80_io io;struct c80_result result;
    c80_u64 us,accept_after,command_us,ack_delay;
    unsigned initial,writes,reads,delays,accepted,delay_fault,stuck,floor;
};
static c80_u32 rd(void *p,c80_u32 a)
{
    struct model *m=p;assert(a==C80_OWN);++m->reads;
    if(m->initial==~0u) return ~0u;
    if(m->accepted && !m->stuck && m->us-m->command_us>=m->ack_delay)
        return m->initial&~1u;
    return m->initial;
}
static void wr(void *p,c80_u32 a,c80_u32 v)
{
    struct model *m=p;assert(a==C80_OWN && v==2);assert(++m->writes==1);
    m->command_us=m->us;m->accepted=m->us>=m->accept_after;
}
static c80_u64 clock_us(void *p) { return ((struct model *)p)->us; }
static void delay_us(void *p,c80_u32 us)
{
    struct model *m=p;++m->delays;
    if(m->delay_fault==1) return;
    if(m->delay_fault==2) { --m->us;return; }
    if(m->delay_fault==3) { m->us+=us-1;return; }
    m->us+=m->floor?c80_delay_min_us(m->result.phase,us):us;
}
static void init(struct model *m,unsigned floor)
{
    memset(m,0,sizeof(*m));m->initial=0x30001;m->us=1000;
    m->accept_after=6000;m->ack_delay=500;m->floor=floor;m->result.phase=4;
    m->io.context=m;m->io.read=rd;m->io.write=wr;
    m->io.time_us=clock_us;m->io.delay_us=delay_us;
}
static unsigned cases;
static void pass(const char *name) { ++cases;printf("PASS BOOT TIMING %s\n",name); }
int main(void)
{
    struct model m;
    /* This models an early dropped request, not the real firmware cause. */
    init(&m,0);wr(&m,C80_OWN,2);
    assert(!c80_poll(&m.io,C80_OWN,1,0,2000000,&m.result.own_last));
    assert(!m.accepted && m.writes==1 && m.result.own_last==0x30001);
    pass("control-early-single-request-is-not-acknowledged-in-readiness-model");
    for(unsigned floor=0;floor<2;++floor) {
        init(&m,floor);assert(!c80_initial_ownership(&m.io,&m.result));
        assert(m.accepted && m.writes==1 && m.result.own_sent && m.result.boot_settled);
        assert(m.result.boot_settle_us==10000 && m.result.boot_own_confirmed);
        assert(m.result.own_before==0x30001 && m.result.own_last==0x30000);
        assert(m.result.boot_own_wait_us==(floor?10000:500));
        pass(floor?"init-floor-single-request-and-real-readback":"hires-settle-single-request-and-real-readback");
    }
    init(&m,1);m.initial=0x30000;
    assert(!c80_initial_ownership(&m.io,&m.result));
    assert(!m.writes && !m.delays && !m.result.boot_settled && m.result.boot_own_confirmed);
    pass("already-host-owned-no-command-or-settle");
    init(&m,1);m.initial=~0u;
    assert(c80_initial_ownership(&m.io,&m.result)==C80_OWN_TIMEOUT);
    assert(!m.writes && !m.delays && !m.result.boot_own_confirmed);
    pass("allones-refused-without-write-or-delay");
    for(unsigned f=1;f<=3;++f) {
        init(&m,1);m.delay_fault=f;
        assert(c80_initial_ownership(&m.io,&m.result)==C80_BAD_TIMER);
        assert(!m.writes && !m.result.boot_settled && !m.result.boot_own_confirmed);
        pass(f==1?"frozen-settle-clock-refused":f==2?"backward-settle-clock-refused":"premature-settle-return-refused");
    }
    for(unsigned floor=0;floor<2;++floor) {
        init(&m,floor);m.stuck=1;
        assert(c80_initial_ownership(&m.io,&m.result)==C80_OWN_TIMEOUT);
        assert(m.writes==1 && m.result.boot_settled && !m.result.boot_own_confirmed);
        assert(m.result.boot_own_wait_us==2000000 && m.result.own_last==0x30001);
        pass(floor?"floored-own-timeout-remains-two-seconds-no-retry":"hires-own-timeout-remains-two-seconds-no-retry");
    }
    for(unsigned phase=0;phase<=90;++phase) {
        if(phase==37) continue;
        m.result.phase=phase;m.floor=1;m.delay_fault=0;m.us=1000;
        delay_us(&m,50);assert(m.us==11000);
        delay_us(&m,20000);assert(m.us==31000);
    }
    pass("initialization-and-cleanup-do-not-shorten-short-or-long-waits");
    m.result.phase=37;m.us=1000;delay_us(&m,1000);assert(m.us==2000);
    delay_us(&m,50);assert(m.us==2050);
    pass("active-AP-keeps-one-ms-poll-and-subtick-command-waits");
    puts("NOTE MCU readiness is modeled; this does not prove the physical failure cause.");
    printf("PASS: %u actual ownership/timing cases.\n",cases);
    return 0;
}
